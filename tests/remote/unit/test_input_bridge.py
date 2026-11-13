"""Unit tests for unshackle.core.api.input_bridge.InputBridge."""

from __future__ import annotations

import threading
import time
from json import loads
from types import SimpleNamespace

import pytest

from unshackle.core.api.input_bridge import AuthStatus, InputBridge
from unshackle.core.approval import ApprovalNotice

pytestmark = pytest.mark.unit


def test_initial_status_is_authenticating() -> None:
    bridge = InputBridge()
    assert bridge.status is AuthStatus.AUTHENTICATING
    assert bridge.get_pending_prompt() is None


def test_submit_response_returns_false_when_no_prompt_pending() -> None:
    bridge = InputBridge()
    assert bridge.submit_response("foo") is False


def test_request_input_blocks_until_submit() -> None:
    bridge = InputBridge()
    result: list[str] = []

    def worker() -> None:
        result.append(bridge.request_input("OTP?", timeout=5))

    t = threading.Thread(target=worker)
    t.start()
    for _ in range(50):
        if bridge.get_pending_prompt() == "OTP?":
            break
        time.sleep(0.02)
    assert bridge.status is AuthStatus.PENDING_INPUT
    assert bridge.get_pending_prompt() == "OTP?"

    assert bridge.submit_response("123456") is True
    t.join(timeout=2)
    assert result == ["123456"]
    assert bridge.status is AuthStatus.AUTHENTICATING
    assert bridge.get_pending_prompt() is None


def test_request_input_times_out() -> None:
    bridge = InputBridge()
    with pytest.raises(TimeoutError, match="No client response"):
        bridge.request_input("hello", timeout=0.6)
    assert bridge.status is AuthStatus.FAILED


def test_cancel_before_request_raises_immediately() -> None:
    bridge = InputBridge()
    bridge.cancel()
    with pytest.raises(RuntimeError, match="cancelled"):
        bridge.request_input("hello", timeout=5)
    assert bridge.status is AuthStatus.FAILED


def test_cancel_unblocks_pending_request() -> None:
    bridge = InputBridge()
    exc: list[Exception] = []

    def worker() -> None:
        try:
            bridge.request_input("OTP?", timeout=5)
        except RuntimeError as e:
            exc.append(e)

    t = threading.Thread(target=worker)
    t.start()
    for _ in range(50):
        if bridge.status is AuthStatus.PENDING_INPUT:
            break
        time.sleep(0.02)

    bridge.cancel()
    t.join(timeout=2)
    assert exc and isinstance(exc[0], RuntimeError)
    assert bridge.status is AuthStatus.FAILED


def test_get_pending_prompt_returns_none_outside_pending_state() -> None:
    bridge = InputBridge()
    bridge.status = AuthStatus.AUTHENTICATED
    assert bridge.get_pending_prompt() is None


def test_status_setter() -> None:
    bridge = InputBridge()
    bridge.status = AuthStatus.AUTHENTICATED
    assert bridge.status is AuthStatus.AUTHENTICATED


def test_approval_is_structured_and_cleared_on_terminal_state() -> None:
    bridge = InputBridge()
    approval = ApprovalNotice("Open the provider and enter the code")
    bridge.set_approval(approval)
    assert bridge.get_pending_approval() == approval

    bridge.status = AuthStatus.AUTHENTICATED
    assert bridge.get_pending_approval() is None


def test_cancel_clears_approval() -> None:
    bridge = InputBridge()
    bridge.set_approval(ApprovalNotice("Approve this device"))
    bridge.cancel()
    assert bridge.get_pending_approval() is None


async def test_prompt_handler_returns_session_owned_approval(monkeypatch: pytest.MonkeyPatch) -> None:
    from unshackle.core.api import handlers

    bridge = InputBridge()
    bridge.set_approval(ApprovalNotice("Approve this device"))
    session = SimpleNamespace(input_bridge=bridge, auth_status=AuthStatus.AUTHENTICATING, auth_error=None)

    async def get_session(session_id: str, request=None):
        assert session_id == "session-a"
        return session

    monkeypatch.setattr(handlers, "get_validated_session", get_session)
    response = await handlers.session_prompt_get_handler("session-a")
    assert loads(response.text) == {
        "status": "authenticating",
        "approval": {"message": "Approve this device"},
    }


def test_request_input_after_authentication_fails_fast() -> None:
    """The client stops polling for prompts once authenticated, so a later prompt must not wait for an answer."""
    bridge = InputBridge()
    bridge.status = AuthStatus.AUTHENTICATED
    with pytest.raises(RuntimeError, match="after authentication"):
        bridge.request_input("Pick a profile", timeout=5)
    assert bridge.status is AuthStatus.AUTHENTICATED
