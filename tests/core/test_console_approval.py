from __future__ import annotations

import io
import threading
from functools import partial
from types import SimpleNamespace
from typing import Optional

import pytest
from rich.console import Console, Group

from unshackle.core import console
from unshackle.core.approval import ApprovalNotice


class _FakeLive:
    def __init__(
        self,
        displays: list[_FakeLive],
        renderable: Group,
        *_args: object,
        transient: Optional[bool] = None,
        **_kwargs: object,
    ) -> None:
        self.renderable = renderable
        self.transient = transient
        self.stopped = False
        displays.append(self)

    def start(self) -> None:
        return None

    def update(self, renderable: Group, **_kwargs: object) -> None:
        self.renderable = renderable

    def stop(self) -> None:
        self.stopped = True


@pytest.fixture
def displays(monkeypatch: pytest.MonkeyPatch) -> list[_FakeLive]:
    displays: list[_FakeLive] = []
    monkeypatch.setattr(console, "SyncLive", partial(_FakeLive, displays))
    monkeypatch.setattr(console, "console", SimpleNamespace(is_terminal=True))
    monkeypatch.setattr(console, "_approval_handler", None)
    return displays


def test_concurrent_approvals_clear_only_their_own_display(displays: list[_FakeLive]) -> None:
    shown = threading.Barrier(3)
    clear = [threading.Event(), threading.Event()]
    cleared = [threading.Event(), threading.Event()]

    def show(index: int, message: str) -> None:
        console.show_approval(ApprovalNotice(message))
        shown.wait(timeout=5)
        assert clear[index].wait(timeout=5)
        console.show_approval(None)
        cleared[index].set()

    threads = [
        threading.Thread(target=show, args=(index, message), daemon=True)
        for index, message in enumerate(("First", "Second"))
    ]
    for thread in threads:
        thread.start()
    shown.wait(timeout=5)
    try:
        assert len(displays) == 1
        assert len(displays[0].renderable.renderables) == 2
        clear[0].set()
        assert cleared[0].wait(timeout=5)
        assert not displays[0].stopped
        assert len(displays[0].renderable.renderables) == 1
    finally:
        for event in clear:
            event.set()
        for thread in threads:
            thread.join(timeout=5)
    assert displays[0].stopped


def test_show_approval_fields_as_literal_text(displays: list[_FakeLive]) -> None:
    notice = ApprovalNotice("[bold]", "https://tv.example", "AB", "2030-01-01T00:00:00Z")
    try:
        console.show_approval(notice)
        assert displays[0].transient is True
        output = io.StringIO()
        Console(file=output, force_terminal=False, width=120).print(displays[0].renderable)
        rendered = output.getvalue()
        for field in ("[bold]", "URL: https://tv.example", "Code: AB", "Expires: 2030-01-01T00:00:00Z"):
            assert field in rendered
    finally:
        console.show_approval(None)
    assert displays[0].stopped
    assert console._approval_live is None
    assert not console._approval_renderables


def test_format_approval_fields_as_literal_text() -> None:
    notice = ApprovalNotice("[bold]", "https://tv.example", "AB", "2030-01-01T00:00:00Z")
    assert (
        console.format_approval(notice).plain
        == "[bold]\nURL: https://tv.example\nCode: AB\nExpires: 2030-01-01T00:00:00Z"
    )
