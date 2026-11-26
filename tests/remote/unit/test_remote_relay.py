import asyncio
import json
import sys
import time
from types import SimpleNamespace

import pytest

from unshackle.core import remote_service
from unshackle.core.api import handlers
from unshackle.core.api.errors import APIError, APIErrorCode
from unshackle.core.approval import ApprovalNotice
from unshackle.core.config import config

SERVICES = [
    {
        "tag": "EXAMPLE",
        "aliases": ["sample"],
        "cli_params": [{"kind": "option", "name": "extras"}, {"kind": "argument", "name": "title"}],
    }
]
INFO = SERVICES[0]


class FakeRemote:
    service_tag = "EXAMPLE"

    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def pool(monkeypatch):
    logins = []

    def fake_setup(data, server, profile, title_id, request=None):
        time.sleep(0.05)  # long enough that every request queues on the lease lock
        logins.append(title_id)
        return FakeRemote()

    monkeypatch.setattr(handlers, "setup_remote_service", fake_setup)
    monkeypatch.setattr(handlers, "_remote_pool", {})
    return logins


def lease(data, request=None, **extra):
    return handlers.lease_remote_service({**data, **extra}, "srv", INFO, None, "show", request)


DATA = {"service": "EXAMPLE", "title_id": "show", "remote": "srv"}


async def test_concurrent_leases_share_one_session(pool):
    leases = await asyncio.gather(*(lease(DATA, wanted=f"S01E0{i}") for i in range(1, 7)))

    assert pool == ["show"]
    assert len({id(x.service) for x in leases}) == 1
    for x in leases:
        await handlers.release_remote_service(x)
    assert not leases[0].service.closed and handlers._remote_pool


async def test_a_broken_session_leaves_the_pool_at_once_but_closes_after_its_last_holder(pool):
    first = await lease(DATA)
    second = await lease(DATA)
    first.dead = True

    await handlers.release_remote_service(first)
    assert not handlers._remote_pool and not first.service.closed

    await handlers.release_remote_service(second)
    assert first.service.closed
    assert (await lease(DATA)).service is not first.service


async def test_only_options_that_reach_the_remote_split_the_pool(pool):
    a = await lease(DATA, extras="a")
    b = await lease(DATA, extras="b")
    c = await lease(DATA, extras="a", tvdb_id="1", client_name="x")
    assert a.service is not b.service
    assert a.service is c.service


def keyed(key):
    return SimpleNamespace(headers={"X-Secret-Key": key})


async def test_each_api_key_gets_its_own_pooled_session(pool):
    a = await lease(DATA, keyed("a"), proxy="us")
    again = await lease(DATA, keyed("a"), proxy="us")
    b = await lease(DATA, keyed("b"), proxy="us")
    assert a.service is again.service
    assert b.service is not a.service
    assert pool == ["show", "show"]


async def test_client_region_splits_the_pool(pool):
    us = await lease(DATA, client_region="us")
    gb = await lease(DATA, client_region="gb")
    assert us.service is not gb.service


@pytest.fixture
def remote_config(monkeypatch):
    monkeypatch.setattr(config, "remote_services", {"srv": {"url": "https://srv", "api_key": "k"}})
    monkeypatch.setattr(remote_service, "remote_service_list", lambda name: SERVICES)
    monkeypatch.setattr(handlers, "get_allowed_services", lambda request=None: None)


def test_remote_server_resolves_case_and_aliases(remote_config):
    assert handlers.remote_server({"remote": "srv", "service": "example"}) == ("srv", INFO)
    assert handlers.remote_server({"remote": "srv", "service": "Sample"}) == ("srv", INFO)
    assert handlers.remote_server({"service": "EXAMPLE"}) is None


@pytest.mark.parametrize(
    "data, code",
    [
        ({"remote": "nope", "service": "EXAMPLE"}, APIErrorCode.INVALID_PARAMETERS),
        ({"remote": ["srv"], "service": "EXAMPLE"}, APIErrorCode.INVALID_PARAMETERS),
        ({"remote": "srv", "service": "OTHER"}, APIErrorCode.INVALID_SERVICE),
    ],
)
def test_remote_server_rejects(remote_config, data, code):
    with pytest.raises(APIError) as e:
        handlers.remote_server(data)
    assert e.value.error_code == code


def test_remote_server_applies_the_allowlist_and_reports_an_unreachable_server(remote_config, monkeypatch):
    monkeypatch.setattr(handlers, "get_allowed_services", lambda request=None: ["OTHER"])
    with pytest.raises(APIError) as e:
        handlers.remote_server({"remote": "srv", "service": "EXAMPLE"})
    assert e.value.error_code == APIErrorCode.INVALID_SERVICE

    monkeypatch.setattr(remote_service, "remote_service_list", lambda name: None)
    with pytest.raises(APIError) as e:
        handlers.remote_server({"remote": "srv", "service": "EXAMPLE"})
    assert e.value.error_code == APIErrorCode.SERVICE_UNAVAILABLE


def test_make_remote_service_passes_only_cli_options(remote_config, monkeypatch):
    built = {}
    monkeypatch.setattr(remote_service, "resolve_server", lambda name: ("https://srv", "k", {"EXAMPLE": {"x": 1}}))
    monkeypatch.setattr(remote_service, "RemoteService", lambda *a, **kw: built.update(args=a, **kw))

    remote_service.make_remote_service(
        None, "srv", "EXAMPLE", "id", {"service_params": {"extras": "y", "service": "OTHER", "proxy": "x"}}, False
    )
    assert built["service_params"] == {"extras": "y"}
    assert "EXAMPLE" not in built["args"][5]  # apply_overrides=False keeps the remote's overrides out

    remote_service.make_remote_service(None, "srv", "EXAMPLE", "id", {"extras": "z", "service": "OTHER", "quality": 1})
    assert built["service_params"] == {"extras": "z"}
    assert built["args"][5]["EXAMPLE"] == {"x": 1}


def test_make_remote_auth_only_service(remote_config):
    original_name = remote_service.RemoteService.__name__
    remote = remote_service.make_remote_service(None, "srv", "EXAMPLE", None, {}, auth_only=True)
    try:
        assert remote.auth_only
        assert remote.title == ""
    finally:
        remote_service.RemoteService.__name__ = original_name
        remote.session.close()


def test_a_service_option_named_like_a_dl_value_passes_only_nested():
    info = {"cli_params": [{"kind": "option", "name": "profile"}]}
    assert remote_service.remote_service_params(info, {"service_params": {"profile": "QC"}}) == {"profile": "QC"}
    assert remote_service.remote_service_params(info, {"profile": "QC"}) == {}


def test_remote_error_carries_its_reason_and_exits_a_cli_run():
    err = remote_service.RemoteError("Server error [SESSION_NOT_FOUND]: gone", "SESSION_NOT_FOUND")
    assert isinstance(err, SystemExit) and err.code == 1 and err.kind == "SESSION_NOT_FOUND"
    assert err.session_broke
    assert not remote_service.RemoteError("Server error [NOT_FOUND]: no title", "NOT_FOUND").session_broke


def test_a_geofenced_remote_service_gets_its_first_allowed_region_as_proxy(monkeypatch):
    monkeypatch.setattr(handlers, "server_proxy_allowed", lambda request=None: True)
    fenced = {"tag": "EXAMPLE", "geofence": ["US", "ca"], "geoblock": ["us"]}
    assert handlers.geofence_proxy({}, {"tag": "EXAMPLE", "geofence": ["US", "ca"]}) == {"proxy": "us"}
    assert handlers.geofence_proxy({}, fenced) == {"proxy": "ca"}
    assert handlers.geofence_proxy({"proxy": "gb"}, fenced) == {}
    assert handlers.geofence_proxy({"no_proxy": True}, fenced) == {}
    assert handlers.geofence_proxy({}, INFO) == {}

    monkeypatch.setattr(handlers, "server_proxy_allowed", lambda request=None: False)
    assert handlers.geofence_proxy({}, fenced) == {}


PAIRING_NOTICE = ApprovalNotice("Approve this device", "https://tv.example/pair", "ABCD", "2030-01-01T00:00:00Z")


@pytest.mark.parametrize("outcome", ["authenticated", "failed", "invalid", "timeout", "cancelled"])
def test_remote_login_shows_structured_approval_instead_of_server_logs(monkeypatch, outcome):
    import logging
    from threading import Lock

    shown = []
    monkeypatch.setattr(remote_service, "show_approval", shown.append)
    clock = [0]
    monkeypatch.setattr(
        remote_service,
        "time",
        SimpleNamespace(monotonic=lambda: clock[0], sleep=lambda _: clock.__setitem__(0, clock[0] + 1)),
    )
    logs = iter([["+ IP Region: CA"], []])

    class Client:
        polls = 0

        def get(self, endpoint):
            self.polls += 1
            if self.polls == 1:
                return {"status": "authenticating", "approval": PAIRING_NOTICE.to_dict()}
            if outcome == "cancelled":
                raise KeyboardInterrupt
            if outcome == "invalid":
                return {"status": "authenticating", "approval": {"message": "Pair", "extra": "private-fixture"}}
            return {"status": outcome}

        def get_optional(self, endpoint):
            batch = next(logs, [])
            remote.seq += len(batch)
            return {"logs": [{"level": "INFO", "message": m} for m in batch], "last_seq": remote.seq}

    remote = object.__new__(remote_service.RemoteService)
    remote.seq = 0
    remote.client, remote._session_id, remote._log_seq = Client(), "sid", 0
    remote._recent_logs, remote.auth_approval, remote._log_drain_lock = [], None, Lock()
    remote.log, remote._cdm_sessions, remote._input_bridge = logging.getLogger("test"), {}, None
    monkeypatch.setattr(remote_service.RemoteService, "local_cdm", None)

    if outcome == "authenticated":
        remote.poll_auth_completion(poll_interval=0)
    elif outcome == "cancelled":
        with pytest.raises(KeyboardInterrupt):
            remote.poll_auth_completion(poll_interval=0)
    else:
        error = {
            "invalid": "^Remote auth returned an invalid approval payload$",
            "timeout": "timed out",
            "failed": "auth failed",
        }[outcome]
        with pytest.raises(remote_service.RemoteError, match=error):
            remote.poll_auth_completion(poll_interval=0, timeout=1 if outcome == "timeout" else 600)
    assert shown == [PAIRING_NOTICE, None]
    assert remote.auth_approval is None


def test_remote_login_relays_redacted_authentication_observations(monkeypatch):
    import logging
    from threading import Lock

    from unshackle.core.authentication import AuthenticationObservation, AuthenticationState

    observed = []
    monkeypatch.setattr(remote_service, "publish_authentication", observed.append)
    monkeypatch.setattr(remote_service.time, "sleep", lambda seconds: None)
    responses = iter(
        [
            {
                "status": "authenticating",
                "authentication": {"state": "session_present", "method": "pairing"},
            },
            {
                "status": "authenticated",
                "authentication": {"state": "authenticated", "method": "pairing"},
            },
        ]
    )

    class Client:
        def get(self, endpoint):
            return next(responses)

        def get_optional(self, endpoint):
            return {"logs": [], "last_seq": 0}

    remote = object.__new__(remote_service.RemoteService)
    remote.client, remote._session_id, remote._log_seq = Client(), "sid", 0
    remote._recent_logs, remote.auth_approval, remote._log_drain_lock = [], None, Lock()
    remote.auth_observation = None
    remote.log, remote._cdm_sessions, remote._input_bridge = logging.getLogger("test"), {}, None
    monkeypatch.setattr(remote_service.RemoteService, "local_cdm", None)

    remote.poll_auth_completion(poll_interval=0)

    assert observed == [
        AuthenticationObservation(AuthenticationState.SESSION_PRESENT, method="pairing"),
        AuthenticationObservation(AuthenticationState.AUTHENTICATED, method="pairing"),
    ]


def test_remote_login_rejects_unstructured_authentication_observation_without_echoing_it(monkeypatch):
    import logging
    from threading import Lock

    monkeypatch.setattr(remote_service.time, "sleep", lambda seconds: None)

    class Client:
        def get(self, endpoint):
            return {
                "status": "authenticating",
                "authentication": {"state": "waiting", "message": "private material"},
            }

        def get_optional(self, endpoint):
            return {"logs": [], "last_seq": 0}

    remote = object.__new__(remote_service.RemoteService)
    remote.client, remote._session_id, remote._log_seq = Client(), "sid", 0
    remote._recent_logs, remote.auth_approval, remote._log_drain_lock = [], None, Lock()
    remote.auth_observation = None
    remote.log, remote._cdm_sessions, remote._input_bridge = logging.getLogger("test"), {}, None
    monkeypatch.setattr(remote_service.RemoteService, "local_cdm", None)

    with pytest.raises(remote_service.RemoteError) as exc_info:
        remote.poll_auth_completion(poll_interval=0)
    assert exc_info.value.message == "Remote auth returned an invalid authentication observation"
    assert "private material" not in exc_info.value.message


@pytest.mark.parametrize(
    "failure_kind, expected_state, expected_failure",
    [
        ("CONNECT", "error", "network"),
        ("CANCEL", "cancelled", None),
    ],
)
def test_remote_login_classifies_transport_failure_and_cancellation(
    monkeypatch,
    failure_kind,
    expected_state,
    expected_failure,
):
    import logging
    from threading import Lock

    from unshackle.core.authentication import AuthenticationObservation, AuthenticationState

    observed = []
    monkeypatch.setattr(remote_service, "publish_authentication", observed.append)

    class Client:
        def get(self, endpoint):
            if failure_kind == "CANCEL":
                raise KeyboardInterrupt
            raise remote_service.RemoteError("Remote transport unavailable", failure_kind)

        def get_optional(self, endpoint):
            return {"logs": [], "last_seq": 0}

    remote = object.__new__(remote_service.RemoteService)
    remote.client, remote._session_id, remote._log_seq = Client(), "sid", 0
    remote._recent_logs, remote.auth_approval, remote._log_drain_lock = [], None, Lock()
    remote.auth_observation = AuthenticationObservation(AuthenticationState.WAITING, method="pairing")
    remote.log, remote._cdm_sessions, remote._input_bridge = logging.getLogger("test"), {}, None
    monkeypatch.setattr(remote_service.RemoteService, "local_cdm", None)

    expected_exception = KeyboardInterrupt if failure_kind == "CANCEL" else remote_service.RemoteError
    with pytest.raises(expected_exception):
        remote.poll_auth_completion(poll_interval=0)

    payload = observed[-1].to_dict()
    assert payload["state"] == expected_state
    assert payload.get("failure") == expected_failure
    assert payload["method"] == "pairing"


@pytest.mark.parametrize("terminal", ["timed_out", "cancelled"])
def test_remote_login_preserves_its_session_bridges_terminal_result(monkeypatch, terminal):
    import logging
    from threading import Lock

    from unshackle.core.api.input_bridge import InputBridge
    from unshackle.core.authentication import AuthenticationObservation, AuthenticationState

    bridge = InputBridge()
    waiting = AuthenticationObservation(AuthenticationState.WAITING, method="pairing")
    bridge.set_authentication_observation(waiting)

    if terminal == "timed_out":
        bridge.request_input = lambda prompt: InputBridge.request_input(bridge, prompt, timeout=0)
        expected_exception = TimeoutError
    else:
        bridge.cancel()
        expected_exception = RuntimeError

    class Client:
        def get(self, endpoint):
            return {"status": "pending_input", "prompt": "Continue"}

        def get_optional(self, endpoint):
            return {"logs": [], "last_seq": 0}

    remote = object.__new__(remote_service.RemoteService)
    remote.client, remote._session_id, remote._log_seq = Client(), "sid", 0
    remote._recent_logs, remote.auth_approval, remote._log_drain_lock = [], None, Lock()
    remote.auth_observation = waiting
    remote.log, remote._cdm_sessions, remote._input_bridge = logging.getLogger("test"), {}, bridge
    monkeypatch.setattr(remote_service.RemoteService, "local_cdm", None)

    with pytest.raises(expected_exception):
        remote.poll_auth_completion(poll_interval=0)

    assert remote.auth_observation == bridge.get_authentication_observation()
    assert remote.auth_observation is not None
    assert remote.auth_observation.state.value == terminal


def test_reopening_a_session_clears_its_previous_authentication_result():
    from threading import Event
    from types import SimpleNamespace

    from unshackle.core.api.input_bridge import InputBridge
    from unshackle.core.authentication import AuthenticationObservation, AuthenticationState

    bridge = InputBridge()
    previous = AuthenticationObservation(AuthenticationState.AUTHENTICATED, method="pairing")
    bridge.set_authentication_observation(previous)
    remote = object.__new__(remote_service.RemoteService)
    remote._server_cdm = remote._server_device = remote._server_vault = False
    remote._keepalive_stop, remote._session_id = Event(), "old-session"
    remote.client = SimpleNamespace(tunnel=None)
    remote._log_seq, remote._segment_filters = 4, {"track": object()}
    remote.auth_observation, remote._input_bridge = previous, bridge
    remote.wait_for_server = lambda accepting: False

    assert remote.reopen() is False
    assert remote.auth_observation is None
    assert bridge.get_authentication_observation() is None


def test_headless_remote_login_routes_approval_through_its_session_bridge(monkeypatch):
    import logging
    from threading import Lock

    from unshackle.core.api.input_bridge import InputBridge

    bridge = InputBridge()
    monkeypatch.setattr(remote_service, "show_approval", lambda approval: pytest.fail("used shared console"))
    monkeypatch.setattr(remote_service.time, "sleep", lambda seconds: None)

    class Client:
        calls = 0

        def get(self, endpoint):
            self.calls += 1
            if self.calls == 1:
                return {"status": "authenticating", "approval": {"message": "Approve this device"}}
            assert bridge.get_pending_approval() == ApprovalNotice("Approve this device")
            return {"status": "authenticated"}

        def get_optional(self, endpoint):
            return {"logs": [], "last_seq": 0}

    remote = object.__new__(remote_service.RemoteService)
    remote.client, remote._session_id, remote._log_seq = Client(), "sid", 0
    remote._recent_logs, remote.auth_approval, remote._log_drain_lock = [], None, Lock()
    remote.log, remote._cdm_sessions, remote._input_bridge = logging.getLogger("test"), {}, bridge
    monkeypatch.setattr(remote_service.RemoteService, "local_cdm", None)

    remote.poll_auth_completion(poll_interval=0)

    assert bridge.get_pending_approval() is None
    assert remote._approval_owner is None and remote._approval_sent is None


class _PollsThenStops:
    """A stop event that lets the poller run a fixed number of polls."""

    def __init__(self, polls: int) -> None:
        self.polls = polls

    def wait(self, interval: float) -> bool:
        self.polls -= 1
        return self.polls < 0

    def is_set(self) -> bool:
        return False


def _post_login_poller(monkeypatch, responses, bridge=None):
    import logging

    class Response:
        def __init__(self, body):
            self.body = body

        def json(self):
            return self.body

    class Session:
        def get(self, url, timeout):
            return Response(next(responses))

    remote = object.__new__(remote_service.RemoteService)
    remote.client = SimpleNamespace(server_url="http://srv", session=Session())
    remote._session_id, remote.auth_approval, remote._input_bridge = "sid", None, bridge
    remote.log, remote._cdm_sessions = logging.getLogger("test"), {}
    monkeypatch.setattr(remote_service.RemoteService, "local_cdm", None)
    return remote


def test_a_post_login_approval_is_shown_and_cleared_while_requests_run(monkeypatch):
    shown = []
    monkeypatch.setattr(remote_service, "show_approval", shown.append)
    responses = iter(
        [
            {"status": "authenticated"},
            {"status": "authenticated", "approval": PAIRING_NOTICE.to_dict()},
            {"status": "authenticated", "approval": PAIRING_NOTICE.to_dict()},
            {"status": "authenticated"},
        ]
    )
    remote = _post_login_poller(monkeypatch, responses)

    remote.poll_cdm_calls(_PollsThenStops(4), interval=0)

    assert shown == [PAIRING_NOTICE, None]
    assert remote.auth_approval is None


def test_a_post_login_approval_is_cleared_when_the_last_request_ends(monkeypatch):
    shown = []
    monkeypatch.setattr(remote_service, "show_approval", shown.append)
    responses = iter([{"status": "authenticated", "approval": {"message": "Approve this device again"}}])
    remote = _post_login_poller(monkeypatch, responses)

    remote.poll_cdm_calls(_PollsThenStops(1), interval=0)

    assert shown == [ApprovalNotice("Approve this device again"), None]
    assert remote.auth_approval is None


def test_a_post_login_approval_reaches_a_headless_sessions_bridge(monkeypatch):
    from unshackle.core.api.input_bridge import InputBridge

    monkeypatch.setattr(remote_service, "show_approval", lambda approval: pytest.fail("used shared console"))
    bridge = InputBridge()
    responses = iter([{"status": "authenticated", "approval": {"message": "Approve this device again"}}])
    remote = _post_login_poller(monkeypatch, responses, bridge)
    seen = []
    real_set = bridge.set_approval
    bridge.set_approval = lambda approval: (seen.append(approval), real_set(approval))

    remote.poll_cdm_calls(_PollsThenStops(1), interval=0)

    assert seen == [ApprovalNotice("Approve this device again"), None]
    assert bridge.get_pending_approval() is None


def test_an_invalid_post_login_approval_does_not_stop_the_poller(monkeypatch):
    shown = []
    monkeypatch.setattr(remote_service, "show_approval", shown.append)
    responses = iter(
        [
            {"status": "authenticated", "approval": {"message": ""}},
            {"status": "authenticated", "approval": {"message": "Approve this device again"}},
        ]
    )
    remote = _post_login_poller(monkeypatch, responses)

    remote.poll_cdm_calls(_PollsThenStops(2), interval=0)

    assert shown == [ApprovalNotice("Approve this device again"), None]


class _FakeResponse:
    status_code = 200
    headers = {"Content-Type": "application/json"}
    text = ""

    def __init__(self, body):
        self.body = body

    def json(self):
        return self.body


class _ScriptedSession:
    """A requests session whose prompt GETs and other requests are released by the test."""

    def __init__(self, approval):
        import threading

        self.approval = approval
        self.prompt_gets = 0
        self.held_get = 1
        self.cdm_call = None
        self.answers = []
        self.first_prompt_in_flight = threading.Event()
        self.release_first_prompt = threading.Event()
        self.request_gates = []

    def post(self, url, timeout, json=None):
        if url.endswith("/prompt"):
            self.answers.append(json)
        return _FakeResponse({"session_id": "sid", "status": "authenticated"})

    def get(self, url, timeout, json=None):
        if url.endswith("/prompt"):
            self.prompt_gets += 1
            if self.prompt_gets == self.held_get:
                self.first_prompt_in_flight.set()
                assert self.release_first_prompt.wait(5)
            if self.cdm_call is not None and self.prompt_gets > 1:
                return _FakeResponse({"status": "pending_input", "cdm_call": self.cdm_call})
            return _FakeResponse({"status": "authenticated", "approval": self.approval})
        assert self.request_gates.pop(0).wait(5)
        return _FakeResponse({})


def _authenticated_session(monkeypatch, local_cdm):
    import logging
    import threading

    from unshackle.core.remote_service import RemoteClient

    session = _ScriptedSession({"message": "Approve this device again"})
    svc = remote_service.RemoteService.__new__(remote_service.RemoteService)
    svc.client = RemoteClient("http://srv", "key")
    svc.client._session = session
    svc.ctx = SimpleNamespace(obj=SimpleNamespace(cdm=local_cdm, cdm_entry=False), parent=None)
    svc.service_tag, svc.title_id, svc.log = "EXAMPLE", "t1", logging.getLogger("test")
    svc._server_cdm, svc._server_accounts, svc._service_params, svc._client_config = None, {"global": True}, {}, None
    svc._cdm_sessions, svc._cdm_lock, svc._cdm_requests = {}, threading.Lock(), 0
    svc._cdm_stop, svc._cdm_poller = threading.Event(), None
    svc.auth_approval, svc._input_bridge, svc._session = None, None, SimpleNamespace(proxies={})
    svc.drain_server_logs = lambda: None
    svc.start_keepalive = lambda: None
    svc.close = lambda: None
    monkeypatch.setattr(handlers.config, "cdm", {})
    return svc, session


class _FakeLive:
    def __init__(self, renderable, **kwargs):
        self.running = False

    def start(self):
        self.running = True

    def update(self, renderable, refresh=False):
        pass

    def stop(self):
        self.running = False


@pytest.fixture
def terminal_console(monkeypatch):
    from unshackle.core import console as console_module

    monkeypatch.setattr(console_module, "console", SimpleNamespace(is_terminal=True))
    monkeypatch.setattr(console_module, "SyncLive", _FakeLive)
    monkeypatch.setattr(console_module, "_approval_handler", None)
    monkeypatch.setattr(console_module, "_approval_live", None)
    monkeypatch.setattr(console_module, "_approval_renderables", {})
    return console_module


def _request_thread(svc, session):
    import threading

    gate = threading.Event()
    session.request_gates.append(gate)
    thread = threading.Thread(target=svc.client.get, args=("/api/session/sid/titles",))
    thread.start()
    return thread, gate


def _wait_for(condition):
    deadline = time.monotonic() + 5
    while not condition():
        assert time.monotonic() < deadline
        time.sleep(0.01)


def test_a_session_without_a_local_cdm_shows_a_post_login_approval_during_a_request(monkeypatch):
    shown = []
    monkeypatch.setattr(remote_service, "show_approval", shown.append)
    monkeypatch.setattr(remote_service, "APPROVAL_POLL_INTERVAL", 0.01)
    svc, session = _authenticated_session(monkeypatch, local_cdm=None)
    session.release_first_prompt.set()
    svc.authenticate()

    request, gate = _request_thread(svc, session)
    _wait_for(lambda: shown)
    gate.set()
    request.join(5)
    _wait_for(lambda: shown[-1:] == [None])

    assert shown == [ApprovalNotice("Approve this device again"), None]


def test_the_next_request_answers_a_cdm_call_while_the_previous_poll_is_still_running(monkeypatch):
    svc, session = _authenticated_session(monkeypatch, local_cdm=SimpleNamespace(is_playready=False))
    session.cdm_call = {"op": "unknown"}
    svc.authenticate()

    first, first_gate = _request_thread(svc, session)
    assert session.first_prompt_in_flight.wait(5)
    first_gate.set()
    first.join(5)

    second, second_gate = _request_thread(svc, session)
    _wait_for(lambda: session.answers)  # the first poll is still inside its GET
    session.release_first_prompt.set()
    second_gate.set()
    second.join(5)

    assert session.answers[0] == {"response": json.dumps({"error": "unknown CDM call 'unknown'"})}


def test_a_delayed_prompt_response_does_not_clear_the_next_requests_approval_notice(monkeypatch, terminal_console):
    import threading

    svc, session = _authenticated_session(monkeypatch, local_cdm=SimpleNamespace(is_playready=False))
    svc.authenticate()

    first, first_gate = _request_thread(svc, session)
    assert session.first_prompt_in_flight.wait(5)
    first_gate.set()
    first.join(5)

    second, second_gate = _request_thread(svc, session)
    _wait_for(lambda: session.prompt_gets >= 2 and terminal_console._approval_renderables)
    session.release_first_prompt.set()
    _wait_for(lambda: len([t for t in threading.enumerate() if t.name == "EXAMPLE-cdm"]) == 1)

    assert len(terminal_console._approval_renderables) == 1
    second_gate.set()
    second.join(5)
    _wait_for(lambda: not [t for t in threading.enumerate() if t.name == "EXAMPLE-cdm"])

    assert terminal_console._approval_renderables == {}
    assert terminal_console._approval_live is None


def test_a_delayed_prompt_response_does_not_clear_the_next_requests_headless_approval(monkeypatch):
    import threading

    from unshackle.core.api.input_bridge import InputBridge

    svc, session = _authenticated_session(monkeypatch, local_cdm=SimpleNamespace(is_playready=False))
    svc._input_bridge = bridge = InputBridge()
    svc.authenticate()

    first, first_gate = _request_thread(svc, session)
    assert session.first_prompt_in_flight.wait(5)
    first_gate.set()
    first.join(5)

    second, second_gate = _request_thread(svc, session)
    _wait_for(lambda: bridge.get_pending_approval() is not None)
    session.release_first_prompt.set()
    _wait_for(lambda: len([t for t in threading.enumerate() if t.name == "EXAMPLE-cdm"]) == 1)

    assert bridge.get_pending_approval() == ApprovalNotice("Approve this device again")
    second_gate.set()
    second.join(5)
    _wait_for(lambda: bridge.get_pending_approval() is None)


def test_a_predecessors_second_prompt_response_does_not_clear_an_approval_the_next_poller_already_fetched(monkeypatch):
    import threading

    from unshackle.core.api.input_bridge import InputBridge

    svc, session = _authenticated_session(monkeypatch, local_cdm=SimpleNamespace(is_playready=False))
    session.held_get = 2
    svc._input_bridge = bridge = InputBridge()
    svc.authenticate()

    first, first_gate = _request_thread(svc, session)
    assert session.first_prompt_in_flight.wait(5)
    assert bridge.get_pending_approval() == ApprovalNotice("Approve this device again")
    first_gate.set()
    first.join(5)

    second, second_gate = _request_thread(svc, session)
    _wait_for(lambda: session.prompt_gets >= 3)
    session.release_first_prompt.set()
    _wait_for(lambda: len([t for t in threading.enumerate() if t.name == "EXAMPLE-cdm"]) == 1)

    assert bridge.get_pending_approval() == ApprovalNotice("Approve this device again")
    second_gate.set()
    second.join(5)
    _wait_for(lambda: bridge.get_pending_approval() is None)


def test_a_predecessors_cleanup_does_not_clear_the_next_pollers_approval_in_a_download_worker(monkeypatch):
    import os
    import threading

    from unshackle.core.api import download_worker
    from unshackle.core.console import set_approval_handler, set_authentication_handler, set_prompt_handler

    read_fd, write_fd = os.pipe()
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(fileno=lambda: read_fd))
    updates = []
    approval = {"approval": {"message": "Approve this device again"}}
    svc, session = _authenticated_session(monkeypatch, local_cdm=SimpleNamespace(is_playready=False))
    session.held_get = 2
    download_worker.relay_prompts(updates.append)
    try:
        svc.authenticate()

        first, first_gate = _request_thread(svc, session)
        assert session.first_prompt_in_flight.wait(5)
        assert updates == [approval]
        first_gate.set()
        first.join(5)

        second, second_gate = _request_thread(svc, session)
        _wait_for(lambda: session.prompt_gets >= 3)
        session.release_first_prompt.set()
        _wait_for(lambda: len([t for t in threading.enumerate() if t.name == "EXAMPLE-cdm"]) == 1)

        assert {"approval": None} not in updates
        second_gate.set()
        second.join(5)
        _wait_for(lambda: updates[-1] == {"approval": None})
    finally:
        set_prompt_handler(None)
        set_approval_handler(None)
        set_authentication_handler(None)
        os.close(write_fd)


def test_a_handlers_approval_is_cleared_only_by_the_poller_that_last_saw_it_and_set_again_after(monkeypatch):
    from unshackle.core.console import set_approval_handler

    updates = []
    set_approval_handler(updates.append)
    try:
        svc, _ = _authenticated_session(monkeypatch, local_cdm=None)
        old, new = object(), object()
        notice = {"message": "Approve this device again"}

        shown = svc.relay_approval(notice, None, old)
        svc.relay_approval(notice, None, new)
        svc.relay_approval(None, shown, old)
        assert updates == [ApprovalNotice("Approve this device again")]

        svc.relay_approval(None, shown, new)
        svc.relay_approval(notice, None, old)
        assert updates == [
            ApprovalNotice("Approve this device again"),
            None,
            ApprovalNotice("Approve this device again"),
        ]
    finally:
        set_approval_handler(None)


def test_a_session_without_a_local_cdm_leaves_the_prompt_endpoint_alone_while_nothing_is_pending(monkeypatch):
    svc, session = _authenticated_session(monkeypatch, local_cdm=None)
    svc.authenticate()
    session.prompt_gets = 0

    request, gate = _request_thread(svc, session)
    time.sleep(0.8)  # a poll every 0.5 s would have made a GET by now
    gate.set()
    request.join(5)

    assert session.prompt_gets == 0


def test_a_session_with_a_local_cdm_still_polls_for_cdm_calls_every_half_second(monkeypatch):
    svc, session = _authenticated_session(monkeypatch, local_cdm=SimpleNamespace(is_playready=False))
    session.approval = None
    session.release_first_prompt.set()
    svc.authenticate()

    request, gate = _request_thread(svc, session)
    _wait_for(lambda: session.prompt_gets >= 1)
    gate.set()
    request.join(5)


async def test_a_remote_login_prompt_waits_for_its_owners_answer(monkeypatch):
    import threading as th

    from unshackle.core.authentication import AuthenticationObservation, AuthenticationState

    class Remote:
        pass

    login = handlers.RemoteLogin("owner", "srv", "OTHER", "show", Remote())
    login.bridge.set_approval(PAIRING_NOTICE)
    login.bridge.set_authentication_observation(
        AuthenticationObservation(AuthenticationState.WAITING, method="pairing")
    )
    monkeypatch.setattr(handlers, "_remote_logins", {login.id: login})
    monkeypatch.setattr(handlers, "is_admin", lambda request: False)
    caller = {"key": "owner"}
    monkeypatch.setattr(handlers, "caller_key", lambda request: caller["key"])
    got = []
    asker = th.Thread(target=lambda: got.append(login.bridge.request_input("Enter the code sent to your email")))
    asker.start()
    while login.bridge.get_pending_prompt() is None:
        await asyncio.sleep(0.01)

    listed = json.loads((await handlers.remote_logins_handler(None)).text)["logins"]
    assert listed[0]["prompt"] == "Enter the code sent to your email"
    assert listed[0]["approval"] == PAIRING_NOTICE.to_dict()
    assert listed[0]["authentication"] == {"state": "waiting", "method": "pairing"}

    caller["key"] = "someone-else"
    assert json.loads((await handlers.remote_logins_handler(None)).text)["logins"] == []
    with pytest.raises(APIError) as e:
        await handlers.remote_login_input_handler(login.id, {"response": "123456"}, None)
    assert e.value.error_code == APIErrorCode.NOT_FOUND

    caller["key"] = "owner"
    await handlers.remote_login_input_handler(login.id, {"response": "123456"}, None)
    asker.join(2)
    assert got == ["123456"] and login.bridge.get_pending_prompt() is None
    with pytest.raises(APIError) as e:
        await handlers.remote_login_input_handler(login.id, {"response": "again"}, None)
    assert e.value.error_code == APIErrorCode.CONFLICT


@pytest.mark.parametrize(
    "title, mode, error",
    [
        ("movie", True, ValueError),
        (0, True, ValueError),
        (None, False, ValueError),
        (" ", False, ValueError),
        ("movie", 1, TypeError),
    ],
)
def test_remote_title_validation_precedes_connection(title, mode, error):
    with pytest.raises(error):
        remote_service.RemoteService(None, "EXAMPLE", title, "", "", {}, auth_only=mode)


def test_auth_only_remote_requests_no_title(monkeypatch):
    svc, session = _authenticated_session(monkeypatch, None)
    svc.ctx.parent = SimpleNamespace(params={"no_proxy": True})
    svc.auth_only = True
    sent = []
    monkeypatch.setattr(
        session,
        "post",
        lambda url, timeout, json: sent.append(json) or _FakeResponse({"session_id": "sid", "status": "authenticated"}),
    )
    svc.authenticate()
    assert sent[0]["auth_only"] and "title_id" not in sent[0]
    with pytest.raises(RuntimeError, match="Auth-only remote sessions"):
        svc.get_titles()
