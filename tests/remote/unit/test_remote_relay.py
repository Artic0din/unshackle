import asyncio
import json
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


def test_remote_login_shows_structured_approval_instead_of_server_logs(monkeypatch):
    import logging
    from threading import Lock

    shown = []
    monkeypatch.setattr(remote_service, "show_approval", shown.append)
    monkeypatch.setattr(remote_service.time, "sleep", lambda s: None)
    logs = iter([["+ IP Region: CA"], []])
    responses = iter(
        [
            {"status": "authenticating", "approval": {"message": "Approve this device"}},
            {"status": "authenticated"},
        ]
    )

    class Client:
        def get(self, endpoint):
            return next(responses)

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

    remote.poll_auth_completion(poll_interval=0)
    assert shown == [ApprovalNotice("Approve this device"), None]
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


async def test_a_remote_login_prompt_waits_for_its_owners_answer(monkeypatch):
    import threading as th

    from unshackle.core.authentication import AuthenticationObservation, AuthenticationState

    class Remote:
        pass

    login = handlers.RemoteLogin("owner", "srv", "OTHER", "show", Remote())
    login.bridge.set_approval(ApprovalNotice("Approve this device"))
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
    assert listed[0]["approval"] == {"message": "Approve this device"}
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
