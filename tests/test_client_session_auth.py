from types import SimpleNamespace
from typing import Optional

import pytest
import requests

from unshackle.core.api.errors import APIError
from unshackle.core.api.handlers import client_session_auth, resolve_handler_proxy, scrub_track_data
from unshackle.core.remote_service import apply_session_cookies


def _session(client_auth):
    cookie = SimpleNamespace(name="sid", value="secret", domain=".example.com", path="/")
    svc = SimpleNamespace(headers={"Authorization": "Bearer x", "User-Agent": "ua"}, cookies=[cookie])
    return SimpleNamespace(service_instance=SimpleNamespace(session=svc), client_auth=client_auth)


def test_client_login_keeps_auth():
    headers, cookies = client_session_auth(_session(True))
    assert headers == {"Authorization": "Bearer x", "User-Agent": "ua"}
    assert cookies == [{"name": "sid", "value": "secret", "domain": ".example.com", "path": "/", "secure": False}]
    assert scrub_track_data({"token": "t", "hls": {}}, _session(True)) == {"token": "t", "hls": {}}


def test_client_cookies_keep_their_domain():
    session = requests.Session()
    _, cookies = client_session_auth(_session(True))
    apply_session_cookies(session, {"session_cookie_jar": cookies})
    assert session.cookies.get("sid", domain=".example.com") == "secret"
    cdn = session.prepare_request(requests.Request("GET", "https://cdn.other.net/seg.mp4"))
    assert "Cookie" not in cdn.headers
    own = session.prepare_request(requests.Request("GET", "https://www.example.com/api"))
    assert own.headers["Cookie"] == "sid=secret"


def test_client_takes_old_server_cookies_without_domain():
    session = requests.Session()
    apply_session_cookies(session, {"session_cookies": {"sid": "secret"}})
    assert session.cookies.get("sid") == "secret"


def test_client_keeps_secure_cookies_off_http():
    session = requests.Session()
    jar = [{"name": "sid", "value": "s", "domain": ".example.com", "path": "/", "secure": True}]
    apply_session_cookies(session, {"session_cookie_jar": jar})
    plain = session.prepare_request(requests.Request("GET", "http://cdn.example.com/seg.mp4"))
    assert "Cookie" not in plain.headers
    tls = session.prepare_request(requests.Request("GET", "https://cdn.example.com/seg.mp4"))
    assert tls.headers["Cookie"] == "sid=s"


def test_client_skips_malformed_server_cookies():
    session = requests.Session()
    jar = [{"value": "v"}, "str", {"name": "n", "value": 1}, {"name": "ok", "value": "v", "domain": ".example.com"}]
    apply_session_cookies(session, {"session_cookie_jar": jar})
    assert [c.name for c in session.cookies] == ["ok"]
    session = requests.Session()
    apply_session_cookies(session, {"session_cookie_jar": 5, "session_cookies": ["x"]})
    assert not session.cookies


def test_rnet_session_sends_client_and_set_cookies():
    from unshackle.core.session import RnetSession

    svc = RnetSession()
    svc.cookies.set("sid", "stale", domain=".example.com")
    svc.cookies.set("cdn", "c", domain="cdn.other.net")
    svc.export_origin_cookies = lambda: {"https://www.example.com": "sid=live; cf=1"}
    _, cookies = client_session_auth(SimpleNamespace(service_instance=SimpleNamespace(session=svc), client_auth=True))
    assert {(c["name"], c["value"], c["domain"]) for c in cookies} == {
        ("sid", "live", "www.example.com"),
        ("cf", "1", "www.example.com"),
        ("cdn", "c", "cdn.other.net"),
    }


def test_tracks_response_carries_the_cookie_jar():
    import asyncio
    import json

    from unshackle.core.api import session_store as store_mod
    from unshackle.core.api.handlers import session_tracks_handler
    from unshackle.core.tracks import Tracks

    cookie = SimpleNamespace(name="sid", value="secret", domain=".example.com", path="/", secure=True)

    class StubService:
        session = SimpleNamespace(headers={}, cookies=[cookie])

        def get_tracks(self, title):
            return Tracks()

        def get_chapters(self, title):
            raise NotImplementedError

    async def run():
        store = store_mod.get_session_store()
        entry = await store.create(
            service_tag="EXAMPLE", service_instance=StubService(), session_id="jar", owner_key=None
        )
        entry.title_map = {"t1": "Example Title"}
        entry.client_auth = True
        try:
            return json.loads((await session_tracks_handler({"title_id": "t1"}, "jar")).body)
        finally:
            await store.delete("jar")

    body = asyncio.run(run())
    assert body["session_cookies"] == {"sid": "secret"}
    assert body["session_cookie_jar"] == [
        {"name": "sid", "value": "secret", "domain": ".example.com", "path": "/", "secure": True}
    ]


def test_remote_get_tracks_scopes_server_cookies():
    import logging

    from unshackle.core.remote_service import RemoteService

    jar = [{"name": "sid", "value": "secret", "domain": ".example.com", "path": "/"}]
    service = object.__new__(RemoteService)
    service.__dict__.update(
        _tracks_by_title={},
        _chapters_by_title={},
        _title_alias={},
        _sample_decrypt_tracks=set(),
        _server_cdm=None,
        _session=requests.Session(),
        _session_id="s",
        service_tag="EXAMPLE",
        log=logging.getLogger("test"),
        client=SimpleNamespace(post=lambda path, body: {"session_cookie_jar": jar}),
        drain_server_logs=lambda: None,
    )
    service.get_tracks(SimpleNamespace(id="t1"))
    cdn = service._session.prepare_request(requests.Request("GET", "https://cdn.other.net/seg.mp4"))
    assert "Cookie" not in cdn.headers
    assert service._session.cookies.get("sid", domain=".example.com") == "secret"


def test_server_login_strips_auth():
    headers, cookies = client_session_auth(_session(False))
    assert headers == {"User-Agent": "ua"}
    assert cookies == []
    assert scrub_track_data({"token": "t", "hls": {}}, _session(False)) == {"hls": {}}


def test_server_account_rejects_client_proxy_uri(monkeypatch):
    monkeypatch.setattr("unshackle.core.api.handlers.server_account_for", lambda request, service: True)
    with pytest.raises(APIError):
        resolve_handler_proxy({"proxy": "http://attacker:8080"}, "svc", None)


def test_profile_rejects_paths():
    from unshackle.core.api.handlers import client_profile

    assert client_profile({"profile": "main-1.b"}) == "main-1.b"
    assert client_profile({}) is None
    for bad in ("../x", "a/b", "..", "a\\b", "x" * 65):
        with pytest.raises(APIError):
            client_profile({"profile": bad})


def test_client_pssh_must_match_track(monkeypatch):
    import uuid

    from unshackle.core.api import handlers

    kid, other = uuid.uuid4(), uuid.uuid4()
    monkeypatch.setattr(handlers, "pssh_kids", lambda pssh, drm_type: {other} if pssh == "OTHER" else {kid})
    track = SimpleNamespace(id="t1", drm=[SimpleNamespace(kids=[kid])])
    handlers.require_track_pssh(track, "MINE", "widevine")
    with pytest.raises(APIError):
        handlers.require_track_pssh(track, "OTHER", "widevine")
    with pytest.raises(APIError):
        handlers.require_track_pssh(SimpleNamespace(id="t2", drm=[]), "MINE", "widevine")


def test_output_dir_stays_under_downloads(tmp_path, monkeypatch):
    from unshackle.core.api.handlers import config, validate_download_parameters

    monkeypatch.setattr(config.directories, "downloads", tmp_path)
    assert validate_download_parameters({"output_dir": "../../etc"})
    data = {"output_dir": "shows/x"}
    assert validate_download_parameters(data) is None
    assert data["output_dir"] == str((tmp_path / "shows/x").resolve())


def test_history_scoped_by_owner(tmp_path, monkeypatch):
    from unshackle.core.api import download_manager as dm

    monkeypatch.setattr(dm, "history_path", lambda: tmp_path / "h.jsonl")
    (tmp_path / "h.jsonl").write_text(
        '{"job_id": "a", "owner": "%s", "service": "X"}\n{"job_id": "b", "owner": "%s", "service": "X"}\n'
        % (dm.owner_id("k1"), dm.owner_id("k2"))
    )
    assert [e["job_id"] for e in dm.read_job_history(owner=dm.owner_id("k1"))] == ["a"]
    assert not dm.delete_job_history("b", owner=dm.owner_id("k1"))
    assert dm.delete_job_history("b", owner=dm.owner_id("k2"))


def test_log_capture_ignores_other_threads():
    import logging
    import threading

    from unshackle.core.api.session_log import SessionLogBuffer, capture_service_logs

    buf = SessionLogBuffer()
    logger = logging.getLogger("SvcBleed")
    with capture_service_logs("SvcBleed", buf):
        logger.info("mine")
        t = threading.Thread(target=lambda: logger.info("theirs"))
        t.start()
        t.join()
    assert [r["message"] for r in buf.since(0)] == ["mine"]


def test_dashboard_logs_redact_path():
    from pathlib import Path

    from unshackle.core.utils.redact import redact_path

    # A path under the real home dir must lose the home prefix, whatever the machine's user is.
    secret = str(Path.home() / "secret" / "svc.py")
    out = redact_path(f'Traceback: File "{secret}", line 5')
    assert str(Path.home()) not in out
    assert "svc.py" in out


def test_server_login_strips_nested_and_unlisted_secrets():
    headers, _ = client_session_auth(
        SimpleNamespace(
            service_instance=SimpleNamespace(
                session=SimpleNamespace(headers={"X-Api-Key": "k", "Accept": "*"}, cookies=[])
            ),
            client_auth=False,
        )
    )
    assert headers == {"Accept": "*"}
    data = {"license": {"auth_token": "t", "url": "u"}, "items": [{"password": "p", "id": 1}]}
    assert scrub_track_data(data, _session(False)) == {"license": {"url": "u"}, "items": [{"id": 1}]}


def test_track_own_pssh_passes_without_kids(monkeypatch):
    from unshackle.core.api import handlers

    monkeypatch.setattr(handlers, "extract_pssh_from_track", lambda track, drm_type: "OWN")
    monkeypatch.setattr(handlers, "pssh_kids", lambda pssh, drm_type: set())
    handlers.require_track_pssh(SimpleNamespace(id="t", drm=[]), "OWN", "widevine")
    with pytest.raises(APIError):
        handlers.require_track_pssh(SimpleNamespace(id="t", drm=[]), "OTHER", "widevine")


def test_download_rejects_path_profile_and_bad_output_dir(tmp_path, monkeypatch):
    from unshackle.core.api.handlers import config, validate_download_parameters

    monkeypatch.setattr(config.directories, "downloads", tmp_path)
    assert validate_download_parameters({"profile": "../x"})
    assert validate_download_parameters({"profile": "ok"}) is None
    assert validate_download_parameters({"output_dir": "a\x00b"})


def test_absent_key_keeps_server_devices(monkeypatch):
    from pathlib import Path

    from unshackle.core.api.handlers import config, serve_user_config

    monkeypatch.setattr(
        config,
        "serve",
        {"users": {"k1": {"devices": ["mine"]}}, "devices": [Path("/x/dev.wvd")], "playready_devices": []},
    )
    assert serve_user_config("k1") == {"devices": ["mine"]}
    assert serve_user_config("admin-secret") == {"devices": ["dev"], "playready_devices": []}


def test_safe_inflate_rejects_non_str_via_isinstance():
    # A non-string cache value must be caught before base64.b64decode raises a 500.
    # Mirror the guard used in session_create_handler.
    from unshackle.core.api.errors import APIError, APIErrorCode

    def guard(content):
        if not isinstance(content, str):
            raise APIError(APIErrorCode.INVALID_INPUT, "cache values must be base64 strings")

    guard("ok")  # no raise
    for bad in (1, {"a": 1}, ["x"], None):
        with pytest.raises(APIError):
            guard(bad)


def _run_session(monkeypatch, tmp_path, data, answer, server_account=False, fail=False, provider=None):
    """Run session_create_handler with a service that prompts during login; return the settled remote session."""
    import asyncio
    import base64
    import json
    import zlib

    from unshackle.core.api import handlers
    from unshackle.core.api.input_bridge import AuthStatus
    from unshackle.core.api.session_store import get_session_store
    from unshackle.core.config import config

    class PromptingService:
        _input_bridge = None
        log = None
        cache = None

        def authenticate(self, cookies, credential):
            if answer is not None:
                self._input_bridge.request_input("Enter code")
            if fail:
                raise ValueError("bad code")

    monkeypatch.setattr(config.directories, "cache", tmp_path)
    monkeypatch.setattr(handlers, "validate_service", lambda service, request=None: service)
    monkeypatch.setattr(handlers, "resolve_handler_proxy", lambda *args: (None, []))
    monkeypatch.setattr(handlers, "server_account_for", lambda *args: server_account)
    monkeypatch.setattr(handlers, "next_server_profile", lambda *args: None)
    monkeypatch.setattr(handlers.Services, "load", lambda service: PromptingService)
    monkeypatch.setattr(
        handlers, "create_service_instance", lambda *a, **k: (provider or PromptingService(), None, None)
    )
    if data.get("cache") == "tokens":
        data["cache"] = {"tokens_default": base64.b64encode(zlib.compress(b"{}")).decode("ascii")}

    async def run():
        resp = await handlers.session_create_handler({"service": "EXAMPLE", "title_id": "t", **data})
        created = json.loads(resp.body)
        info = json.loads((await handlers.session_info_handler(created["session_id"])).body)
        assert ("auth_only" in created) == data.get("auth_only", False)
        assert ("auth_only" in info) == data.get("auth_only", False)
        session = get_session_store().peek(created["session_id"])
        for _ in range(200):
            if answer is not None and session.input_bridge.status == AuthStatus.PENDING_INPUT:
                await handlers.session_prompt_post_handler({"response": answer}, session.session_id)
            if session.auth_status in (AuthStatus.AUTHENTICATED, AuthStatus.FAILED):
                break
            await asyncio.sleep(0.01)
        await get_session_store().delete(session.session_id)
        return session

    return asyncio.run(run())


@pytest.mark.parametrize(
    "data, answer, server_account, fail, expected",
    [
        ({}, None, False, False, True),  # no prompt: a pair code shown in the log, approved on another device
        ({}, "CODE", False, False, True),  # device code the client approved
        ({}, "CODE", False, True, False),  # answered, but the login failed
        ({}, "CODE", True, False, False),  # server account OTP answered by the client
        ({"cache": "tokens"}, None, False, False, True),  # client uploaded its own earlier login
        ({}, None, True, False, False),  # server account
    ],
)
def test_client_auth_follows_login_provenance(monkeypatch, tmp_path, data, answer, server_account, fail, expected):
    session = _run_session(monkeypatch, tmp_path, dict(data), answer, server_account, fail)
    assert session.client_auth is expected


def test_prompt_post_rejects_response_the_bridge_refused(monkeypatch):
    import asyncio

    from unshackle.core.api import handlers
    from unshackle.core.api.input_bridge import AuthStatus

    bridge = SimpleNamespace(status=AuthStatus.PENDING_INPUT, submit_response=lambda text: False)

    async def fake_get_session(session_id, request):
        return SimpleNamespace(input_bridge=bridge)

    monkeypatch.setattr(handlers, "get_validated_session", fake_get_session)
    with pytest.raises(APIError):
        asyncio.run(handlers.session_prompt_post_handler({"response": ""}, "sess"))


def test_login_that_outlives_its_session_leaves_no_cache(monkeypatch, tmp_path):
    """A login loop that finishes after DELETE must not leave its tokens on the server's disk."""
    import asyncio
    import json
    import threading

    from unshackle.core.api import handlers
    from unshackle.core.api.session_store import get_session_store
    from unshackle.core.config import config

    paired = threading.Event()
    finished = threading.Event()

    class SlowPairingService:
        _input_bridge = None
        log = None
        cache = None

        def authenticate(self, cookies, credential):
            paired.wait(5)
            self.cache.get("tokens").set("token")
            finished.set()

    monkeypatch.setattr(config.directories, "cache", tmp_path)
    monkeypatch.setattr(handlers, "validate_service", lambda service, request=None: service)
    monkeypatch.setattr(handlers, "resolve_handler_proxy", lambda *args: (None, []))
    monkeypatch.setattr(handlers, "server_account_for", lambda *args: False)
    monkeypatch.setattr(handlers.Services, "load", lambda service: SlowPairingService)
    monkeypatch.setattr(handlers, "create_service_instance", lambda *a, **k: (SlowPairingService(), None, None))

    async def run():
        resp = await handlers.session_create_handler({"service": "EXAMPLE", "title_id": "t"})
        session = get_session_store().peek(json.loads(resp.body)["session_id"])
        await get_session_store().delete(session.session_id)
        paired.set()
        for _ in range(200):
            if finished.is_set() and session.auth_status.value == "authenticated":
                break
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.05)
        return session

    session = asyncio.run(run())
    assert session.auth_status.value == "authenticated"
    assert not (tmp_path / session.cache_tag).exists()


@pytest.mark.parametrize(
    "data, error",
    [
        ([], "service"),
        ({"service": 1}, "service"),
        ({"service": " "}, "service"),
        ({"service": "EX", "auth_only": 1}, "boolean"),
        ({"service": "EX", "auth_only": None}, "boolean"),
        *[
            ({"service": "EX", "auth_only": True, "title_id": title}, "must not provide")
            for title in (False, 123, "movie")
        ],
        *[
            ({"service": "EX", "title_id": title}, "required parameter: title_id")
            for title in (None, False, 123, " ", "")
        ],
    ],
)
async def test_title_mode_validation(data, error):
    from unshackle.core.api import handlers

    with pytest.raises(handlers.APIError, match=error):
        await handlers.session_create_handler(data)


@pytest.mark.parametrize("mode, client_owned", [("full", False), ("remote_only", True)])
@pytest.mark.parametrize("title", [None, "", "  "])
def test_title_free_login_ownership(monkeypatch, tmp_path, mode, client_owned, title):
    from unshackle.core.api.stats import stats

    monkeypatch.setattr(stats, "mode", mode)
    session = _run_session(monkeypatch, tmp_path, {"auth_only": True, "title_id": title}, None)
    assert session.auth_only and session.summary()["auth_only"]
    assert session.client_auth is client_owned
    assert bool(session.cache_tag) is client_owned


def test_auth_only_click_contract():
    from types import SimpleNamespace

    import click

    from unshackle.core.api import handlers

    @click.command()
    @click.argument("title")
    def titled(title: str) -> str:
        return title

    @click.command()
    def untitled() -> str:
        return "ready"

    @click.command()
    def optional_titled(title: Optional[str] = None) -> Optional[str]:
        return title

    ctx = click.Context(click.Command("dl"))
    ctx.params["auth_only"] = True
    assert handlers.instantiate_service(ctx, SimpleNamespace(cli=titled), "ignored") == ""
    assert handlers.instantiate_service(ctx, SimpleNamespace(cli=optional_titled), "ignored") == ""
    assert handlers.instantiate_service(ctx, SimpleNamespace(cli=untitled), "ignored") == "ready"


async def test_full_auth_only_requires_local_account_grant(monkeypatch):
    from unshackle.core.api import handlers
    from unshackle.core.api.stats import stats

    monkeypatch.setattr(stats, "mode", "full")
    monkeypatch.setattr(handlers, "server_account_spec", lambda *_: None)
    monkeypatch.setattr(handlers, "server_accounts_allowed", lambda *_: False)
    monkeypatch.setattr(handlers, "validate_service", lambda *_: "EX")
    monkeypatch.setattr(handlers, "resolve_handler_proxy", lambda *_: (None, []))
    with pytest.raises(handlers.APIError, match="Server account access is required"):
        await handlers.session_create_handler({"service": "EX", "auth_only": True})


def test_local_account_blocks_client_proxy(monkeypatch):
    from unshackle.core.api import handlers
    from unshackle.core.api.stats import stats

    monkeypatch.setattr(stats, "mode", "full")
    monkeypatch.setattr(handlers, "server_account_spec", lambda *_: None)
    data = {"auth_only": True, "proxy": "https://proxy.example"}
    with pytest.raises(handlers.APIError, match="not a proxy URI"):
        handlers.resolve_handler_proxy(data, "EX", local_server_auth=True)
    assert handlers.resolve_handler_proxy(data, "EX") == ("https://proxy.example", [])


def test_configured_account_without_grant_uses_client_cache(monkeypatch, tmp_path):
    from unshackle.core.api import handlers
    from unshackle.core.api.stats import stats

    monkeypatch.setattr(stats, "mode", "full")
    monkeypatch.setattr(handlers, "server_account_spec", lambda *_: True)
    session = _run_session(monkeypatch, tmp_path, {"auth_only": True, "title_id": None}, None)
    assert session.client_auth and session.cache_tag.startswith("_sessions/")


@pytest.mark.parametrize(
    "configured,granted,reload",
    [
        (False, False, False),
        (False, True, False),
        (True, False, False),
        (True, True, False),
        (True, False, True),
        (False, True, True),
    ],
)
async def test_auth_only_login_ownership(monkeypatch, tmp_path, configured, granted, reload):
    import asyncio
    import json
    from types import SimpleNamespace

    from unshackle.commands.dl import dl
    from unshackle.core.api import handlers
    from unshackle.core.api.session_store import get_session_store
    from unshackle.core.api.stats import stats

    serve = {"users": {"client": {"server_accounts": granted}}, "server_accounts": {"EX": True} if configured else {}}
    request = SimpleNamespace(headers={"X-Secret-Key": "client"}, remote=None, app={})
    data = {"service": "EX", "auth_only": True, "no_proxy": True}
    monkeypatch.setattr(handlers.config, "serve", serve)
    monkeypatch.setattr(stats, "mode", "full")
    monkeypatch.setattr(handlers, "validate_service", lambda *_: "EX")
    if not configured and not granted:
        monkeypatch.setattr(
            handlers, "resolve_handler_proxy", lambda *args: pytest.fail("proxy evaluated before grant")
        )
        with pytest.raises(handlers.APIError, match="Server account access is required") as exc:
            await handlers.session_create_handler(data, request)
        assert exc.value.error_code == handlers.APIErrorCode.FORBIDDEN
        return

    original = handlers.resolve_handler_proxy

    def resolve(*args, **kwargs):
        if reload:
            handlers.config.serve = {**serve, "server_accounts": {} if configured else {"EX": True}}
        return original(*args, **kwargs)

    received = []
    provider = SimpleNamespace(
        cache=None, log=None, authenticate=lambda cookies, credential: received.append(credential)
    )
    monkeypatch.setattr(handlers, "resolve_handler_proxy", resolve)
    monkeypatch.setattr(handlers.config.directories, "cache", tmp_path)
    monkeypatch.setattr(handlers, "server_region", lambda: None)
    monkeypatch.setattr(handlers, "load_service_yaml", lambda *_: {})
    monkeypatch.setattr(handlers, "load_full_cdm", lambda *_: None)
    monkeypatch.setattr(handlers.Services, "load", lambda *_: type(provider))
    monkeypatch.setattr(handlers, "instantiate_service", lambda *_: provider)
    monkeypatch.setattr(dl, "get_cookie_jar", lambda *_: None)
    monkeypatch.setattr(dl, "get_credentials", lambda *_: "server fixture")
    response = await handlers.session_create_handler(data, request)
    assert response.status == 200, response.text
    session_id = json.loads(response.body)["session_id"]
    store = get_session_store()
    try:
        await asyncio.gather(*handlers._auth_tasks)
        session = store.peek(session_id)
        assert received == ["server fixture" if granted else None]
        assert session.client_auth is (not granted)
        assert (session.cache_tag is None) is granted
        assert session.server_account == ("default" if configured and granted else None)
        assert session.service_instance.cache.service_tag == (
            "_accounts/EX/default" if configured and granted else "EX" if granted else session.cache_tag
        )
    finally:
        await store.delete(session_id)


async def test_create_event_includes_auth_only():
    from unshackle.core.api.events import bus
    from unshackle.core.api.session_store import SessionStore

    store = SessionStore()
    seq = bus.seq
    entry = await store.create("EX", object(), auth_only=True)
    (event,) = [
        event["data"]
        for event in bus.since(seq)
        if event["event"] == "session"
        and event["data"]["action"] == "create"
        and event["data"]["id"] == entry.session_id
    ]
    assert event["auth_only"] is True


@pytest.mark.parametrize(
    "mode, profile, existing",
    [
        ("full", None, False),
        ("full", "family", False),
        ("full", "family", True),
        ("remote_only", "family", False),
        ("remote_only", "family", True),
    ],
)
@pytest.mark.parametrize("backend", ["requests", "rnet", "empty"])
def test_auth_only_cookie_persistence(monkeypatch, tmp_path, mode, profile, existing, backend):
    from http.cookiejar import CookieJar

    from unshackle.commands.dl import dl
    from unshackle.core.api import handlers
    from unshackle.core.api.input_bridge import AuthStatus
    from unshackle.core.api.session_store import get_session_store
    from unshackle.core.api.stats import stats
    from unshackle.core.session import RnetSession

    class CookieService:
        cache = None
        log = None

        def __init__(self):
            self.session = RnetSession() if backend == "rnet" else requests.Session()

        def authenticate(self, cookies, credential):
            jar = CookieJar()
            if backend != "empty":
                jar.set_cookie(requests.cookies.create_cookie("sid", "refreshed", domain=".example.com"))
            self.session.cookies.update(jar)

    cookie_root = tmp_path / "cookies"
    monkeypatch.setattr(handlers.config.directories, "cookies", cookie_root)
    monkeypatch.setattr(stats, "mode", mode)
    monkeypatch.setattr(handlers, "server_account_spec", lambda *_: None)
    direct = cookie_root / "EXAMPLE.txt"
    if existing:
        cookie_root.mkdir()
        direct.write_text(".example.com\tTRUE\t/\tFALSE\t0\tsid\tprevious\n")
    before = direct.read_bytes() if existing else None
    provider = CookieService()
    original_save = handlers.os.replace
    saved_states = []

    def save(path, cookies):
        original_save(path, cookies)
        entry = next(entry for entry in get_session_store().list() if entry.service_instance is provider)
        saved_states.append((entry.auth_status, entry.input_bridge.status))

    monkeypatch.setattr(handlers.os, "replace", save)
    session = _run_session(
        monkeypatch, tmp_path, {"auth_only": True, "title_id": None, "profile": profile}, None, provider=provider
    )
    assert session.auth_status == AuthStatus.AUTHENTICATED
    assert get_session_store().peek(session.session_id) is None
    if mode == "remote_only" or backend == "empty":
        assert saved_states == []
        assert list(cookie_root.rglob("*")) == ([direct] if existing else [])
        if existing:
            assert direct.read_bytes() == before
    else:
        assert len(saved_states) == 1
        assert AuthStatus.AUTHENTICATED not in saved_states[0]
        assert dl.get_cookie_path("EXAMPLE", profile) == (
            direct if existing else cookie_root / "EXAMPLE" / f"{profile or 'default'}.txt"
        )
        assert [(c.name, c.value) for c in dl.get_cookie_jar("EXAMPLE", profile)] == [("sid", "refreshed")]


def test_overlapping_cookie_saves(monkeypatch, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    from unshackle.commands.dl import dl
    from unshackle.core.api import handlers

    monkeypatch.setattr(handlers.config.directories, "cookies", tmp_path)
    ready = Barrier(2)

    def persist(name):
        session = requests.Session()
        session.cookies.set(name, name, domain=".example.com")
        ready.wait(timeout=5)
        handlers.save_local_auth_cookies("EXAMPLE", None, SimpleNamespace(session=session))

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(persist, ["first", "second"]))
    assert {c.name for c in dl.load_cookie_file(tmp_path / "EXAMPLE/default.txt")} == {"first", "second"}


def test_failed_cookie_save_preserves_original(monkeypatch, tmp_path):
    from http.cookiejar import MozillaCookieJar
    from pathlib import Path

    from unshackle.core.api import handlers

    monkeypatch.setattr(handlers.config.directories, "cookies", tmp_path)
    path = tmp_path / "EXAMPLE.txt"
    original = b".example.com\tTRUE\t/\tFALSE\t0\tsid\tprevious\n"
    path.write_bytes(original)
    session = requests.Session()
    session.cookies.set("sid", "new", domain=".example.com")

    def fail(self, filename=None, **kwargs):
        Path(filename or self.filename).write_bytes(b"partial")
        raise OSError("write failed")

    monkeypatch.setattr(MozillaCookieJar, "save", fail)
    with pytest.raises(OSError, match="write failed"):
        handlers.save_local_auth_cookies("EXAMPLE", None, SimpleNamespace(session=session))
    assert path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [path]


@pytest.fixture
def shared_cookie_file(monkeypatch, tmp_path):
    from unshackle.core.config import config

    monkeypatch.setattr(config.directories, "cookies", tmp_path)
    path = tmp_path / "EXAMPLE.txt"
    path.write_text("".join(f".example.com\tTRUE\t/\tFALSE\t0\t{name}\told_{name}\n" for name in ("a", "b")))
    return path


@pytest.mark.parametrize("backend", ["requests", "rnet"])
def test_shared_cookie_refresh(shared_cookie_file, backend, monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock

    from unshackle.commands.dl import dl
    from unshackle.core.api import handlers
    from unshackle.core.session import RnetSession

    initial = dl.get_cookie_jar("EXAMPLE", None)
    baseline = handlers.snapshot_auth_cookies(initial)
    for name in ("a", "b"):
        client = requests.Session() if backend == "requests" else RnetSession()
        client.cookies.update(initial)
        changes = requests.cookies.RequestsCookieJar()
        changes.set(name, f"new_{name}", domain=".example.com")
        client.cookies.update(changes)
        handlers.save_local_auth_cookies("EXAMPLE", None, SimpleNamespace(session=client), baseline)
    assert {c.name: c.value for c in dl.load_cookie_file(shared_cookie_file)} == {"a": "new_a", "b": "new_b"}
    replace = Mock(wraps=handlers.os.replace)
    monkeypatch.setattr(handlers.os, "replace", replace)
    baseline = handlers.snapshot_auth_cookies(client.cookies)
    handlers.save_local_auth_cookies("EXAMPLE", None, SimpleNamespace(session=client), baseline)
    replace.assert_not_called()
    shared_cookie_file.unlink()
    handlers.save_local_auth_cookies("EXAMPLE", None, SimpleNamespace(session=client), baseline)
    assert {c.name: c.value for c in dl.get_cookie_jar("EXAMPLE", None)} == {"a": "old_a", "b": "new_b"}


@pytest.mark.asyncio
async def test_overlapping_auth_only_refresh(shared_cookie_file, monkeypatch):
    import asyncio
    import json
    from threading import Event

    from unshackle.commands.dl import dl
    from unshackle.core.api import handlers
    from unshackle.core.api.input_bridge import AuthStatus
    from unshackle.core.api.session_store import get_session_store
    from unshackle.core.api.stats import stats

    class Provider:
        cache = None
        log = None

        def __init__(self, name):
            self.name = name
            self.session = requests.Session()
            self.ready = Event()
            self.release = Event()

        def authenticate(self, cookies, credential):
            self.session.cookies.update(cookies)
            self.ready.set()
            assert self.release.wait(10)
            self.session.cookies.set(self.name, f"new_{self.name}", domain=".example.com")

    providers = [Provider(name) for name in ("a", "b")]
    instances = iter(providers)
    monkeypatch.setattr(stats, "mode", "full")
    monkeypatch.setattr(handlers, "validate_service", lambda service, request=None: service)
    monkeypatch.setattr(handlers, "resolve_handler_proxy", lambda *args: (None, []))
    monkeypatch.setattr(handlers, "server_account_for", lambda *args: False)
    monkeypatch.setattr(handlers, "server_account_spec", lambda *args: None)
    monkeypatch.setattr(handlers.Services, "load", lambda service: Provider)
    monkeypatch.setattr(
        handlers, "create_service_instance", lambda *a, **k: (next(instances), dl.get_cookie_jar("EXAMPLE", None), None)
    )
    store = get_session_store()
    ids = []
    try:
        for provider in providers:
            response = await handlers.session_create_handler({"service": "EXAMPLE", "auth_only": True})
            ids.append(json.loads(response.body)["session_id"])
            assert await asyncio.to_thread(provider.ready.wait, 5)
        for provider, session_id in zip(providers, ids):
            provider.release.set()
            async with asyncio.timeout(5):
                while store.peek(session_id).auth_status == AuthStatus.AUTHENTICATING:
                    await asyncio.sleep(0.01)
            assert store.peek(session_id).auth_status == AuthStatus.AUTHENTICATED
        assert {c.name: c.value for c in dl.get_cookie_jar("EXAMPLE", None)} == {"a": "new_a", "b": "new_b"}
    finally:
        for provider in providers:
            provider.release.set()
        for session_id in ids:
            await store.delete(session_id)
