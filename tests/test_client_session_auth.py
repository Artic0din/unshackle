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


@pytest.fixture
def cookie_handler():
    from http.server import BaseHTTPRequestHandler
    from urllib.parse import urlsplit

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = urlsplit(self.path).path
            redirects = {
                "/query": "/echo?own=1",
                "/bad-host": "http://bad host/",
                "/malformed": "http://[::1",
                "/login": "/done",
                "/rotate": "/end",
                "/first": "http://other.example.test/middle",
                "/middle": "/echo",
            }
            if path.startswith("/redirect/"):
                self.send_response(int(path.split("/")[-1]))
                self.send_header("Location", "http://other.example.test/request")
            else:
                self.send_response(302 if path in redirects else 200)
            if path in redirects:
                self.send_header("Location", redirects[path])
            if path == "/login":
                self.send_header("Set-Cookie", "hop=redir1; Path=/")
            elif path == "/done":
                self.send_header("Set-Cookie", "root=ok; Path=/; HttpOnly; Max-Age=3600")
                self.send_header("Set-Cookie", "scoped=api; Path=/api")
                self.send_header("Set-Cookie", "ip=ok; Domain=127.0.0.1; Path=/")
            elif path == "/expire":
                self.send_header("Set-Cookie", "scoped=gone; Path=/api; Max-Age=0")
            elif path == "/rotate":
                self.send_header("Set-Cookie", "a=new_a; Path=/; Domain=example.com")
            elif path == "/first":
                self.send_header("Set-Cookie", "scoped=ok; Path=/api")
                self.send_header(
                    "Set-Cookie", "sid=parent; Domain=example.com; HttpOnly; Expires=Fri, 01 Jan 2100 00:00:00 GMT"
                )
                self.send_header("Set-Cookie", "seed=; Max-Age=0")
            elif path == "/middle":
                self.send_header("Set-Cookie", "middle=ok; Path=/auth")
            elif path == "/expire-domain":
                self.send_header("Set-Cookie", "sid=; Domain=example.com; Path=/; Max-Age=0")
            elif path == "/host":
                self.send_header("Set-Cookie", "sid=host")
            elif path == "/expire-host":
                self.send_header("Set-Cookie", "sid=; Max-Age=0")
            elif path == "/refresh":
                self.send_header(
                    "Set-Cookie", "sid=parent; Domain=example.com; HttpOnly; Expires=Fri, 01 Jan 2100 00:00:00 GMT"
                )
            elif path == "/ipv6":
                self.send_header("Set-Cookie", "scoped=api; Path=/api")
                self.send_header("Set-Cookie", "short=yes; Path=/; Max-Age=1")
            elif path == "/ttl":
                self.send_header("Set-Cookie", "live=yes; Max-Age=60; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
                self.send_header("Set-Cookie", "short=yes; Max-Age=1")
            self.end_headers()
            if path == "/bad-host":
                self.wfile.write(b"original")
            elif path == "/echo" and "?" in self.path:
                self.wfile.write(urlsplit(self.path).query.encode())
            elif path in ("/echo", "/api/echo"):
                self.wfile.write("; ".join(self.headers.get_all("Cookie") or []).encode())

            elif path == "/request":
                import json

                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                self.wfile.write(json.dumps([self.command, dict(self.headers.items()), body.decode()]).encode())

        do_POST = do_PUT = do_PATCH = do_DELETE = do_GET

        def log_message(self, *args):
            pass

    return Handler


@pytest.fixture
def cookie_server(cookie_handler):
    from http.server import ThreadingHTTPServer
    from threading import Thread

    with ThreadingHTTPServer(("127.0.0.1", 0), cookie_handler) as server:
        thread = Thread(target=server.serve_forever)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}"
        finally:
            server.shutdown()
            thread.join()


def test_rnet_login_cookie_persistence(monkeypatch, tmp_path, cookie_server):
    from time import time

    from unshackle.commands.dl import dl
    from unshackle.core.api import handlers
    from unshackle.core.api.input_bridge import AuthStatus
    from unshackle.core.api.stats import stats
    from unshackle.core.session import RnetSession

    session = RnetSession()
    provider = SimpleNamespace(
        session=session,
        cache=None,
        log=None,
        authenticate=lambda cookies, credential: session.get(f"{cookie_server}/login"),
    )
    monkeypatch.setattr(stats, "mode", "full")
    monkeypatch.setattr(handlers, "server_account_spec", lambda *_: None)
    monkeypatch.setattr(handlers.config.directories, "cookies", tmp_path)
    before = int(time())
    entry = _run_session(monkeypatch, tmp_path, {"auth_only": True, "title_id": None}, None, provider=provider)
    assert entry.auth_status == AuthStatus.AUTHENTICATED
    assert list(session.cookies.jar) == []
    jar = dl.get_cookie_jar("EXAMPLE", None)
    assert jar is not None
    assert {(c.name, c.value, c.path) for c in jar} == {
        ("root", "ok", "/"),
        ("scoped", "api", "/api"),
        ("ip", "ok", "/"),
        ("hop", "redir1", "/"),
    }
    assert all(c.domain == "127.0.0.1" and not c.domain_specified for c in jar)
    root = next(c for c in session.cookies.persistable_jar() if c.name == "root")
    assert root.has_nonstandard_attr("HTTPOnly") and not root.discard
    assert before + 3600 <= root.expires <= int(time()) + 3600
    assert (
        f"#HttpOnly_127.0.0.1\tFALSE\t/\tFALSE\t{root.expires}\troot\tok"
        in dl.get_cookie_path("EXAMPLE", None).read_text()
    )


def test_rnet_redirect_cookie_scopes(cookie_server):
    from unshackle.core.session import RnetSession

    client = RnetSession(proxy=cookie_server)
    client.cookies.set("seed", "old", domain="sub.example.com")
    client.get("http://sub.example.com/first")
    exported = {(c.domain, c.path, c.name): c for c in client.cookies.persistable_jar()}
    assert set(exported) == {
        ("sub.example.com", "/api", "scoped"),
        (".example.com", "/", "sid"),
        ("other.example.test", "/auth", "middle"),
    }
    parent = exported[".example.com", "/", "sid"]
    assert parent.domain_specified and parent.domain_initial_dot
    assert parent.has_nonstandard_attr("HTTPOnly") and parent.expires == 4102444800


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_rnet_redirect_method_and_headers(cookie_server, code):
    from unshackle.core.session import RnetSession

    client = RnetSession(proxy=cookie_server)
    client.headers.update({"Authorization": "session", "Content-Type": "text/plain"})
    headers = {"cOoKiE": "sid=initial", "Proxy-Authorization": "request", "X-Keep": "yes"}
    response = client.post(f"http://sub.example.com/redirect/{code}", data="payload", headers=headers)
    method, sent_headers, body = response.json()
    sent = {name.lower(): value for name, value in sent_headers.items()}
    assert sent["x-keep"] == "yes"
    assert set(sent).isdisjoint({"cookie", "authorization", "proxy-authorization"})
    if code in (307, 308):
        assert (method, body, sent["content-type"]) == ("POST", "payload", "text/plain")
    else:
        assert (method, body) == ("GET", "")
        assert set(sent).isdisjoint({"content-type", "content-length"})


def test_rnet_redirect_controls(cookie_server):
    import rnet

    from unshackle.core.session import RnetSession

    client = RnetSession(proxy=cookie_server, max_redirects=1)
    url = "http://sub.example.com/first"
    assert client.get(url, allow_redirects=False).status_code == 302
    with pytest.raises(rnet.RedirectError, match="Exceeded 1 redirects"):
        client.get(url)


@pytest.mark.parametrize("method", ["GET", "PUT", "PATCH", "DELETE"])
@pytest.mark.parametrize("code", [301, 302, 303])
def test_redirect_rewrites_body_and_sets_referer(cookie_server, method, code):
    from unshackle.core.session import RnetSession

    url = f"http://sub.example.com/redirect/{code}"
    headers = {"Content-Type": "text/plain"}
    result = RnetSession(proxy=cookie_server).request(method, url + "#private", body=b"payload", headers=headers)
    sent_method, sent_headers, body = result.json()
    sent = {name.lower(): value for name, value in sent_headers.items()}
    assert (sent_method, body, sent["referer"]) == ("GET", "", url)
    assert set(sent).isdisjoint({"content-length", "content-type"})
    assert headers == {"Content-Type": "text/plain"}


@pytest.mark.parametrize("source", ["userinfo", "disabled", "session", "request"])
def test_redirect_referer_policy(cookie_server, source):
    from unshackle.core.session import RnetSession

    client = RnetSession(proxy=cookie_server, referer=source != "disabled")
    headers = {"rEfErEr": "custom"} if source == "request" else {}
    if source == "session":
        client.headers["referer"] = "custom"
    authority = "user@sub.example.com" if source == "userinfo" else "sub.example.com"
    _, sent_headers, _ = client.get(f"http://{authority}/redirect/302", headers=headers).json()
    sent = {name.lower(): value for name, value in sent_headers.items()}
    assert sent.get("referer") == ("custom" if source in ("session", "request") else None)


def test_redirect_downgrade_clears_previous_referer(cookie_server, tmp_path):
    import ssl
    import subprocess
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    from unshackle.core.session import RnetSession

    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.headers.get("Referer"))
            self.send_response(302)
            self.send_header("Location", "/middle" if self.path == "/start" else cookie_server + "/request")
            self.end_headers()

        def log_message(self, *args):
            pass

    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-days",
            "1",
            "-keyout",
            key,
            "-out",
            cert,
        ],
        check=True,
        capture_output=True,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = Thread(target=server.serve_forever)
        thread.start()
        try:
            start = f"https://127.0.0.1:{server.server_port}/start"
            session = RnetSession()
            session._client_kwargs["verify"] = cert
            _, headers, _ = session.get(start).json()
            assert seen == [None, start]
            assert "referer" not in {k.lower() for k in headers}
        finally:
            server.shutdown()
            thread.join()


@pytest.mark.parametrize("code", [307, 308])
@pytest.mark.parametrize("kind", ["generator", "multipart", "bytes"])
def test_redirect_body_replay(cookie_server, code, kind):
    import rnet

    from unshackle.core.session import RnetSession

    if kind == "multipart":
        kwargs = {"multipart": rnet.Multipart(rnet.Part("field", "payload"))}
    else:
        kwargs = {"body": b"payload" if kind == "bytes" else (part for part in [b"payload"])}
    response = RnetSession(proxy=cookie_server).post(f"http://sub.example.com/redirect/{code}", **kwargs)
    if kind == "bytes":
        method, _, body = response.json()
        assert (method, body) == ("POST", "payload")
    else:
        assert response.status_code == code
        assert response.content == b""


def test_redirect_limit_and_location(cookie_server):
    import rnet

    from unshackle.core.session import RnetSession

    session = RnetSession(proxy=cookie_server, max_redirects=None)
    base = "http://sub.example.com"
    for limit in (None, 0):
        assert session.get(base + "/login", allow_redirects=False, max_redirects=limit).status_code == 302
    for limit in (0, 1):
        with pytest.raises(rnet.RedirectError, match=f"Exceeded {limit} redirects"):
            session.get(base + "/login", max_redirects=limit)
    assert session.get(base + "/login", max_redirects=2).status_code == 200
    with pytest.raises(rnet.RedirectError, match="Exceeded 2 redirects"):
        session.get(base + "/first", max_redirects=2)
    first = session.get(base + "/query", query={"initial": "one"}, allow_redirects=False)
    assert first.url.endswith("/query?initial=one")
    assert session.get(base + "/query", query={"initial": "one"}).text == "own=1"
    bad = session.get(base + "/bad-host")
    assert (bad.status_code, bad.content) == (302, b"original")
    malformed = session.get(base + "/malformed", max_redirects=1)
    assert (malformed.status_code, malformed.content) == (302, b"")


def test_ipv6_cookie_scope_and_expiry(cookie_handler):
    import errno
    import socket
    import time
    from http.server import ThreadingHTTPServer
    from threading import Thread

    from unshackle.core.session import RnetSession

    class IPv6Server(ThreadingHTTPServer):
        address_family = socket.AF_INET6

    try:
        server = IPv6Server(("::1", 0), cookie_handler)
    except OSError as exc:
        if exc.errno in (errno.EADDRNOTAVAIL, errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT):
            pytest.skip(f"IPv6 loopback unavailable: {exc}")
        raise
    with server:
        thread = Thread(target=server.serve_forever)
        thread.start()
        try:
            base = f"http://[::1]:{server.server_port}"
            session = RnetSession()
            session.get(base + "/ipv6")
            assert "short=yes" in session.get(base + "/echo").text
            session.rebuild_client()
            assert "scoped=api" in session.get(base + "/api/echo").text
            assert "scoped=api" not in session.get(base + "/echo").text
            time.sleep(1)
            assert [(c.name, c.path) for c in session.cookies.persistable_jar()] == [("scoped", "/api")]
            session.rebuild_client()
            assert session.get(base + "/api/echo").text == "scoped=api"
        finally:
            server.shutdown()
            thread.join()


def test_rnet_host_cookie_preserves_parent_and_refreshes_metadata(cookie_server):
    from unshackle.core.session import RnetSession

    client = RnetSession(proxy=cookie_server)
    client.cookies.set("sid", "parent", domain=".example.com")
    origin = "http://sub.example.com"
    client.get(f"{origin}/host")
    assert sorted(client.get(f"{origin}/echo").text.split("; ")) == ["sid=host", "sid=parent"]
    assert {(c.domain, c.value) for c in client.cookies.persistable_jar()} == {
        ("sub.example.com", "host"),
        (".example.com", "parent"),
    }
    client.get(f"{origin}/expire-host")
    assert client.get(f"{origin}/echo").text == "sid=parent"
    client.get(f"{origin}/refresh")
    (parent,) = client.cookies.persistable_jar()
    assert (parent.domain, parent.value, parent.expires) == (".example.com", "parent", 4102444800)
    assert parent.has_nonstandard_attr("HTTPOnly") and not parent.discard


@pytest.mark.parametrize(
    ("first", "second", "expire", "domain"),
    [
        ("host", "refresh", "expire-host", ".example.com"),
        ("refresh", "host", "expire-domain", "example.com"),
    ],
)
def test_same_host_cookie_slot(cookie_server, first, second, expire, domain):
    from unshackle.core.session import RnetSession

    session = RnetSession(proxy=cookie_server)
    origin = "http://example.com"
    for endpoint in (first, second):
        session.get(f"{origin}/{endpoint}")
    assert [c.domain for c in session.cookies.persistable_jar()] == [domain]
    session.get(f"{origin}/{expire}")
    assert list(session.cookies.persistable_jar()) == []
    session.rebuild_client()
    assert session.get(f"{origin}/echo").text == ""


@pytest.mark.parametrize("expire", [False, True])
def test_cookie_response_after_rebuild(cookie_handler, cookie_server, monkeypatch, expire):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from unshackle.core.session import RnetSession

    started, release = Event(), Event()
    original = cookie_handler.do_GET

    def handle(handler):
        if handler.path == "/in-flight":
            started.set()
            assert release.wait(10)
            handler.send_response(200)
            handler.send_header("Set-Cookie", "sid=; Max-Age=0" if expire else "sid=rotated")
            handler.end_headers()
        else:
            original(handler)

    monkeypatch.setattr(cookie_handler, "do_GET", handle)
    session = RnetSession()
    session.headers["X-Test"] = "old"
    session.get(f"{cookie_server}/host")
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(session.get, f"{cookie_server}/in-flight")
        try:
            assert started.wait(10)
            session.headers.pop("X-Test")
        finally:
            release.set()
        assert pending.result().status_code == 200
    assert session.get(f"{cookie_server}/echo").text == ("" if expire else "sid=rotated")


def test_rnet_cookie_max_age_survives_rebuild_until_deadline(cookie_server):
    import time

    from unshackle.core.session import RnetSession

    client = RnetSession()
    client.get(f"{cookie_server}/ttl")
    assert {c.name for c in client.cookies.persistable_jar()} == {"short", "live"}
    assert "live=yes" in client.get(f"{cookie_server}/echo").text
    client.rebuild_client()
    time.sleep(1.1)
    assert {c.name for c in client.cookies.persistable_jar()} == {"live"}
    client.rebuild_client()
    assert client.get(f"{cookie_server}/echo").text == "live=yes"


def test_rnet_rebuild_sends_one_parent_cookie(cookie_server):
    from unshackle.core.session import RnetSession

    client = RnetSession(proxy=cookie_server)
    client.cookies.set("sid", "parent", domain=".example.com")
    url = "http://sub.example.com/echo"
    assert client.get(url).text == "sid=parent"
    client.rebuild_client()
    assert client.get(url).text == "sid=parent"


def test_rnet_explicit_domain_persistence(monkeypatch, tmp_path):
    from unshackle.commands.dl import dl
    from unshackle.core.api import handlers
    from unshackle.core.session import RnetSession

    monkeypatch.setattr(handlers.config.directories, "cookies", tmp_path)
    session = RnetSession()
    session.cookies.set("sid", "val", domain=".example.com")
    session.cookies.set("tmp", "val")
    session.cookies["other_tmp"] = "val"
    handlers.save_local_auth_cookies("EXAMPLE", None, SimpleNamespace(session=session))
    jar = dl.get_cookie_jar("EXAMPLE", None)
    assert jar is not None
    assert [(c.name, c.domain) for c in jar] == [("sid", ".example.com")]


def test_rnet_received_cookie_removal(cookie_server):
    from unshackle.core.session import RnetSession

    session = RnetSession()
    session.get(f"{cookie_server}/done")
    session.get(f"{cookie_server}/expire")
    assert {c.name for c in session.cookies.persistable_jar()} == {"root", "ip"}
    session.cookies.clear(name="root")
    assert {c.name for c in session.cookies.persistable_jar()} == {"ip"}
    session.cookies.clear()
    assert list(session.cookies.persistable_jar()) == []


def test_rnet_redirect_refresh_preserves_shared_domain_cookie(shared_cookie_file, cookie_server, monkeypatch):
    from unittest.mock import Mock

    from unshackle.commands.dl import dl
    from unshackle.core.api import handlers
    from unshackle.core.session import RnetSession

    initial = dl.get_cookie_jar("EXAMPLE", None)
    baseline = handlers.snapshot_auth_cookies(initial)
    client = RnetSession(proxy=cookie_server)
    client.cookies.update(initial)
    client.get("http://www.example.com/rotate")
    other = requests.Session()
    other.cookies.set("b", "new_b", domain=".example.com")
    handlers.save_local_auth_cookies("EXAMPLE", None, SimpleNamespace(session=other), baseline)
    current = handlers.snapshot_auth_cookies(client.cookies)
    assert {key for key in current if current[key] != baseline.get(key)} == {(".example.com", "/", "a")}
    handlers.save_local_auth_cookies("EXAMPLE", None, SimpleNamespace(session=client), baseline)
    assert {c.name: c.value for c in dl.load_cookie_file(shared_cookie_file)} == {"a": "new_a", "b": "new_b"}
    replace = Mock(wraps=handlers.os.replace)
    monkeypatch.setattr(handlers.os, "replace", replace)
    handlers.save_local_auth_cookies("EXAMPLE", None, SimpleNamespace(session=client), current)
    replace.assert_not_called()


def _persist_named_cookie(service, name):
    from unshackle.core.api import handlers

    session = requests.Session()
    session.cookies.set(name, name, domain=".example.com")
    handlers.save_local_auth_cookies(service, None, SimpleNamespace(session=session))


def test_overlapping_cookie_saves(monkeypatch, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event, Lock

    from unshackle.commands.dl import dl
    from unshackle.core.api import handlers

    monkeypatch.setattr(handlers.config.directories, "cookies", tmp_path)
    path = tmp_path / "EXAMPLE.txt"
    path.write_text(".example.com\tTRUE\t/\tFALSE\t0\tseed\tseed\n")
    original_load, original_replace = dl.load_cookie_file, handlers.os.replace
    reading, contender, release = Event(), Event(), Event()
    active = peak = 0
    counting = Lock()
    lock = Lock()

    class ObservedLock:
        def __enter__(self):
            if not lock.acquire(blocking=False):
                contender.set()
                assert lock.acquire(timeout=5)

        def __exit__(self, *args):
            lock.release()

    monkeypatch.setitem(handlers._COOKIE_SERVICE_LOCKS, "EXAMPLE", ObservedLock())

    def load(path):
        nonlocal active, peak
        jar = original_load(path)
        with counting:
            active += 1
            peak = max(peak, active)
            if reading.is_set():
                contender.set()
            reading.set()
        assert release.wait(5)
        return jar

    def replace(src, dst):
        nonlocal active
        original_replace(src, dst)
        with counting:
            active -= 1

    monkeypatch.setattr(dl, "load_cookie_file", load)
    monkeypatch.setattr(handlers.os, "replace", replace)
    with ThreadPoolExecutor(2) as pool:
        first = pool.submit(_persist_named_cookie, "EXAMPLE", "first")
        try:
            assert reading.wait(5)
            second = pool.submit(_persist_named_cookie, "EXAMPLE", "second")
            assert contender.wait(5)
        finally:
            release.set()
        first.result()
        second.result()
    assert peak == 1
    assert {c.name for c in original_load(path)} == {"seed", "first", "second"}


def test_independent_service_cookie_saves(monkeypatch, shared_cookie_file):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from unshackle.commands.dl import dl

    reading, release = Event(), Event()
    original_load = dl.load_cookie_file

    def load(path):
        if path == shared_cookie_file:
            reading.set()
            assert release.wait(10)
        return original_load(path)

    monkeypatch.setattr(dl, "load_cookie_file", load)
    with ThreadPoolExecutor(2) as pool:
        first = pool.submit(_persist_named_cookie, "EXAMPLE", "one")
        try:
            assert reading.wait(5)
            pool.submit(_persist_named_cookie, "OTHER", "two").result(timeout=5)
            assert {c.name for c in dl.get_cookie_jar("OTHER", None)} == {"two"}
        finally:
            release.set()
        first.result()


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


@pytest.mark.parametrize("backend", ["requests", "rnet"])
@pytest.mark.asyncio
async def test_overlapping_auth_only_refresh(shared_cookie_file, monkeypatch, backend):
    import asyncio
    import json
    from threading import Event

    from unshackle.commands.dl import dl
    from unshackle.core.api import handlers
    from unshackle.core.api.input_bridge import AuthStatus
    from unshackle.core.api.session_store import get_session_store
    from unshackle.core.api.stats import stats
    from unshackle.core.session import RnetSession

    class Provider:
        cache = None
        log = None

        def __init__(self, name):
            self.name = name
            self.session = RnetSession() if backend == "rnet" else requests.Session()
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


@pytest.mark.parametrize("expire", [False, True])
def test_cookie_change_during_stale_rebuild_copy(cookie_server, monkeypatch, expire):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from unshackle.core.session import RnetSession

    session = RnetSession()
    session.cookies.set("sid", "old", domain="127.0.0.1")
    session.get(cookie_server + "/echo")
    read, release = Event(), Event()
    copy = session.copy_cookies

    def paused(source, target, origin):
        raw = source.get_cookies(origin)
        assert raw == b"sid=old"
        read.set()
        assert release.wait(10)
        copy(SimpleNamespace(get_cookies=lambda _: raw), target, origin)

    monkeypatch.setattr(session, "copy_cookies", paused)
    with ThreadPoolExecutor(1) as pool:
        rebuild = pool.submit(session.rebuild_client)
        try:
            assert read.wait(10)
            session.get(cookie_server + ("/expire-host" if expire else "/host"))
        finally:
            release.set()
        rebuild.result()
    assert session.get(cookie_server + "/echo").text == ("" if expire else "sid=host")


def test_alternating_login_cookie_scope(monkeypatch, tmp_path, cookie_server, cookie_handler):
    from unshackle.commands.dl import dl
    from unshackle.core.api import handlers
    from unshackle.core.api.input_bridge import AuthStatus
    from unshackle.core.api.stats import stats
    from unshackle.core.session import RnetSession

    original = cookie_handler.do_GET

    def handle(handler):
        if handler.path.endswith("/auth"):
            handler.send_response(200)
            handler.send_header("Set-Cookie", assignment)
            handler.end_headers()
        else:
            original(handler)

    monkeypatch.setattr(cookie_handler, "do_GET", handle)
    monkeypatch.setattr(stats, "mode", "full")
    monkeypatch.setattr(handlers, "server_account_spec", lambda *_: None)
    monkeypatch.setattr(handlers.config.directories, "cookies", tmp_path)
    for assignment in ("sid=first; Domain=example.com", "sid=second", "sid=third; Domain=example.com"):
        session = RnetSession(proxy=cookie_server)

        def authenticate(cookies, credential):
            if cookies:
                session.cookies.update(cookies)
            session.get("http://example.com/auth")

        provider = SimpleNamespace(session=session, cache=None, log=None, authenticate=authenticate)
        entry = _run_session(monkeypatch, tmp_path, {"auth_only": True, "title_id": None}, None, provider=provider)
        assert entry.auth_status == AuthStatus.AUTHENTICATED
    fresh = RnetSession(proxy=cookie_server)
    jar = dl.get_cookie_jar("EXAMPLE", None)
    assert [(c.domain, c.value) for c in jar] == [(".example.com", "third")]
    fresh.cookies.update(jar)
    assert fresh.get("http://example.com/echo").text == "sid=third"


@pytest.mark.parametrize("port,expected", [(80, True), (81, False)])
def test_default_redirect_origin(cookie_server, cookie_handler, monkeypatch, port, expected):
    from urllib.parse import urlparse

    from unshackle.core.session import RnetSession, _origin_key

    for scheme, default in (("http", 80), ("https", 443)):
        assert _origin_key(urlparse(f"{scheme}://example.com:{default}")) == _origin_key(
            urlparse(f"{scheme}://example.com")
        )
    original = cookie_handler.do_GET

    def handle(handler):
        if handler.path.endswith("/start"):
            handler.send_response(302)
            handler.send_header("Location", "http://example.com/request")
            handler.end_headers()
        else:
            original(handler)

    monkeypatch.setattr(cookie_handler, "do_GET", handle)
    response = RnetSession(proxy=cookie_server).get(
        f"http://example.com:{port}/start", headers={"Authorization": "sample"}
    )
    assert ("sample" in response.json()[1].values()) is expected


@pytest.mark.parametrize(
    "configured,request_options,code",
    [
        (None, {}, 200),
        (True, {"allow_redirects": None}, 200),
        (False, {"allow_redirects": None}, 302),
        (None, {"allow_redirects": False}, 302),
    ],
)
def test_optional_redirect_policy(cookie_server, configured, request_options, code):
    from unshackle.core.session import RnetSession

    session = RnetSession(allow_redirects=configured)
    assert session.get(cookie_server + "/login", **request_options).status_code == code


def test_parent_expiry_during_subdomain_copy(cookie_server, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from unshackle.core.session import RnetSession

    session = RnetSession(proxy=cookie_server)
    session.cookies.set("sid", "old", domain=".example.com")
    base = "http://sub.example.com"
    assert session.get(base + "/echo").text == "sid=old"
    read, release = Event(), Event()

    def paused(source, target, origin):
        raw = source.get_cookies(origin)
        assert raw == b"sid=old"
        read.set()
        assert release.wait(10)
        session.set_cookie_header(target, origin, raw.decode())

    monkeypatch.setattr(session, "copy_cookies", paused)
    with ThreadPoolExecutor(1) as pool:
        rebuild = pool.submit(session.rebuild_client)
        try:
            assert read.wait(10)
            session.get(base + "/expire-domain")
        finally:
            release.set()
        rebuild.result()
    assert session.get(base + "/echo").text == ""


def test_overlapping_header_rebuilds(cookie_server, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from unshackle.core.session import RnetSession

    session = RnetSession()
    session.headers.update({"X-First": "one", "X-Second": "two"})
    session.cookies.set("sid", "old", domain="127.0.0.1")
    session.get(cookie_server + "/echo")
    read, release = Event(), Event()
    copy = session.copy_cookies

    def paused(source, target, origin):
        if not read.is_set():
            read.set()
            assert release.wait(10)
        copy(source, target, origin)

    def check():
        headers = {k.lower(): v for k, v in session.get(cookie_server + "/request").json()[1].items()}
        assert headers["cookie"] == "sid=new"
        assert "x-first" not in headers and "x-second" not in headers

    monkeypatch.setattr(session, "copy_cookies", paused)
    with ThreadPoolExecutor(1) as pool:
        first = pool.submit(session.headers.__delitem__, "X-First")
        try:
            assert read.wait(10)
            del session.headers["X-Second"]
            session.cookies.set("sid", "new", domain="127.0.0.1")
            check()
        finally:
            release.set()
        first.result()
    check()


def test_login_preserves_newer_host_cookie(tmp_path, monkeypatch):
    from unshackle.commands.dl import dl
    from unshackle.core.api import handlers

    monkeypatch.setattr(handlers.config.directories, "cookies", tmp_path)
    stale = requests.Session()
    stale.cookies.set("sid", "old", domain=".example.com")
    handlers.save_local_auth_cookies("EXAMPLE", None, SimpleNamespace(session=stale))
    baseline = handlers.snapshot_auth_cookies(dl.get_cookie_jar("EXAMPLE", None))
    stale.cookies = dl.get_cookie_jar("EXAMPLE", None)
    latest = requests.Session()
    latest.cookies.set("sid", "new", domain="example.com")
    handlers.save_local_auth_cookies("EXAMPLE", None, SimpleNamespace(session=latest), baseline)
    stale.cookies.set_cookie(requests.cookies.create_cookie("prefs", "1", domain="example.com"))
    handlers.save_local_auth_cookies("EXAMPLE", None, SimpleNamespace(session=stale), baseline)
    assert {(c.domain, c.name, c.value) for c in dl.get_cookie_jar("EXAMPLE", None)} == {
        ("example.com", "sid", "new"),
        ("example.com", "prefs", "1"),
    }


def test_expiry_during_rebuild_copy(cookie_server, monkeypatch, cookie_handler):
    import time

    from unshackle.core.session import RnetSession

    original = cookie_handler.do_GET

    def handle(handler):
        if handler.path == "/short":
            handler.send_response(200)
            handler.send_header("Set-Cookie", "sid=old; Max-Age=1")
            handler.end_headers()
        else:
            original(handler)

    monkeypatch.setattr(cookie_handler, "do_GET", handle)
    session = RnetSession()
    session.get(cookie_server + "/short")
    copy = session.copy_cookies

    def paused(source, target, origin):
        raw = source.get_cookies(origin)
        assert raw == b"sid=old"
        time.sleep(1.1)
        copy(SimpleNamespace(get_cookies=lambda _: raw), target, origin)

    monkeypatch.setattr(session, "copy_cookies", paused)
    session.rebuild_client()
    assert session.get(cookie_server + "/echo").text == ""
    assert not list(session.cookies.persistable_jar())


@pytest.mark.parametrize("first,second", [("old", "new"), ("expired", "new"), ("old", "expired")])
def test_paused_cookie_absorption(cookie_server, cookie_handler, monkeypatch, shared_cookie_file, first, second):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from unshackle.commands.dl import dl
    from unshackle.core.api import handlers
    from unshackle.core.session import RnetSession

    original = cookie_handler.do_GET

    def handle(handler):
        if handler.path in ("/old", "/new", "/expired"):
            handler.send_response(200)
            assignment = "sid=; Max-Age=0" if handler.path == "/expired" else f"sid={handler.path[1:]}"
            handler.send_header("Set-Cookie", assignment)
            handler.end_headers()
        else:
            original(handler)

    monkeypatch.setattr(cookie_handler, "do_GET", handle)
    session = RnetSession()
    entered, release = Event(), Event()
    absorb = session.cookies.absorb

    def paused(response, *args, **kwargs):
        if response.url.endswith("/" + first):
            entered.set()
            assert release.wait(10)
        absorb(response, *args, **kwargs)

    monkeypatch.setattr(session.cookies, "absorb", paused)
    with ThreadPoolExecutor(1) as pool:
        pending = pool.submit(session.get, cookie_server + "/" + first)
        try:
            assert entered.wait(10)
            session.get(cookie_server + "/" + second)
        finally:
            release.set()
        pending.result()
    expected = [] if second == "expired" else ["new"]
    assert session.get(cookie_server + "/echo").text == ("" if not expected else "sid=new")
    assert [c.value for c in session.cookies.persistable_jar()] == expected
    handlers.save_local_auth_cookies("EXAMPLE", None, SimpleNamespace(session=session))
    assert [c.value for c in dl.load_cookie_file(shared_cookie_file) if c.name == "sid"] == expected


@pytest.mark.parametrize("add_pref", [False, True])
def test_requests_retains_both_domain_rows(shared_cookie_file, add_pref):
    from unshackle.commands.dl import dl
    from unshackle.core.api import handlers

    shared_cookie_file.write_text(
        "example.com\tFALSE\t/\tFALSE\t0\tsid\tolder\n.example.com\tTRUE\t/\tFALSE\t0\tsid\tlatest\n"
    )
    session = requests.Session()
    session.cookies.update(dl.load_cookie_file(shared_cookie_file))
    baseline = handlers.snapshot_auth_cookies(session.cookies)
    if add_pref:
        session.cookies.set("prefs", "1", domain="example.com")
    handlers.save_local_auth_cookies("EXAMPLE", None, SimpleNamespace(session=session), baseline)
    assert {(c.domain, c.value) for c in dl.load_cookie_file(shared_cookie_file) if c.name == "sid"} == {
        ("example.com", "older"),
        (".example.com", "latest"),
    }


def test_same_value_response_metadata_order(cookie_server, cookie_handler, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from time import time

    from unshackle.core.session import RnetSession

    def handle(handler):
        metadata = "Max-Age=60" if handler.path == "/short" else "HttpOnly; Max-Age=3600"
        handler.send_response(200)
        handler.send_header("Set-Cookie", f"sid=same; {metadata}")
        handler.end_headers()

    monkeypatch.setattr(cookie_handler, "do_GET", handle)
    session = RnetSession()
    entered, release = Event(), Event()
    absorb = session.absorb_cookies

    def paused(response, *args, **kwargs):
        if response.url.endswith("/short"):
            entered.set()
            assert release.wait(10)
        return absorb(response, *args, **kwargs)

    monkeypatch.setattr(session, "absorb_cookies", paused)
    with ThreadPoolExecutor(1) as pool:
        first = pool.submit(session.get, cookie_server + "/short")
        try:
            assert entered.wait(10)
            start = int(time())
            session.get(cookie_server + "/long")
        finally:
            release.set()
        first.result()
    (cookie,) = session.cookies.persistable_jar()
    assert cookie.has_nonstandard_attr("HTTPOnly")
    assert cookie.expires >= start + 3600


def test_old_client_cookie_updates_across_publication(cookie_server, cookie_handler, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from unshackle.core.session import RnetSession

    copying, publish, requested, finish = (Event() for _ in range(4))
    original = cookie_handler.do_GET

    def handle(handler):
        if handler.path not in ("/first", "/second"):
            return original(handler)
        if handler.path == "/second":
            requested.set()
            assert finish.wait(10)
        handler.send_response(200)
        handler.send_header("Set-Cookie", f"sid={handler.path[1:]}")
        handler.end_headers()

    monkeypatch.setattr(cookie_handler, "do_GET", handle)
    session = RnetSession()
    session.get(cookie_server + "/echo")
    old_client = session._client
    copy = session.copy_cookies

    def paused(source, target, origin):
        copying.set()
        assert publish.wait(10)
        copy(source, target, origin)

    monkeypatch.setattr(session, "copy_cookies", paused)
    with ThreadPoolExecutor(2) as pool:
        rebuild = pool.submit(session.rebuild_client)
        try:
            assert copying.wait(10)
            session.get(cookie_server + "/first")
            second = pool.submit(session.get, cookie_server + "/second")
            assert requested.wait(10)
            publish.set()
            rebuild.result()
            assert session._client is not old_client
        finally:
            publish.set()
            finish.set()
        second.result()
    assert [c.value for c in session.cookies.persistable_jar()] == ["second"]
    assert session.get(cookie_server + "/echo").text == "sid=second"


@pytest.mark.parametrize("clear_first", [False, True], ids=["arrival-deadline", "clear-new-slot"])
def test_delayed_response_cookie_lifecycle(cookie_server, cookie_handler, monkeypatch, clear_first):
    from datetime import datetime, timedelta, timezone

    from unshackle.core import session as module

    instant = datetime.now(timezone.utc)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return instant

    monkeypatch.setattr(module, "datetime", Clock)
    original = cookie_handler.do_GET
    assignment = "sid=first" if clear_first else "sid=short; Max-Age=1"

    def handle(handler):
        if handler.path != "/set-test":
            return original(handler)
        handler.send_response(200)
        handler.send_header("Set-Cookie", assignment)
        handler.end_headers()

    monkeypatch.setattr(cookie_handler, "do_GET", handle)
    session = module.RnetSession()
    session.get(cookie_server + "/echo")
    absorb = session.absorb_cookies

    def delayed(response, *args, **kwargs):
        nonlocal instant
        if response.url.endswith("/set-test"):
            if clear_first:
                session.rebuild_client()
                session.cookies.clear(name="sid")
                assert session.get(cookie_server + "/echo").text == ""
            else:
                instant += timedelta(milliseconds=600)
        return absorb(response, *args, **kwargs)

    monkeypatch.setattr(session, "absorb_cookies", delayed)
    session.get(cookie_server + "/set-test")
    if not clear_first:
        from unittest.mock import patch

        with patch.object(session.cookies, "_wire_cookie", wraps=session.cookies._wire_cookie) as wire_cookie:
            session.rebuild_client()
        assert wire_cookie.call_args.args[1] == timedelta(milliseconds=400)
        assert [cookie.value for cookie in session.cookies.persistable_jar()] == ["short"]
        instant += timedelta(milliseconds=401)
        session.rebuild_client()
    assert session.get(cookie_server + "/echo").text == ""
    assert not list(session.cookies.persistable_jar())


@pytest.mark.parametrize("operation", ["expire", "delete", "clear-path"])
def test_unabsorbed_wire_cookie(cookie_server, cookie_handler, monkeypatch, operation):
    from time import sleep
    from urllib.parse import urlsplit

    from unshackle.core.session import RnetSession

    session = RnetSession(proxy=cookie_server)
    base = "http://sub.example.com"
    assignment = {
        "expire": "sid=short; Domain=example.com; Max-Age=1",
        "delete": "sid=short; Domain=example.com; Max-Age=0",
        "clear-path": "sid=live; Path=/account",
    }[operation]
    path = "/account" if operation == "clear-path" else ""

    def handle(handler):
        handler.send_response(200)
        if urlsplit(handler.path).path.endswith("/set"):
            handler.send_header("Set-Cookie", assignment)
        handler.end_headers()
        handler.wfile.write(handler.headers.get("Cookie", "").encode())

    monkeypatch.setattr(cookie_handler, "do_GET", handle)
    absorb = session.absorb_cookies

    def delayed(response, *args, **kwargs):
        if response.url.endswith("/set"):
            if operation == "clear-path":
                session.cookies.clear(name="sid")
            else:
                session.rebuild_client()
                if operation == "expire":
                    sleep(1.1)
            assert session.get(base + path + "/echo").text == ""
        return absorb(response, *args, **kwargs)

    if operation == "delete":
        session.cookies.set("sid", "old", domain=".example.com")
    monkeypatch.setattr(session, "absorb_cookies", delayed)
    session.get(base + path + "/set")
    assert session.get(base + path + "/echo").text == ""
    assert not list(session.cookies.persistable_jar())


@pytest.mark.parametrize("filters", [{"name": "sid"}, {"domain": ".example.com"}, {"path": "/account", "name": "sid"}])
def test_filtered_clear_pending_parent_cookie(cookie_server, cookie_handler, monkeypatch, filters):
    from unshackle.core.session import RnetSession

    session = RnetSession(proxy=cookie_server)
    base = "http://sub.example.com"
    path_filter = "path" in filters
    expected = "sid=root" if path_filter else ""

    def handle(handler):
        handler.send_response(200)
        if handler.path.endswith("/set"):
            value = "root" if path_filter else "parent"
            handler.send_header("Set-Cookie", f"sid={value}; Domain=example.com; Path=/")
            if path_filter:
                handler.send_header("Set-Cookie", "sid=acct; Domain=example.com; Path=/account")
        handler.end_headers()
        handler.wfile.write(handler.headers.get("Cookie", "").encode())

    monkeypatch.setattr(cookie_handler, "do_GET", handle)
    absorb = session.absorb_cookies
    echo = base + ("/account/echo" if path_filter else "/echo")

    def delayed(response, *args, **kwargs):
        if response.url.endswith("/set"):
            session.cookies.clear(**filters)
            assert session.get(echo).text == expected
        return absorb(response, *args, **kwargs)

    monkeypatch.setattr(session, "absorb_cookies", delayed)
    session.get(base + "/set")
    assert session.get(echo).text == expected
    assert [(c.name, c.value, c.path) for c in session.cookies.persistable_jar()] == (
        [("sid", "root", "/")] if path_filter else []
    )


@pytest.mark.parametrize("source", ["adapter", "pending", "path"])
def test_filtered_clear_preserves_imported_cookie(cookie_server, cookie_handler, monkeypatch, source):
    from unshackle.core.session import RnetSession

    session = RnetSession(proxy=cookie_server)
    other = "http://other.example"
    base = "http://sub.example.com"
    path = "/account" if source == "path" else "/"

    def handle(handler):
        handler.send_response(200)
        if handler.path.endswith("/set"):
            handler.send_header("Set-Cookie", "sid=drop; Domain=example.com; Path=/")
        handler.end_headers()
        handler.wfile.write(handler.headers.get("Cookie", "").encode())

    monkeypatch.setattr(cookie_handler, "do_GET", handle)
    session.import_origin_cookies({other: "sid=keep"})
    assert session.get(other + "/echo").text == "sid=keep"

    def clear():
        if source == "path":
            session.cookies.clear(path=path)
        else:
            session.cookies.clear(domain=".example.com")
        assert session.get(other + "/echo").text == "sid=keep"
        assert session.get(base + path.rstrip("/") + "/echo").text == ""

    if source == "pending":
        absorb = session.absorb_cookies

        def delayed(response, *args, **kwargs):
            if response.url.endswith("/set"):
                clear()
            return absorb(response, *args, **kwargs)

        monkeypatch.setattr(session, "absorb_cookies", delayed)
        session.get(base + "/set")
    else:
        session.cookies.set("sid", "drop", domain=".example.com", path=path)
        assert session.get(base + path.rstrip("/") + "/echo").text == "sid=drop"
        clear()
    session.rebuild_client()
    assert session.get(other + "/echo").text == "sid=keep"
    assert session.get(base + path.rstrip("/") + "/echo").text == ""


@pytest.mark.parametrize("rebuild_before_absorb", [False, True])
@pytest.mark.parametrize("cookie_path", ["/account", "/account/.."])
def test_path_clear_preserves_same_host_import(
    cookie_server, cookie_handler, monkeypatch, rebuild_before_absorb, cookie_path
):
    from unshackle.core.session import RnetSession

    session = RnetSession(proxy=cookie_server)
    base = "http://example.com"
    session.import_origin_cookies({base: "sid=keep"})

    def handle(handler):
        handler.send_response(200)
        if handler.path.endswith("/set"):
            handler.send_header("Set-Cookie", f"sid=drop; Path={cookie_path}")
        handler.end_headers()
        handler.wfile.write(handler.headers.get("Cookie", "").encode())

    monkeypatch.setattr(cookie_handler, "do_GET", handle)

    def assert_cookie():
        for path in ("/echo", "/account/echo"):
            assert session.get(base + path).text == "sid=keep"

    absorb = session.absorb_cookies

    def delayed(response, *args, **kwargs):
        if response.url.endswith("/set"):
            session.cookies.clear(path=cookie_path)
            assert_cookie()
            if rebuild_before_absorb:
                session.rebuild_client()
                assert_cookie()
        return absorb(response, *args, **kwargs)

    monkeypatch.setattr(session, "absorb_cookies", delayed)
    session.get(base + "/set")
    assert_cookie()
    session.rebuild_client()
    assert_cookie()


@pytest.mark.parametrize("path", ["/account/..", "/account/%2e%2e"])
def test_dot_path_clear_preserves_root_cookie(path):
    from unshackle.core.session import RnetSession

    session = RnetSession()
    client = session.ensure_client()
    session.cookies.set("sid", "keep", domain="example.com", path="/")
    session.cookies.set("sid", "drop", domain="example.com", path=path)
    session.cookies.clear(path=path)
    assert session.cookies.get("sid") == "keep"
    assert client.get_cookies("https://example.com/") == b"sid=keep"


@pytest.mark.parametrize("path", ["/ ", "/account/.. ", ""])
def test_noncanonical_clear_preserves_imported_root(path):
    from unshackle.core.session import RnetSession

    session = RnetSession()
    root = "https://example.com/"
    session.import_origin_cookies({"https://example.com": "sid=keep"})
    client = session.ensure_client()
    session.cookies.set("sid", "drop", domain="example.com", path=path)
    assert session.cookies.get("sid") == "drop"
    session.cookies.clear(path=path)
    assert session.cookies.get("sid") != "drop"
    assert client.get_cookies(root) == b"sid=keep"
    session.rebuild_client()
    assert session.ensure_client().get_cookies(root) == b"sid=keep"


def test_path_import_clear_survives_rebuild():
    from unshackle.core.session import RnetSession

    session = RnetSession()
    base = "https://example.com:8443"
    page = base + "/account/page"
    session.import_origin_cookies({page: "sid=v"})
    session.rebuild_client()
    client = session.ensure_client()
    assert client.get_cookies(base + "/account") == b"sid=v"
    assert not client.get_cookies(base + "/")
    session.cookies.clear(path="/account", name="sid")
    assert not client.get_cookies(page)
    session.rebuild_client()
    assert not session.ensure_client().get_cookies(page)
    session.import_origin_cookies({base: "root=keep"})
    assert set(session.export_origin_cookies()) == {base}


def test_save_empty_path_preserves_disk_root(shared_cookie_file):
    from unshackle.commands.dl import dl
    from unshackle.core.api import handlers
    from unshackle.core.session import RnetSession

    shared_cookie_file.write_text(".example.com\tTRUE\t/\tFALSE\t0\tsid\troot_keep\n")
    session = RnetSession()
    session.cookies.set("sid", "empty_new", domain="example.com", path="")
    handlers.save_local_auth_cookies("EXAMPLE", None, SimpleNamespace(session=session))
    jar = dl.load_cookie_file(shared_cookie_file)
    assert {(c.domain, c.path, c.value) for c in jar} == {
        (".example.com", "/", "root_keep"),
        ("example.com", "", "empty_new"),
    }
    session.import_origin_cookies({"https://example.com": "sid=root"})
    assert {c.path for c in session.scoped_cookies()} == {"", "/"}
    assert set(handlers.snapshot_auth_cookies(session.scoped_cookies())) == {
        ("example.com", "", "sid"),
        ("example.com", "/", "sid"),
    }


@pytest.mark.parametrize("parent", ["/account/long-filename", "/account/z/../long-filename"])
def test_import_replays_parent_cookie_before_child(parent):
    from unshackle.core.session import RnetSession

    session = RnetSession()
    base = "https://example.com:8443"
    child = base + "/account/x/y"
    session.import_origin_cookies({base + parent: "sid=v", child: "other=w"})
    session.rebuild_client()
    assert session.ensure_client().get_cookies(child) == b"sid=v; other=w"
    session.cookies.clear(path="/account", name="sid")
    assert session.ensure_client().get_cookies(child) == b"other=w"
    session.rebuild_client()
    assert session.ensure_client().get_cookies(child) == b"other=w"


@pytest.mark.parametrize(
    ("origin", "path"),
    [
        ("https://example.com:8443/account/..;param", "/account"),
        ("https:////example.com:8443/account/child", "/account"),
        ("https://example.com:8443/account;param/child", "/account;param"),
    ],
)
def test_import_url_grammar_survives_rebuild_and_clear(origin, path):
    from unshackle.core.session import RnetSession

    session = RnetSession()
    base = "https://example.com:8443"
    child = base + path + "/child"
    session.import_origin_cookies({origin: "sid=v"})
    for expected in (b"sid=v", None):
        for rebuild in (False, True):
            if rebuild:
                session.rebuild_client()
            client = session.ensure_client()
            assert client.get_cookies(child) == expected
            assert client.get_cookies(base + "/") is None
        if expected is not None:
            session.cookies.clear(path=path, name="sid")


@pytest.mark.parametrize("port", ["", ":8443"])
@pytest.mark.parametrize("domain", [None, "faß.example", "xn--fa-hia.example"])
def test_import_uts46_host_survives_rebuild_and_clear(port, domain):
    from unshackle.core.session import RnetSession

    session = RnetSession()
    base = "https://faß.example" + port
    child = base + "/account/child"
    other = "https://fass.example/account/child" if domain else "https://fass.example/elsewhere/child"
    session.import_origin_cookies({child: "sid=v", other: "sid=other"})
    assert session.ensure_client().get_cookies(child) == b"sid=v"
    target = session._canonical_import_target(child)
    assert target is not None
    assert target[1] == "/account"
    for expected in (b"sid=v", None):
        for rebuild in (False, True):
            if rebuild:
                session.rebuild_client()
            client = session.ensure_client()
            assert client.get_cookies(child) == expected
            assert client.get_cookies(base + "/") is None
            assert client.get_cookies(other) == b"sid=other"
        if expected is not None:
            session.cookies.clear(domain=domain, path="/account", name="sid")


def test_clear_stale_ipv6_cookie_once_per_slot(monkeypatch, tmp_path):
    from unshackle.commands.dl import dl
    from unshackle.core.api import handlers

    monkeypatch.setattr(handlers.config.directories, "cookies", tmp_path)
    session = requests.Session()
    session.cookies.set("sid", "old", domain="[::1]", path="/")
    handlers.save_local_auth_cookies("EXAMPLE", None, SimpleNamespace(session=session))
    session.cookies.clear()
    for domain in ("::1", ".::1"):
        session.cookies.set("sid", domain, domain=domain, path="/")
    handlers.save_local_auth_cookies("EXAMPLE", None, SimpleNamespace(session=session))
    jar = dl.get_cookie_jar("EXAMPLE", None)
    assert jar is not None
    assert {(c.domain, c.path, c.name, c.value) for c in jar} == {
        ("::1", "/", "sid", "::1"),
        (".::1", "/", "sid", ".::1"),
    }


def test_login_restores_missing_dotted_ipv6_cookie(tmp_path, monkeypatch):
    from unshackle.commands.dl import dl
    from unshackle.core.api import handlers

    monkeypatch.setattr(handlers.config.directories, "cookies", tmp_path)
    session = requests.Session()
    session.cookies.set("sid", "host", domain="::1", path="/")
    service = SimpleNamespace(session=session)
    handlers.save_local_auth_cookies("EXAMPLE", None, service)
    session.cookies.set("sid", "dot", domain=".::1", path="/")
    baseline = handlers.snapshot_auth_cookies(session.cookies)

    handlers.save_local_auth_cookies("EXAMPLE", None, service, baseline)

    assert {(c.domain, c.path, c.name, c.value) for c in dl.get_cookie_jar("EXAMPLE", None)} == {
        ("::1", "/", "sid", "host"),
        (".::1", "/", "sid", "dot"),
    }


@pytest.mark.parametrize(
    ("location", "expected"),
    [
        ("folder//item", "/dir/folder//item"),
        ("../a//b", "/a//b"),
        ("http:/", "/"),
        ("http:/foo//bar", "/foo//bar"),
        (r"http:\foo\bar", "/foo/bar"),
    ],
)
def test_relative_redirect_preserves_empty_segments(cookie_server, cookie_handler, monkeypatch, location, expected):
    import rnet

    from unshackle.core.session import RnetSession

    observed = []

    def handle(handler):
        if handler.path == "/dir/start":
            handler.send_response(302)
            handler.send_header("Location", location)
            handler.send_header("Set-Cookie", f"sid=v; Path={expected}")
        else:
            observed.append((handler.path, handler.headers.get("Cookie")))
            handler.send_response(200)
        handler.end_headers()

    monkeypatch.setattr(cookie_handler, "do_GET", handle)
    url = cookie_server + "/dir/start"
    assert str(rnet.BlockingClient(allow_redirects=True, cookie_store=True).get(url).status_code) == "200"
    assert observed == [(expected, "sid=v")]
    assert RnetSession().get(url).status_code == 200
    assert observed[1:] == observed[:1]


@pytest.mark.parametrize(
    ("start", "location", "expected"),
    [("/start?old=1", "?", "/start?"), ("/start?old=1", "http:?", "/start?"), ("/from_empty?#frag", "/done", "/done")],
)
def test_redirect_preserves_empty_query(cookie_server, cookie_handler, monkeypatch, start, location, expected):
    import rnet

    from unshackle.core.session import RnetSession

    observed = []

    def handle(handler):
        if handler.path == start.partition("#")[0]:
            handler.send_response(302)
            handler.send_header("Location", location)
        else:
            observed.append((handler.path, handler.headers.get("Referer")))
            handler.send_response(200)
        handler.end_headers()

    monkeypatch.setattr(cookie_handler, "do_GET", handle)
    for client in (rnet.BlockingClient(allow_redirects=True), RnetSession()):
        response = client.get(cookie_server + start)
        assert observed.pop() == (expected, cookie_server + start.partition("#")[0])
        assert str(response.url) == cookie_server + expected


@pytest.mark.parametrize("location", ["", "   ", None], ids=["empty", "spaces", "missing"])
def test_blank_redirect_location(cookie_server, cookie_handler, monkeypatch, location):
    import rnet

    from unshackle.core.session import RnetSession

    observed = []

    def handle(handler):
        observed.append((handler.path, handler.headers.get("Referer")))
        if len(observed) == 1:
            handler.send_response(302)
            if location is not None:
                handler.send_header("Location", location)
        else:
            handler.send_response(200)
        handler.end_headers()

    monkeypatch.setattr(cookie_handler, "do_GET", handle)
    target = cookie_server + "/start?"
    for client in (rnet.BlockingClient(allow_redirects=True), RnetSession()):
        observed.clear()
        response = client.get(target + "#old")
        if location is None:
            assert str(response.status_code) == "302"
            assert observed == [("/start?", None)]
        else:
            assert str(response.status_code) == "200"
            assert observed == [("/start?", None), ("/start?", target)]
            assert str(response.url) == target


@pytest.mark.parametrize(
    ("source", "target", "expected"),
    [
        ("127.0.0.1", "%31%32%37.0.0.1", "Bearer test"),
        ("%31%32%37.0.0.1", "127.0.0.1", "Bearer test"),
        ("127.0.0.1", "0x7f.0.0.1", "Bearer test"),
        ("127.0.0.1", "2130706433", "Bearer test"),
        ("[::1]", "[0:0:0:0:0:0:0:1]", "Bearer test"),
        ("127.0.0.1", "localhost", None),
    ],
)
def test_canonical_redirect_authorization(cookie_handler, monkeypatch, source, target, expected):
    import socket
    from http.server import ThreadingHTTPServer
    from threading import Thread

    import rnet

    from unshackle.core.session import RnetSession

    observed = []

    def handle(handler):
        if handler.path == "/start":
            handler.send_response(302)
            handler.send_header("Location", f"http://{target}:{handler.server.server_port}/finish")
        else:
            observed.append((handler.path, handler.headers.get("Authorization")))
            handler.send_response(200)
        handler.end_headers()

    class IPv6Server(ThreadingHTTPServer):
        address_family = socket.AF_INET6

    monkeypatch.setattr(cookie_handler, "do_GET", handle)
    ipv6 = source == "[::1]"
    server_type = IPv6Server if ipv6 else ThreadingHTTPServer
    with server_type(("::1" if ipv6 else "127.0.0.1", 0), cookie_handler) as server:
        thread = Thread(target=server.serve_forever)
        thread.start()
        try:
            for client in (rnet.BlockingClient(allow_redirects=True), RnetSession()):
                client.get(f"http://{source}:{server.server_port}/start", headers={"Authorization": "Bearer test"})
                assert observed.pop() == ("/finish", expected)
        finally:
            server.shutdown()
            thread.join()


def test_canonical_redirect_origin():
    from urllib.parse import urlsplit

    from unshackle.core.session import _same_origin

    for first, second, expected in (
        ("[::ffff:127.0.0.1]", "[::ffff:7f00:1]", True),
        ("faß.example", "xn--fa-hia.example", True),
        ("example.com.", "example.com", False),
        ("", "", False),
    ):
        assert _same_origin(urlsplit(f"http://{first}"), urlsplit(f"http://{second}")) is expected


@pytest.mark.parametrize("url_fields", [{}, {"url": None}], ids=["missing-url", "null-url"])
def test_real_minimal_responses_follow_relative_redirect(monkeypatch, url_fields):
    from unshackle.core import session as session_module

    redirect = SimpleNamespace(status_code=302, headers={"Location": "/done"}, **url_fields)
    responses = iter([redirect, SimpleNamespace(status_code=200, headers={})])
    urls = []

    def request(method, url, **kwargs):
        urls.append(url)
        return next(responses)

    session = session_module.RnetSession()
    monkeypatch.setattr(session, "ensure_client", lambda: SimpleNamespace(request=request))
    response = session.get("http://127.0.0.1/start")
    assert (response.status_code, urls) == (200, ["http://127.0.0.1/start", "http://127.0.0.1/done"])

    response = session_module.RnetResponse(redirect)
    assert response.url == ""
    assert response.headers["location"] == "/done"
    assert "location" in response.headers
    assert response.headers.get("location") == "/done"
    assert len(response.headers) == 1


def test_minimal_responses_follow_relative_redirect(monkeypatch):
    from unshackle.core import session as session_module

    session = session_module.RnetSession()
    urls = []

    def request(method, url, **kwargs):
        urls.append(url)
        return SimpleNamespace() if len(urls) == 1 else None

    monkeypatch.setattr(session, "ensure_client", lambda: SimpleNamespace(request=request))
    monkeypatch.setattr(
        session_module,
        "RnetResponse",
        lambda raw: (
            SimpleNamespace(status_code=200)
            if raw is None
            else SimpleNamespace(status_code=302, headers={"Location": "/done"})
        ),
    )
    assert session.get("http://127.0.0.1/start").status_code == 200
    assert urls == ["http://127.0.0.1/start", "http://127.0.0.1/done"]
