"""Session utilities for creating HTTP sessions with TLS fingerprinting through rnet (Rust/BoringSSL)."""

from __future__ import annotations

import functools
import http
import ipaddress
import logging
import math
import random
import re
import sys
import threading
import time
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping, MutableMapping
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from http.cookiejar import Cookie, CookieJar
from typing import Any, Optional, Union
from urllib.parse import SplitResult, quote, unquote, urlencode, urlparse, urlsplit, urlunparse

import rnet
from requests import HTTPError, Request, Response, Session
from requests.cookies import create_cookie
from requests.structures import CaseInsensitiveDict

from unshackle.core.config import config
from unshackle.core.utils import run_proxy

# rnet's only distinguishing role is TLS fingerprinting; retry, backoff,
# pooling, and timeouts must match the plain-requests path. Both RnetSession
# (below) and Service.get_session import these so the two can't drift.
# The unified downloader keeps its own copies (downloaders/requests.py) by design.

MAX_RETRIES = 5
BACKOFF_FACTOR = 0.2
MAX_BACKOFF = 60.0  # shared backoff cap (rnet max_backoff == requests Retry backoff_max)
STATUS_FORCELIST = [429, 500, 502, 503, 504]
RETRY_METHODS = frozenset({"GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "TRACE"})
# pool_block=True means a pool smaller than the in-flight request count stalls threads
POOL_MAX_SIZE = 64  # rnet pool_max_idle_per_host == requests pool_maxsize/pool_connections
CONNECT_TIMEOUT = 10
READ_TIMEOUT = 30


DEFAULT_IMPERSONATE = rnet.Impersonate.Chrome131


_PATH_PROBE_LOCK = threading.Lock()
_PATH_PROBE_CLIENT = rnet.BlockingClient(cookie_store=True)


@functools.lru_cache(maxsize=512)
def _rnet_same_host(h1: str, h2: str) -> bool:
    b1, b2 = h1.strip("[]").lower(), h2.strip("[]").lower()
    if not b1 or not b2:
        return False
    if ":" in b1 or ":" in b2:
        if "%" in b1 or "%" in b2:
            return False
        try:
            return ipaddress.IPv6Address(b1) == ipaddress.IPv6Address(b2)
        except ValueError:
            return False
    if b1 == b2:
        return True
    with _PATH_PROBE_LOCK:
        _PATH_PROBE_CLIENT.clear_cookies()
        try:
            _PATH_PROBE_CLIENT.set_cookie(f"https://{RnetCookieAdapter._url_host(b1)}", rnet.Cookie("p", "1"))
            return _PATH_PROBE_CLIENT.get_cookies(f"https://{RnetCookieAdapter._url_host(b2)}") == b"p=1"
        except Exception:
            return False
        finally:
            _PATH_PROBE_CLIENT.clear_cookies()


def _rnet_host_matches(host: str, bare_domain: str, include_subdomains: bool = True) -> bool:
    if _rnet_same_host(host, bare_domain):
        return True
    if include_subdomains:
        labels = host.strip("[]").split(".")
        return any(_rnet_same_host(".".join(labels[i:]), bare_domain) for i in range(1, len(labels)))
    return False


@functools.lru_cache(maxsize=512)
def _is_exact_rnet_nonroot_path(path: str) -> bool:
    if (
        not path.startswith("/")
        or path == "/"
        or "?" in path
        or "#" in path
        or "\\" in path
        or any(ord(ch) <= 0x20 or ord(ch) >= 0x7F or ch in '"<>`{}' for ch in path)
        or any(unquote(seg) in (".", "..") for seg in path.split("/"))
    ):
        return False
    with _PATH_PROBE_LOCK:
        _PATH_PROBE_CLIENT.clear_cookies()
        try:
            _PATH_PROBE_CLIENT.set_cookie("https://localhost", rnet.Cookie("p", "1", path=path))
            return (
                _PATH_PROBE_CLIENT.get_cookies("https://localhost" + path) == b"p=1"
                and _PATH_PROBE_CLIENT.get_cookies("https://localhost/") is None
            )
        except Exception:
            return False
        finally:
            _PATH_PROBE_CLIENT.clear_cookies()


def resolve_impersonate(browser: str) -> rnet.Impersonate:
    """Change a browser string to an rnet.Impersonate preset.

    Accepts exact rnet preset names (e.g. "Chrome131", "OkHttp4_12", "Edge101").
    See https://github.com/0x676e67/rnet for the full list of available presets.
    """
    preset = getattr(rnet.Impersonate, browser, None)
    if preset is not None:
        return preset
    raise ValueError(f"Unknown impersonate preset {browser!r}, expected an rnet.Impersonate name such as 'Chrome131'")


METHOD_MAP: dict[str, rnet.Method] = {
    "GET": rnet.Method.GET,
    "POST": rnet.Method.POST,
    "PUT": rnet.Method.PUT,
    "DELETE": rnet.Method.DELETE,
    "HEAD": rnet.Method.HEAD,
    "OPTIONS": rnet.Method.OPTIONS,
    "PATCH": rnet.Method.PATCH,
    "TRACE": rnet.Method.TRACE,
}


class RnetResponseHeaders(MutableMapping):
    """Read-only str-based view over rnet's bytes-based HeaderMap."""

    def __init__(self, header_map: Any) -> None:
        self._map = header_map

    def decode(self, val: Any) -> str:
        return val.decode("utf-8", errors="replace") if isinstance(val, (bytes, bytearray)) else str(val)

    def __getitem__(self, key: str) -> str:
        if hasattr(self._map, "contains_key"):
            return self.decode(self._map[key])
        for k, v in self._map.items():
            if self.decode(k).lower() == key.lower():
                return self.decode(v)
        raise KeyError(key)

    def __setitem__(self, key: str, value: str) -> None:
        raise TypeError("Response headers are read-only")

    def __delitem__(self, key: str) -> None:
        raise TypeError("Response headers are read-only")

    def __contains__(self, key: object) -> bool:
        if not isinstance(key, str):
            return False
        if hasattr(self._map, "contains_key"):
            return self._map.contains_key(key)
        return any(self.decode(k).lower() == key.lower() for k in self._map)

    def __iter__(self) -> Iterator[str]:
        seen: set[str] = set()
        for k, _ in self._map.items():
            dk = self.decode(k)
            if dk not in seen:
                seen.add(dk)
                yield dk

    def __len__(self) -> int:
        if hasattr(self._map, "keys_len"):
            return self._map.keys_len()
        return len({self.decode(k).lower() for k in self._map})

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:  # type: ignore[override]
        if hasattr(self._map, "contains_key"):
            val = self._map.get(key)
            return default if val is None else self.decode(val)
        try:
            return self[key]
        except KeyError:
            return default

    def items(self) -> list[tuple[str, str]]:  # type: ignore[override]
        return [(self.decode(k), self.decode(v)) for k, v in self._map.items()]


class RnetResponse:
    """Wraps rnet.BlockingResponse with a requests-compatible API."""

    def __init__(self, resp: Any) -> None:
        self._resp = resp
        self._headers: Optional[RnetResponseHeaders] = None
        self._content: Optional[bytes] = None
        self._text: Optional[str] = None
        self._streamed = False

    @property
    def status_code(self) -> int:
        return int(str(self._resp.status_code))

    @property
    def ok(self) -> bool:
        return self._resp.ok

    @property
    def headers(self) -> RnetResponseHeaders:
        if self._headers is None:
            self._headers = RnetResponseHeaders(self._resp.headers)
        return self._headers

    @property
    def url(self) -> str:
        raw_url = getattr(self._resp, "url", None)
        return "" if raw_url is None else str(raw_url)

    @property
    def content_length(self) -> Optional[int]:
        return self._resp.content_length

    @property
    def content(self) -> bytes:
        if self._content is None:
            self._content = self._resp.bytes()
        return self._content

    @property
    def text(self) -> str:
        if self._text is None:
            encoding = self._resp.encoding or "utf-8"
            self._text = self.content.decode(encoding, errors="replace")
        return self._text

    @property
    def reason(self) -> str:
        try:
            return http.HTTPStatus(self.status_code).phrase
        except ValueError:
            return "Unknown"

    @property
    def cookies(self) -> Any:
        return self._resp.cookies

    @property
    def version(self) -> str:
        """Get the HTTP version used for the response as a string (e.g. 'HTTP/2', 'HTTP/1.1')."""
        try:
            v_str = str(self._resp.version)
            if "HTTP_2" in v_str:
                return "HTTP/2"
            elif "HTTP_11" in v_str:
                return "HTTP/1.1"
            elif "HTTP_3" in v_str:
                return "HTTP/3"
            elif "HTTP_10" in v_str:
                return "HTTP/1.0"
            elif "HTTP_09" in v_str:
                return "HTTP/0.9"
            return v_str.replace("Version.", "").replace("_", "/")
        except Exception:
            return "HTTP/1.1"

    def json(self, **kwargs: Any) -> Any:
        import json as _json

        return _json.loads(self.content)

    def raise_for_status(self) -> None:
        if not self.ok:
            raise HTTPError(
                f"{self.status_code} {self.reason}: {self.url}",
                response=self,  # type: ignore[arg-type]
            )

    def iter_content(self, chunk_size: Optional[int] = None) -> Iterator[bytes]:
        """Re-chunk rnet's variable-size data into fixed-size pieces."""
        self._streamed = True
        if chunk_size is None or chunk_size <= 0:
            yield from self._resp.stream()
            return

        buf = bytearray()
        for chunk in self._resp.stream():
            buf.extend(chunk)
            while len(buf) >= chunk_size:
                yield bytes(buf[:chunk_size])
                buf = buf[chunk_size:]
        if buf:
            yield bytes(buf)

    def stream(self) -> Iterator[bytes]:
        """Direct pass-through of rnet's native ``stream()`` iterator."""
        self._streamed = True
        yield from self._resp.stream()

    def close(self) -> None:
        try:
            self._resp.close()
        except Exception:
            pass


def utf8_text(res: Response | RnetResponse) -> str:
    """Return the response text, decoded as UTF-8 unless the server sent a charset.

    With no charset, requests assumes ISO-8859-1 for a `text/*` type and runs charset detection
    on the full body for any other type. Use this only for a format that is UTF-8 by
    specification, such as M3U8.
    """
    if isinstance(res, Response) and "charset" not in res.headers.get("content-type", "").lower():
        res.encoding = "utf-8"
    return res.text


_REDIRECT_CREDENTIAL_HEADERS = {"authorization", "proxy-authorization", "cookie"}


def _remove_whatwg_dot_segments(path: str) -> str:
    if not path:
        return ""
    segments = path.split("/")
    out: list[str] = []
    for index, segment in enumerate(segments):
        if index == 0 and not segment:
            continue
        decoded = unquote(segment)
        if decoded in (".", ".."):
            if decoded == ".." and out:
                out.pop()
            if index == len(segments) - 1:
                out.append("")
        else:
            out.append(segment)
    return "/" + "/".join(out)


_REDIRECT_TRIM = "".join(chr(i) for i in range(0x21))


def _resolve_redirect_url(base_url: str, location: str) -> str:
    base = urlsplit(base_url)
    ref = location.strip(_REDIRECT_TRIM).replace("\t", "").replace("\r", "").replace("\n", "")
    scheme = base.scheme
    authority = base.netloc
    has_authority = False
    candidate, colon, rest = ref.partition(":")
    if colon and candidate.isascii() and candidate[:1].isalpha() and all(c.isalnum() or c in "+-." for c in candidate):
        scheme = candidate.lower()
        if scheme not in ("http", "https"):
            return ref
        ref = rest
        has_authority = scheme != base.scheme.lower()

    path_end = min((i for c in "?#" if (i := ref.find(c)) >= 0), default=len(ref))
    path, suffix = ref[:path_end].replace("\\", "/"), ref[path_end:]
    if has_authority or path.startswith("//"):
        authority, _, tail = path.lstrip("/").partition("/")
        path = "/" + tail
    elif not path:
        if suffix.startswith("?"):
            return f"{scheme}://{authority}{base.path or '/'}{suffix}"
        _, qmark, raw_query = base_url.partition("#")[0].partition("?")
        return f"{scheme}://{authority}{base.path or '/'}{qmark}{raw_query}{suffix}"
    elif not path.startswith("/"):
        path = base.path.rpartition("/")[0] + "/" + path
    return f"{scheme}://{authority}{_remove_whatwg_dot_segments(path)}{suffix}"


def _origin_key(parsed: SplitResult) -> tuple[str, str, Optional[int]]:
    scheme = parsed.scheme.lower()
    default_port = 80 if scheme == "http" else 443 if scheme == "https" else None
    return scheme, (parsed.hostname or "").lower(), parsed.port if parsed.port is not None else default_port


def _same_origin(first: SplitResult, second: SplitResult) -> bool:
    s1, h1, p1 = _origin_key(first)
    s2, h2, p2 = _origin_key(second)
    return s1 == s2 and p1 == p2 and _rnet_same_host(h1, h2)


_REDIRECT_BODY_HEADERS = {"content-length", "content-type", "content-encoding", "transfer-encoding"}
_REDIRECT_HEADERS = _REDIRECT_CREDENTIAL_HEADERS | _REDIRECT_BODY_HEADERS


class RnetSessionHeaders(CaseInsensitiveDict):
    """Dict-like headers that write to the rnet client through update()."""

    def __init__(self, session: Optional[RnetSession] = None) -> None:
        self._session = session
        self._client: Any = None
        super().__init__()

    def sync(self, client: Optional[rnet.BlockingClient] = None) -> None:
        """Push current headers to the rnet client."""
        target = client or self._client
        if target is not None and hasattr(self, "_store"):
            target.update(headers={k: v for k, v in self.items() if k.lower() not in _REDIRECT_HEADERS})

    def __setitem__(self, key: str, value: str) -> None:
        super().__setitem__(key, value)
        self.sync()

    def update(self, __m: Any = None, **kwargs: Any) -> None:
        if __m:
            if hasattr(__m, "items"):
                for k, v in __m.items():
                    super().__setitem__(k, v)
            else:
                for k, v in __m:
                    super().__setitem__(k, v)
        for k, v in kwargs.items():
            super().__setitem__(k, v)
        self.sync()

    def rebuild(self) -> None:
        """Remake the rnet client so removed headers stop going out.

        rnet's update() merges into the client default headers and offers no removal,
        so a header dropped from this dict alone keeps reaching every later host.
        """
        if self._session is not None and self._client is not None:
            self._session.rebuild_client()

    def __delitem__(self, key: str) -> None:
        super().__delitem__(key)
        self.rebuild()

    def clear(self) -> None:
        for key in list(self.keys()):
            super().__delitem__(key)
        self.rebuild()


class RnetCookieAdapter(MutableMapping):
    """Cookie adapter that bridges requests-style cookie access to rnet.

    One store keyed by (domain, path, name) holds every cookie set through this class, in write
    order. Same-name cookies on different paths stay apart on the wire, and the latest write
    answers a lookup by name.
    """

    def __init__(self, client: Any, session: Optional[RnetSession] = None) -> None:
        self._client = client
        self._lock = threading.RLock()
        self._active_rebuilds: dict[int, list[tuple[Any, ...]]] = {}
        self._tls = threading.local()
        self._session = session
        self._store: dict[tuple[str, str, str], Cookie] = {}
        self._received: dict[tuple[str, str, str], Cookie] = {}
        self._in_flight: dict[int, tuple[int, int, rnet.BlockingClient, datetime, str, list[Any]]] = {}
        self._seq_counter = 0
        self._filter_clears: list[tuple[int, Optional[str], Optional[str], Optional[str]]] = []
        self._clear_all_seq = 0
        self._slot_seq: dict[tuple[str, str, str], int] = {}
        self._slot_gen: dict[tuple[str, str, str], int] = {}
        self._expiry: dict[tuple[str, str, str], datetime] = {}
        self._from_jar: set[tuple[str, str, str]] = set()

    @staticmethod
    def _url_host(host: str) -> str:
        bare = host.strip("[]")
        return f"[{bare}]" if ":" in bare else bare

    @staticmethod
    def client_url(cookie: Cookie) -> str:
        """The URL rnet stores *cookie* under; a domain-less cookie goes to localhost."""
        host = (cookie.domain or "").lstrip(".")
        return f"https://{RnetCookieAdapter._url_host(host or 'localhost')}"

    @staticmethod
    def to_rnet(cookie: Cookie) -> rnet.Cookie:
        """The rnet form of *cookie*.

        A leading dot marks a cookie for subdomains too, as in a Netscape cookie file; without
        one the cookie stays on its own host. Expiry stays out, so no layer drops a cookie the
        cookie loader deliberately kept.
        """
        return RnetCookieAdapter._wire_cookie(cookie)

    @staticmethod
    def _wire_cookie(cookie: Cookie, max_age: Optional[timedelta] = None) -> rnet.Cookie:
        domain = cookie.domain or ""
        return rnet.Cookie(
            cookie.name,
            cookie.value or "",
            domain=domain if domain.startswith(".") else None,
            path=cookie.path or "/",
            secure=bool(cookie.secure),
            http_only=cookie.has_nonstandard_attr("HTTPOnly"),
            max_age=max_age,
        )

    def _push_cookie(
        self,
        cookie: Cookie,
        key: tuple[str, str, str],
        now: Optional[datetime] = None,
        client: Optional[rnet.BlockingClient] = None,
    ) -> None:
        target = client or self._client
        if target is None or cookie.path == "":
            return
        deadline = self._expiry.get(key)
        remaining = deadline - (now or datetime.now(timezone.utc)) if deadline is not None else None
        if remaining is not None and remaining.total_seconds() <= 0:
            return
        try:
            target.set_cookie(self.client_url(cookie), self._wire_cookie(cookie, remaining))
        except Exception:
            pass

    @staticmethod
    def _slot_key(domain: Optional[str], path: Optional[str], name: str) -> tuple[str, str, str]:
        return ((domain or "").lstrip(".").strip("[]").lower(), path if path is not None else "/", name)

    def _next_seq(self) -> int:
        self._seq_counter += 1
        return self._seq_counter

    def next_seq(self) -> int:
        with self._lock:
            return self._next_seq()

    def _discard(self, key: tuple[str, str, str]) -> None:
        self._store.pop(key, None)
        self._from_jar.discard(key)
        self._received.pop(key, None)
        self._expiry.pop(key, None)

    def _prune_expired(self, now: Optional[datetime] = None) -> None:
        now = now or datetime.now(timezone.utc)
        for key, deadline in list(self._expiry.items()):
            if deadline <= now:
                cookie = self._store.get(key) or self._received.get(key)
                cpath = key[1]
                cdomain = cookie.domain if cookie is not None else f".{key[0]}"
                self._record_touch(
                    key[2], domain=cdomain, path=cpath, include_subdomains=(cpath == "/" and cdomain.startswith("."))
                )
                self._discard(key)

    def add(self, cookie: Cookie, from_jar: bool = False) -> None:
        """Store *cookie* as the latest write for its (domain, path, name) and send it to the client."""
        with self._lock:
            key = self._slot_key(cookie.domain, cookie.path, cookie.name)
            cpath = key[1]
            self._record_touch(
                cookie.name,
                domain=cookie.domain,
                path=cpath,
                include_subdomains=cpath == "/" and bool(cookie.domain and cookie.domain.startswith(".")),
            )
            self._expiry.pop(key, None)
            self._received.pop(key, None)
            self._store.pop(key, None)
            if self._session is not None:
                self._slot_gen[key] = self._session._published_gen
            self._slot_seq[key] = self._next_seq()
            self._store[key] = cookie
            if from_jar:
                self._from_jar.add(key)
            self._push_cookie(cookie, key)

    def snapshot(self) -> list[Cookie]:
        """Every stored cookie, oldest write first. Download threads write the store, so read a copy."""
        with self._lock:
            self._prune_expired()
            return list(self._store.values())

    def flush_to_client(self) -> None:
        """Push all buffered cookies to the rnet client after unshackle makes it."""
        with self._lock:
            now = datetime.now(timezone.utc)
            self._prune_expired(now)
            for jar in (self._store, self._received):
                for key, cookie in list(jar.items()):
                    self._push_cookie(cookie, key, now, getattr(self._tls, "rebuild_client", None))

    def _pending_cookies(
        self, now: Optional[datetime] = None
    ) -> list[tuple[int, int, rnet.BlockingClient, tuple[str, str, str], Cookie, Optional[datetime]]]:
        now = now or datetime.now(timezone.utc)
        rows = []
        for seq, req_gen, req_client, arrived, url, cookies in sorted(self._in_flight.values()):
            parsed = urlparse(url)
            default_path = (parsed.path[: parsed.path.rfind("/")] or "/") if parsed.path.startswith("/") else "/"
            for raw in cookies:
                row = self._parse_server_cookie(raw, parsed.hostname or "", default_path, arrived, now)
                if row is not None:
                    key, fresh, deadline = row
                    rows.append((seq, req_gen, req_client, key, fresh, deadline))
        return rows

    def _pending_staged(
        self, now: datetime, target_client: Optional[rnet.BlockingClient] = None, name: Optional[str] = None
    ) -> dict[tuple[str, str, str], tuple[Cookie, Optional[datetime]]]:
        return {
            key: (fresh, deadline)
            for seq, req_gen, req_client, key, fresh, deadline in self._pending_cookies(now)
            if (name is None or fresh.name == name)
            and not self._superseded(seq, key, fresh)
            and not (
                target_client is not None
                and req_client is not None
                and req_client is not target_client
                and self._slot_gen.get(key, -1) > req_gen
            )
        }

    @staticmethod
    def _is_safe_url_path(path: str) -> bool:
        return path == "/" or _is_exact_rnet_nonroot_path(path)

    def client_urls(
        self,
        domain: Optional[str] = None,
        name: Optional[str] = None,
        path: Optional[str] = None,
        include_subdomains: bool = False,
    ) -> list[str]:
        """URLs the rnet cookie jar could hold a cookie under.

        rnet keys its jar by URL, removes a cookie only at its exact path, and cannot list the
        jar. So a removal names every host this class has set a cookie on, every origin the
        HTTP session has requested, and every stored path of the cookie *name*.
        """
        cookies = list(self._store.values()) + list(self._received.values())
        cookies.extend(fresh for _, _, _, _, fresh, _ in self._pending_cookies())
        hosts = {self.client_url(c) for c in cookies} | {"https://localhost"}
        if self._session is not None:
            hosts |= set(self._session._origins)
        if domain is not None:
            if any(ord(ch) <= 0x20 or ord(ch) == 0x7F or ch in "/?#@\\" for ch in domain):
                return []
            host_bare = "localhost" if domain == "" else domain.lstrip(".").strip("[]").lower()
            if not host_bare:
                return []
            hosts = {
                url
                for url in hosts
                if _rnet_host_matches(urlsplit(url).hostname or "", host_bare, include_subdomains=include_subdomains)
            }
            hosts.add(f"https://{self._url_host(host_bare)}")
        if path is not None:
            if path == "/":
                return sorted(hosts)
            if not _is_exact_rnet_nonroot_path(path):
                return []
            return sorted({url + path for url in hosts})
        paths = {
            c.path
            for c in cookies
            if c.path and _is_exact_rnet_nonroot_path(c.path) and (name is None or c.name == name)
        }
        if self._session is not None:
            paths.update(p for p in self._session._paths if _is_exact_rnet_nonroot_path(p))
        return sorted(hosts | {url + path for url in hosts for path in paths})

    def remove_cookie_on_client(self, name: str, domain: Optional[str] = None) -> None:
        """Drop a cookie from the rnet cookie jar; call it before the store forgets the cookie's paths.

        The client is built with cookie_store=True, so a cookie the server set lives in that
        jar alone. Dropping it from the store leaves it going out on the wire.
        """
        if self._client is None:
            return
        for url in self.client_urls(domain, name):
            try:
                self._client.remove_cookie(url, name)
            except Exception:
                pass

    @staticmethod
    def _received_domain(domain: Optional[str], host: str) -> Optional[str]:
        host = host.strip("[]")
        if domain is None:
            return host or None
        bare = domain.strip().lstrip(".").lower()
        if not bare or (bare != host and not host.endswith(f".{bare}")):
            return None
        try:
            ipaddress.ip_address(bare)
        except ValueError:
            return f".{bare}"
        return bare

    def _parse_server_cookie(
        self, server_cookie: Any, host: str, default_path: str, arrived_at: datetime, now: datetime
    ) -> Optional[tuple[tuple[str, str, str], Cookie, Optional[datetime]]]:
        path = server_cookie.path if (server_cookie.path or "").startswith("/") else default_path
        domain = self._received_domain(server_cookie.domain, host.lower())
        if domain is None or not server_cookie.name:
            return None
        key = self._slot_key(domain, path, server_cookie.name)
        max_age, expires = server_cookie.max_age, server_cookie.expires
        if max_age is not None:
            deadline = arrived_at + max_age
        elif expires is not None and expires.tzinfo is None:
            deadline = expires.replace(tzinfo=timezone.utc)
        else:
            deadline = expires

        fresh = create_cookie(
            server_cookie.name,
            server_cookie.value,
            domain=domain,
            path=path,
            secure=bool(server_cookie.secure),
            expires=int(deadline.timestamp()) if deadline is not None else None,
            discard=deadline is None,
            rest={"HTTPOnly": ""} if server_cookie.http_only else {},
        )
        fresh.domain_specified = domain.startswith(".")
        fresh.path_specified = (server_cookie.path or "").startswith("/")
        return key, fresh, deadline

    def _superseded(self, seq: int, key: tuple[str, str, str], fresh: Cookie) -> bool:
        return seq < max(self._clear_all_seq, self._slot_seq.get(key, 0)) or any(
            seq < clear_seq
            and domain in (None, fresh.domain)
            and path in (None, fresh.path)
            and name in (None, fresh.name)
            for clear_seq, domain, path, name in self._filter_clears
        )

    def _reconcile_name_on_client(
        self,
        target_client: Optional[rnet.BlockingClient],
        name: str,
        urls: Optional[Iterable[str]] = None,
        now: Optional[datetime] = None,
        staged: Optional[dict[tuple[str, str, str], tuple[Cookie, Optional[datetime]]]] = None,
        repush_all: bool = False,
    ) -> None:
        if target_client is None:
            return
        now = now or datetime.now(timezone.utc)
        active_staged = staged if staged is not None else self._pending_staged(now, target_client, name=name)
        remove_urls = set(urls) if urls is not None else set(self.client_urls(name=name))
        remove_hosts = {urlsplit(url).hostname or "" for url in remove_urls}

        def _touches_host(cookie_domain: Optional[str]) -> bool:
            bare = (cookie_domain or "localhost").lstrip(".").strip("[]").lower()
            return repush_all or any(_rnet_host_matches(host, bare, include_subdomains=True) for host in remove_hosts)

        for url in remove_urls:
            try:
                target_client.remove_cookie(url, name)
            except Exception:
                continue
        for jar in (self._store, self._received):
            for key, cookie in jar.items():
                if cookie.name == name and key not in active_staged and _touches_host(cookie.domain):
                    self._push_cookie(cookie, key, now, target_client)

        for fresh, deadline in active_staged.values():
            if fresh.name == name and (deadline is None or deadline > now) and _touches_host(fresh.domain):
                remaining = deadline - now if deadline is not None else None
                target_client.set_cookie(self.client_url(fresh), self._wire_cookie(fresh, remaining))

    def absorb(
        self,
        response: Any,
        request_client: Optional[rnet.BlockingClient] = None,
        req_gen: Optional[int] = None,
        resp_seq: Optional[int] = None,
        received_at: Optional[datetime] = None,
    ) -> None:
        """Mirror Set-Cookie at its exact scope after rnet has updated the wire jar."""
        with self._lock:
            server_cookies = response.cookies
            if not server_cookies:
                return
            parsed = urlparse(response.url)
            host = parsed.hostname or ""
            default_path = (parsed.path[: parsed.path.rfind("/")] or "/") if parsed.path.startswith("/") else "/"
            now = datetime.now(timezone.utc)
            for server_cookie in server_cookies:
                row = self._parse_server_cookie(server_cookie, host, default_path, received_at or now, now)
                if row is None:
                    continue
                key, fresh, deadline = row
                path = fresh.path or "/"
                safe_path = path == "/" or self._is_safe_url_path(path)
                probe_url = self.client_url(fresh) + (path if path != "/" else "")
                extra = {probe_url} if safe_path else set()
                rebuild_subdomains = path == "/" and bool(fresh.domain and fresh.domain.startswith("."))
                live_urls = (
                    set(self.client_urls(domain=fresh.domain, name=fresh.name, path=path, include_subdomains=False))
                    | extra
                )
                rebuild_urls = (
                    set(
                        self.client_urls(
                            domain=fresh.domain, name=fresh.name, path=path, include_subdomains=rebuild_subdomains
                        )
                    )
                    | extra
                )
                if resp_seq is not None and self._superseded(resp_seq, key, fresh):
                    if self._client is not None:
                        self._reconcile_name_on_client(
                            self._client,
                            fresh.name,
                            rebuild_urls
                            if request_client is not None and request_client is not self._client
                            else live_urls,
                            now,
                        )
                    continue
                if (
                    req_gen is not None
                    and request_client is not None
                    and self._client is not None
                    and request_client is not self._client
                    and self._slot_gen.get(key, -1) > req_gen
                ):
                    continue
                if request_client is not None and safe_path:
                    raw = request_client.get_cookies(probe_url) or b""
                    slot_vals = [
                        v
                        for n, v in RnetSession.parse_cookie_header(raw.decode("utf-8", errors="replace"))
                        if n == fresh.name
                    ]
                    for jar in (self._store, self._received):
                        for other_key, other in jar.items():
                            other_path = other.path or "/"
                            if (
                                other_key != key
                                and other.name == fresh.name
                                and other.domain
                                and (
                                    other_key[0] == key[0]
                                    or (other.domain.startswith(".") and key[0].endswith("." + other_key[0]))
                                )
                                and (path == other_path or path.startswith(other_path.rstrip("/") + "/"))
                                and other.value in slot_vals
                            ):
                                slot_vals.remove(other.value)
                    if deadline is None or deadline > now:
                        if fresh.value not in slot_vals:
                            continue
                    else:
                        cur = self._store.get(key) or self._received.get(key)
                        if cur is not None and (cur.value or "") in slot_vals:
                            continue
                self._slot_seq[key] = resp_seq if resp_seq is not None else self._next_seq()
                self._slot_gen[key] = (
                    req_gen
                    if req_gen is not None
                    else (self._session._published_gen if self._session is not None else 0)
                )
                self._record_touch(fresh.name, domain=fresh.domain, path=path, include_subdomains=rebuild_subdomains)
                if deadline is not None and deadline <= now:
                    self._discard(key)
                    if self._client is not None and request_client is not self._client:
                        self._reconcile_name_on_client(self._client, fresh.name, rebuild_urls, now)
                    continue
                jar = self._store if key in self._store else self._received
                jar.pop(key, None)
                jar[key] = fresh
                if deadline is None:
                    self._expiry.pop(key, None)
                else:
                    self._expiry[key] = deadline
                if self._client is not None and request_client is not self._client:
                    self._reconcile_name_on_client(self._client, fresh.name, rebuild_urls, now)

    def persistable_jar(self) -> CookieJar:
        """Export stored and received cookies with their original scopes."""
        with self._lock:
            self._prune_expired()
            jar = CookieJar()
            for key, cookie in list(self._store.items()):
                if cookie.name and cookie.domain and (key in self._from_jar or key[0] != "localhost"):
                    jar.set_cookie(cookie)
            for key, cookie in list(self._received.items()):
                if key not in self._store:
                    jar.set_cookie(cookie)
            return jar

    @property
    def jar(self) -> CookieJar:
        """Return a CookieJar of the cookies that arrived as a CookieJar (requests compat).

        ``save_cookies`` in dl.py uses this to write cookies back to disk, so it carries a value
        the server rotated for one of those cookies but not the cookies set by name.
        """
        with self._lock:
            self._prune_expired()
            jar = CookieJar()
            for key, cookie in list(self._store.items()):
                if key in self._from_jar:
                    jar.set_cookie(cookie)
            return jar

    def update(self, other: Any = None, /, **kwargs: Any) -> None:
        if other is None:
            other = {}
        if isinstance(other, (CookieJar, list)):
            for cookie in other:
                self.add(cookie, from_jar=True)
        elif hasattr(other, "items"):
            for name, value in other.items():
                self.add(create_cookie(name, str(value)))
        for name, value in kwargs.items():
            self.add(create_cookie(name, str(value)))

    def get(  # type: ignore[override]
        self, name: str, default: Optional[str] = None, domain: Optional[str] = None, path: Optional[str] = None
    ) -> Optional[str]:
        """The latest value of *name*."""
        for cookie in reversed(self.snapshot()):
            if cookie.name == name and domain in (None, cookie.domain) and path in (None, cookie.path):
                return cookie.value
        return default

    def set(self, name: str, value: str, domain: str = "localhost", path: str = "/", **kwargs: Any) -> None:
        self.add(create_cookie(name, value, domain=domain, path=path, **kwargs))

    def flat(self) -> dict[str, str]:
        """Each cookie name with its latest value."""
        return {cookie.name: cookie.value or "" for cookie in self.snapshot()}

    def __getitem__(self, name: str) -> str:
        return self.flat()[name]

    def __setitem__(self, name: str, value: str) -> None:
        self.set(name, value)

    def __delitem__(self, name: str) -> None:
        self.clear(name=name)

    def __contains__(self, name: object) -> bool:
        return any(cookie.name == name for cookie in self.snapshot())

    def __iter__(self) -> Iterator:
        return iter(self.flat())

    def __len__(self) -> int:
        return len(self.flat())

    def __bool__(self) -> bool:
        return bool(self._store)

    def get_dict(self, domain: Optional[str] = None, path: Optional[str] = None) -> dict[str, str]:
        """Return cookies as a plain dict (requests RequestsCookieJar compat), filtered by exact domain and path."""
        return {c.name: c.value or "" for c in self.snapshot() if domain in (None, c.domain) and path in (None, c.path)}

    def clear(self, domain: Optional[str] = None, path: Optional[str] = None, name: Optional[str] = None) -> None:
        """Remove cookies (requests RequestsCookieJar compat).

        - ``clear()`` removes all cookies.
        - ``clear(domain=..., path=..., name=...)`` removes the cookies that match every given filter.
        """
        with self._lock:
            if domain is None and path is None and name is None:
                self._clear_all_seq = self._next_seq()
                self._filter_clears.clear()
                self._slot_seq.clear()
                for journal in self._active_rebuilds.values():
                    journal.append(("clear_all",))
                for key in (*self._received, *self._store):
                    if self._session is not None:
                        self._slot_gen[key] = self._session._published_gen
                    self._discard(key)
                self._expiry.clear()
                self._received.clear()
                self._store.clear()
                self._from_jar.clear()
                if self._client is not None:
                    self._client.clear_cookies()
                return

            def hit(cookie: Cookie) -> bool:
                return domain in (None, cookie.domain) and path in (None, cookie.path) and name in (None, cookie.name)

            now = datetime.now(timezone.utc)
            self._prune_expired(now)
            pending = self._pending_cookies(now)
            names = (
                {name}
                if name is not None
                else {
                    c.name
                    for c in (*self._store.values(), *self._received.values(), *(row[4] for row in pending))
                    if hit(c)
                }
            )
            clear_seq = self._next_seq()
            self._filter_clears.append((clear_seq, domain, path, name))
            rebuild_subdomains = path in (None, "/") and bool(domain and domain.startswith("."))
            for each in names:
                self._record_touch(each, domain=domain, path=path, include_subdomains=rebuild_subdomains)
            urls = {each: self.client_urls(domain=domain, name=each, path=path) for each in names}
            for jar in (self._store, self._received):
                for key, cookie in list(jar.items()):
                    if hit(cookie):
                        self._slot_seq[key] = clear_seq
                        if self._session is not None:
                            self._slot_gen[key] = self._session._published_gen
                        self._discard(key)
            for seq, _, _, key, fresh, _ in pending:
                if seq < clear_seq and hit(fresh):
                    self._slot_seq[key] = max(self._slot_seq.get(key, 0), clear_seq)
                    if self._session is not None:
                        self._slot_gen[key] = self._session._published_gen
            for each in names:
                self._reconcile_name_on_client(self._client, each, urls[each], now)

    def _record_touch(
        self, name: str, domain: Optional[str] = None, path: Optional[str] = None, include_subdomains: bool = False
    ) -> None:
        if self._active_rebuilds:
            urls = set(self.client_urls(domain=domain, name=name, path=path, include_subdomains=include_subdomains))
            for journal in self._active_rebuilds.values():
                journal.append(("touch", name, urls))

    def finish_rebuild(self, client: rnet.BlockingClient, journal: list[tuple[Any, ...]]) -> None:
        with self._lock:
            now = datetime.now(timezone.utc)
            touched: dict[str, set[str]] = {}
            had_clear_all = any(op[0] == "clear_all" for op in journal)
            if had_clear_all:
                client.clear_cookies()
                touched.update((c.name, set()) for jar in (self._store, self._received) for c in jar.values())
            for op in journal:
                if op[0] == "touch":
                    touched.setdefault(op[1], set()).update(op[2])
            staged = self._pending_staged(now, client)
            for _, _, _, _, fresh, _ in self._pending_cookies(now):
                fpath = fresh.path or "/"
                touched.setdefault(fresh.name, set()).update(
                    self.client_urls(
                        domain=fresh.domain,
                        name=fresh.name,
                        path=fpath,
                        include_subdomains=fpath == "/" and bool(fresh.domain and fresh.domain.startswith(".")),
                    )
                )
            for name, urls in touched.items():
                self._reconcile_name_on_client(client, name, urls, now, staged, repush_all=had_clear_all)

    def items(self) -> list[tuple[str, str]]:  # type: ignore[override]
        return list(self.flat().items())

    def keys(self) -> list[str]:  # type: ignore[override]
        return list(self.flat().keys())

    def values(self) -> list[str]:  # type: ignore[override]
        return list(self.flat().values())


class RnetProxyDict(dict):
    """Dict-like proxy config that syncs to the rnet client.

    Accepts ``{"all": url}``, ``{"https": url}``, or ``{"http": url}``
    and applies through rnet's native ``proxies`` parameter (``List[rnet.Proxy]``).
    Supports both lazy (pre-client) and live (post-client) proxy updates.
    """

    def __init__(self, session: "RnetSession") -> None:
        super().__init__()
        self._session = session

    def sync(self) -> None:
        proxy = self.get("all") or self.get("https") or self.get("http")
        proxies = [rnet.Proxy.all(proxy)] if proxy else []
        self._session._client_kwargs["proxies"] = proxies or None
        if self._session._client is not None:
            self._session._client.update(proxies=proxies or None)

    def update(self, __m: Any = None, **kwargs: Any) -> None:
        super().update(__m or {}, **kwargs)
        self.sync()

    def __setitem__(self, key: str, value: str) -> None:
        super().__setitem__(key, value)
        self.sync()


class MaxRetriesError(Exception):
    def __init__(self, message: str, cause: Optional[Exception] = None) -> None:
        super().__init__(message)
        self.__cause__ = cause


# the innermost io error text in rnet's wreq::Error debug form, e.g. "stream closed because of a broken pipe"
RNET_ERROR_TEXT_RE = re.compile(r'error: "([^"]+)"')


def failure_response(exc: BaseException) -> Any:
    """The HTTP response of a status failure, or None.

    RnetSession wraps a forcelist HTTPError in MaxRetriesError as ``__cause__``, so this unwraps one level.
    """
    response = getattr(exc, "response", None)
    return response if response is not None else getattr(exc.__cause__, "response", None)


def failure_reason(exc: BaseException) -> str:
    """Name a request failure without its URL, which can carry signed tokens.

    Gives the HTTP status of a status failure, else the exception class and, for an rnet error,
    its innermost error text.
    """
    inner = exc.__cause__ or exc
    response = failure_response(exc)
    status = getattr(response, "status_code", None)
    if isinstance(status, int):
        return f"{status} {getattr(response, 'reason', '') or ''}".strip()
    texts = RNET_ERROR_TEXT_RE.findall(str(inner))
    return f"{type(inner).__name__} ({texts[-1]})" if texts else type(inner).__name__


class RnetSession:
    """TLS-fingerprinted HTTP session powered by rnet (Rust/BoringSSL).

    Drop-in replacement for CurlSession with requests-compatible API.
    Supports browser impersonation (Chrome, Firefox, Edge, Safari, OkHttp),
    retry with exponential backoff, cookie persistence, and proxies.

    unshackle makes the client lazily on the first request, so you can
    configure headers, cookies, and proxies freely before it opens any
    connection.
    """

    def __init__(
        self,
        max_retries: int = MAX_RETRIES,
        backoff_factor: float = BACKOFF_FACTOR,
        max_backoff: float = MAX_BACKOFF,
        status_forcelist: Optional[list[int]] = None,
        allowed_methods: Optional[set[str]] = None,
        catch_exceptions: Optional[tuple[type[Exception], ...]] = None,
        **session_kwargs: Any,
    ) -> None:
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.max_backoff = max_backoff
        self.status_forcelist = status_forcelist or list(STATUS_FORCELIST)
        self.allowed_methods = allowed_methods or set(RETRY_METHODS)
        self.catch_exceptions = catch_exceptions or (
            rnet.ConnectionError,
            rnet.ConnectionResetError,  # sibling of ConnectionError; mid-request resets are retryable
            rnet.TimeoutError,
            rnet.RequestError,
        )
        self.log = logging.getLogger(self.__class__.__name__)

        client_kwargs: dict[str, Any] = {}
        for key in (
            "impersonate",
            "timeout",
            "connect_timeout",
            "read_timeout",
            "proxies",
            "verify",
            "referer",
            "allow_redirects",
            "max_redirects",
            "pool_idle_timeout",
            "pool_max_idle_per_host",
            "pool_max_size",
            "tcp_keepalive",
            "tcp_keepalive_interval",
            "tcp_keepalive_retries",
            "http1_only",
            "http2_only",
            "tcp_nodelay",
        ):
            if key in session_kwargs:
                client_kwargs[key] = session_kwargs.pop(key)
        proxy_url = session_kwargs.pop("proxy", None)

        client_kwargs["cookie_store"] = True

        self.verify: bool = client_kwargs.pop("verify", True)
        if not self.verify:
            client_kwargs["danger_accept_invalid_certs"] = True

        self._client_kwargs = dict(client_kwargs)
        self._client: Optional[rnet.BlockingClient] = None
        self._published_gen = 0
        self._rebuild_gen = 0
        self._paths: set[str] = set()
        self._origins: set[str] = set()
        self._copy_urls: set[str] = set()

        self.headers = RnetSessionHeaders(self)
        self.cookies = RnetCookieAdapter(None, self)
        self.proxies = RnetProxyDict(self)
        self.proxy_exempt = False  # True: this HTTP session goes direct on purpose, so the proxy check skips it

        if "headers" in session_kwargs:
            self.headers.update(session_kwargs.pop("headers"))
        if "cookies" in session_kwargs:
            self.cookies.update(session_kwargs.pop("cookies"))
        if "proxies" in session_kwargs:
            self.proxies.update(session_kwargs.pop("proxies"))
        if proxy_url:
            self.proxies.update({"all": proxy_url})

    @property
    def impersonate_name(self) -> Optional[str]:
        """Preset name (e.g. 'Chrome131') for rebuilding this HTTP session in another process.

        rnet enums stringify as 'Impersonate.Chrome131'. Return the trailing name, or None
        when no preset was set (then the HTTP session is not cheaply rebuildable across
        processes).
        """
        preset = self._client_kwargs.get("impersonate")
        if preset is None:
            return None
        name = str(preset).rsplit(".", 1)[-1]
        return name or None

    def ensure_client(self) -> rnet.BlockingClient:
        """Lazily make the rnet client on first use, flushing any buffered state."""
        if self._client is None:
            client = rnet.BlockingClient(**self._client_kwargs)
            self.headers._client = client
            self.headers.sync()
            self.cookies._client = client
            self.cookies.flush_to_client()
            self._client = client
        return self._client

    def rebuild_client(self) -> None:
        """Replace the rnet client with one that carries only the current header set.

        rnet merges header updates and has no header removal, so a new client is the only
        way to drop a header the caller deleted. Do not pass the headers as default_headers:
        that replaces the impersonate header set instead of overlaying it, which breaks the
        fingerprint.

        A new client also starts with an empty cookie jar. This method replays the stored
        cookies, which hold any value the server rotated for them, then the root-path cookies
        of every origin this HTTP session has used. The new client
        goes on the HTTP session last, so a request from another thread keeps the old client
        until the new one holds the headers and the cookies.
        """
        with self.cookies._lock:
            old_client = self._client
            if old_client is None:
                return
            self._rebuild_gen += 1
            gen = self._rebuild_gen
            self.cookies._active_rebuilds[gen] = []
        try:
            client = rnet.BlockingClient(**self._client_kwargs)
            with self.cookies._lock:
                prev = getattr(self.cookies._tls, "rebuild_client", None)
                self.cookies._tls.rebuild_client = client
                try:
                    self.headers.sync(client)
                    self.cookies.flush_to_client()
                finally:
                    self.cookies._tls.rebuild_client = prev
            for origin in sorted(self._origins | self._copy_urls, key=lambda u: (len(urlsplit(u).path), u)):
                self.copy_cookies(old_client, client, origin)
            with self.cookies._lock:
                self.cookies._prune_expired()
                journal = self.cookies._active_rebuilds.pop(gen)
                if gen != self._rebuild_gen:
                    return
                self.cookies.finish_rebuild(client, journal)
                self.headers.sync(client)
                self.headers._client = client
                self.cookies._client = client
                self._published_gen = gen
                self._client = client
        finally:
            with self.cookies._lock:
                self.cookies._active_rebuilds.pop(gen, None)

    @staticmethod
    def parse_cookie_header(header: str) -> Iterator[tuple[str, str]]:
        """The ``(name, value)`` pairs of a ``name=value; ...`` header string."""
        for pair in header.split(";"):
            name, separator, value = pair.partition("=")
            if separator:
                yield name.strip(), value.strip()

    @staticmethod
    def set_cookie_header(client: rnet.BlockingClient, origin: str, header: str) -> None:
        """Set every cookie in a ``name=value; ...`` header string on one origin of *client*."""
        for name, value in RnetSession.parse_cookie_header(header):
            try:
                client.set_cookie(origin, rnet.Cookie(name, value))
            except Exception:
                pass

    @staticmethod
    def copy_cookies(source: rnet.BlockingClient, target: rnet.BlockingClient, origin: str) -> None:
        """Copy one origin's cookies between clients. rnet cannot list the whole cookie jar."""
        try:
            raw = source.get_cookies(origin)
            existing = target.get_cookies(origin) or b""
        except Exception:
            return
        if not raw:
            return
        satisfied = Counter(RnetSession.parse_cookie_header(existing.decode("utf-8", errors="replace")))
        for name, value in RnetSession.parse_cookie_header(raw.decode("utf-8", errors="replace")):
            if satisfied[name, value]:
                satisfied[name, value] -= 1
            else:
                try:
                    target.set_cookie(origin, rnet.Cookie(name, value))
                except Exception:
                    pass

    def export_origin_cookies(self) -> dict[str, str]:
        """Cookie headers the live client holds, one per origin this HTTP session has requested.

        The client also holds cookies from intermediate redirects. rnet
        cannot list the jar, so this covers the origins already requested and no others.
        """
        if self._client is None:
            return {}
        exported: dict[str, str] = {}
        for origin in list(self._origins):
            try:
                raw = self._client.get_cookies(origin)
            except Exception:
                continue
            if raw:
                exported[origin] = raw.decode("utf-8", errors="replace")
        return exported

    def scoped_cookies(self) -> CookieJar:
        """Every cookie this HTTP session sends, each scoped to its domain.

        The live client's root-path cookies of each requested origin come first, then the
        cookies stored in :attr:`cookies` with their own paths.
        """
        jar = CookieJar()
        hosts: dict[str, set[str]] = {}
        for origin, header in self.export_origin_cookies().items():
            host = urlparse(origin).hostname or ""
            for name, value in self.parse_cookie_header(header):
                jar.set_cookie(create_cookie(name, value, domain=host))
                hosts.setdefault(name, set()).add(host)
        for cookie in self.cookies.snapshot():
            bare = (cookie.domain or "").lstrip(".")
            live = any(h == bare or h.endswith("." + bare) for h in hosts.get(cookie.name, ()))
            if not (live and cookie.path in (None, "/")):
                jar.set_cookie(cookie)
        return jar

    @staticmethod
    @functools.lru_cache(maxsize=512)
    def _canonical_import_target(origin: str) -> Optional[tuple[str, str, str]]:
        """Choose a replay URL whose cookie default-path matches the imported cookie."""
        cleaned = origin.strip("".join(map(chr, range(33)))).translate(str.maketrans("", "", "\t\r\n"))
        scheme, separator, rest = cleaned.partition(":")
        scheme = scheme.lower()
        if not separator or scheme not in ("http", "https"):
            return None
        rest = rest.lstrip("/\\")
        cut = next((i for i, ch in enumerate(rest) if ch in "/\\?#"), len(rest))
        authority, tail = rest[:cut], rest[cut:]
        if not authority:
            return None
        try:
            parsed = urlsplit(f"{scheme}://{authority}")
            host = parsed.hostname
            if not host:
                return None
            host = RnetCookieAdapter._url_host(host)
            port = parsed.port
        except (ValueError, UnicodeError):
            return None
        base_origin = f"{scheme}://{host}"
        if port is not None and port != (443 if scheme == "https" else 80):
            base_origin += f":{port}"
        raw_path = tail.partition("?")[0].partition("#")[0].replace("\\", "/")
        parts = raw_path.split("/")[1:]
        segments: list[str] = []
        for index, segment in enumerate(parts):
            decoded = unquote(segment)
            if decoded in (".", ".."):
                if decoded == ".." and segments:
                    segments.pop()
                if index == len(parts) - 1:
                    segments.append("")
            else:
                segments.append(
                    "".join(
                        quote(ch, safe="") if ord(ch) <= 32 or ord(ch) >= 127 or ch in '"<>`{}' else ch
                        for ch in segment
                    )
                )
        with _PATH_PROBE_LOCK:
            _PATH_PROBE_CLIENT.clear_cookies()
            try:
                _PATH_PROBE_CLIENT.set_cookie(origin, rnet.Cookie("p", "1"))
                if _PATH_PROBE_CLIENT.get_cookies(origin) != b"p=1":
                    return None
                if _PATH_PROBE_CLIENT.get_cookies(base_origin + "/") == b"p=1":
                    return base_origin, "/", base_origin
                prefixes: set[str] = set()
                current = ""
                for segment in segments:
                    current += "/" + segment
                    prefixes.update((current, current + "/"))
                for candidate in sorted(prefixes, key=len):
                    if _PATH_PROBE_CLIENT.get_cookies(base_origin + candidate) == b"p=1":
                        return base_origin, candidate, f"{base_origin}{candidate}/"
            except Exception:
                return None
            finally:
                _PATH_PROBE_CLIENT.clear_cookies()
        return None

    def import_origin_cookies(self, exported: dict[str, str]) -> None:
        """Load cookie headers from :meth:`export_origin_cookies` into this HTTP session's client."""
        if not exported:
            return
        client = self.ensure_client()
        for origin, header in exported.items():
            self.set_cookie_header(client, origin, header)
            target = self._canonical_import_target(origin)
            if target is not None:
                base_origin, default_path, copy_url = target
                self._origins.add(base_origin)
                if copy_url != base_origin:
                    self._copy_urls.add(copy_url)
                self._record_paths(f"{base_origin}{default_path}")

    def build_url(self, url: str, params: Optional[Any] = None) -> str:
        """Encode params into the URL (rnet ignores the params kwarg).

        Accepts the same shapes as requests: a mapping, a sequence of pairs, or a
        pre-built query string/bytes. This method appends a string verbatim (already
        encoded). urlencode() would raise TypeError on it.
        """
        if not params:
            return url
        if isinstance(params, bytes):
            extra = params.decode("utf-8")
        elif isinstance(params, str):
            extra = params
        else:
            extra = urlencode(params, doseq=True)
        parsed = urlparse(url)
        separator = "&" if parsed.query else ""
        query = parsed.query + separator + extra if parsed.query else extra
        return urlunparse(parsed._replace(query=query))

    def get_sleep_time(self, response: Optional[RnetResponse], attempt: int) -> Optional[float]:
        if response:
            retry_after = response.headers.get("Retry-After")
            if retry_after:
                wait: Optional[float] = None
                try:
                    wait = float(retry_after)
                except ValueError:
                    try:
                        retry_date = parsedate_to_datetime(retry_after)
                        if retry_date.tzinfo is None:
                            retry_date = retry_date.replace(tzinfo=timezone.utc)
                        wait = (retry_date - datetime.now(timezone.utc)).total_seconds()
                    except Exception:
                        # parsedate_to_datetime itself raises ValueError on malformed dates
                        # (Python >= 3.10); an unusable header must not escape the retry loop
                        wait = None
                if wait is not None and math.isfinite(wait):
                    # a hostile Retry-After (e.g. 86400) would otherwise park the caller for a day
                    return min(wait, self.max_backoff)

        if attempt == 0:
            return 0.0

        backoff_value = self.backoff_factor * (2 ** (attempt - 1))
        jitter = backoff_value * 0.1
        sleep_time = backoff_value + random.uniform(-jitter, jitter)
        return min(sleep_time, self.max_backoff)

    def absorb_cookies(
        self,
        response: RnetResponse,
        request_client: Optional[rnet.BlockingClient] = None,
        req_gen: Optional[int] = None,
        resp_seq: Optional[int] = None,
        received_at: Optional[datetime] = None,
    ) -> RnetResponse:
        """Record a value the server set for a stored cookie; a cookie fault must never fail the request."""
        try:
            parsed = urlparse(response.url)
            if parsed.scheme and parsed.netloc:
                self._origins.add(f"{parsed.scheme}://{parsed.netloc}")
            self.cookies.absorb(response, request_client, req_gen, resp_seq, received_at=received_at)
        except Exception:  # nosec B110 - the store keeps its old value, the rnet jar still has the new one
            pass
        finally:
            with self.cookies._lock:
                if resp_seq is not None:
                    self.cookies._in_flight.pop(resp_seq, None)
        return response

    def _record_paths(self, url: str, server_cookies: Any = None) -> None:
        path = urlsplit(url).path
        while path and path != "/":
            if RnetCookieAdapter._is_safe_url_path(path):
                self._paths.add(path)
            path = path.rpartition("/")[0]
        self._paths.update(
            ck.path
            for ck in server_cookies or ()
            if ck.path and ck.path != "/" and RnetCookieAdapter._is_safe_url_path(ck.path)
        )

    def _request_once(
        self,
        client: rnet.BlockingClient,
        req_gen: int,
        rnet_method: rnet.Method,
        method_upper: str,
        url: str,
        **kwargs: Any,
    ) -> RnetResponse:
        raw_allow = kwargs.pop("allow_redirects", None)
        if raw_allow is None:
            raw_allow = self._client_kwargs.get("allow_redirects")
        allow_redirects = True if raw_allow is None else bool(raw_allow)
        raw_max = kwargs.pop("max_redirects", None)
        if raw_max is None:
            raw_max = self._client_kwargs.get("max_redirects")
        max_redirects = 10 if raw_max is None else raw_max
        auto_referer = (
            self._client_kwargs.get("referer") is not False
            and "referer" not in self.headers
            and not any(key.lower() == "referer" for key in (kwargs.get("headers") or {}))
        )
        if isinstance(kwargs.get("query"), Mapping):
            kwargs["query"] = list(kwargs["query"].items())
        hop = 0
        while True:
            current = urlsplit(url)
            if current.scheme and current.netloc:
                self._origins.add(f"{current.scheme}://{current.netloc}")
            self._record_paths(url)
            raw_response = client.request(rnet_method, url, allow_redirects=False, **kwargs)
            received_at = datetime.now(timezone.utc)
            resp_seq: Optional[int] = None
            try:
                raw_url = raw_response.url if raw_response is not None else None
                raw_cookies = list(raw_response.cookies or ()) if raw_response is not None else []
            except Exception:
                raw_url, raw_cookies = None, []
            if isinstance(raw_url, str):
                with self.cookies._lock:
                    resp_split = urlsplit(raw_url)
                    if resp_split.scheme and resp_split.netloc:
                        self._origins.add(f"{resp_split.scheme}://{resp_split.netloc}")
                    self._record_paths(raw_url, raw_cookies)
                    resp_seq = self.cookies.next_seq()
                    self.cookies._in_flight[resp_seq] = (
                        resp_seq,
                        req_gen,
                        client,
                        received_at,
                        raw_url,
                        raw_cookies,
                    )
            response = self.absorb_cookies(
                RnetResponse(raw_response), client, req_gen, resp_seq, received_at=received_at
            )
            if not allow_redirects or response.status_code not in (301, 302, 303, 307, 308):
                return response
            headers = getattr(response, "headers", None)
            location = None
            if isinstance(headers, (RnetResponseHeaders, CaseInsensitiveDict)):
                location = headers.get("location")
            elif headers is not None:
                location = next((v for k, v in headers.items() if k.lower() == "location"), None)
            if location is None:
                return response
            base_url = getattr(response, "url", None) or url
            try:
                next_url = _resolve_redirect_url(base_url, location)
                following = urlsplit(next_url)
                _ = following.port
                if following.scheme not in ("http", "https") or not following.hostname:
                    return response
                if hasattr(client, "get_cookies"):
                    client.get_cookies(next_url)
            except (ValueError, rnet.URLParseError, rnet.BuilderError):
                return response
            code = response.status_code
            body = kwargs.get("body")
            if code in (307, 308) and (
                kwargs.get("multipart") is not None
                or (body is not None and not isinstance(body, (str, bytes, bytearray, memoryview)))
            ):
                return response
            close = getattr(response, "close", None)
            if callable(close):
                close()
            if hop + 1 >= max_redirects:
                raise rnet.RedirectError(f"Exceeded {max_redirects} redirects")
            hop += 1
            kwargs.pop("query", None)
            drop_headers: set[str] = set()
            if code in (301, 302, 303):
                if method_upper != "HEAD":
                    method_upper, rnet_method = "GET", rnet.Method.GET
                for field in ("body", "form", "json", "multipart"):
                    kwargs.pop(field, None)
                drop_headers.update(_REDIRECT_BODY_HEADERS)
            actual_current = urlsplit(base_url)
            if not _same_origin(actual_current, following):
                drop_headers.update(_REDIRECT_CREDENTIAL_HEADERS)
                for field in ("auth", "bearer_auth", "basic_auth", "cookies"):
                    kwargs.pop(field, None)
            if auto_referer:
                drop_headers.add("referer")
            hop_headers = {k: v for k, v in (kwargs.get("headers") or {}).items() if k.lower() not in drop_headers}
            if auto_referer:
                # rnet removes userinfo from its response URL.
                if (
                    current.username is None
                    and current.password is None
                    and actual_current.username is None
                    and actual_current.password is None
                    and not (actual_current.scheme == "https" and following.scheme == "http")
                ):
                    _, qmark, raw_query = base_url.partition("#")[0].partition("?")
                    hop_headers["Referer"] = (
                        f"{actual_current.scheme}://{actual_current.netloc}{actual_current.path or '/'}{qmark}{raw_query}"
                    )
            kwargs["headers"] = hop_headers
            url = next_url

    def request(self, method: str, url: str, **kwargs: Any) -> RnetResponse:
        """Send a request, retrying on the status forcelist and on the caught exception types.

        This method retries only the methods in allowed_methods. Any other method gets one try.
        A max_retries kwarg overrides the HTTP session retry budget for this call alone, where 0
        means one try with no retries. Once the budget is spent, this method raises
        MaxRetriesError with the last failure as its cause.
        """
        with self.cookies._lock:
            client = self.ensure_client()
            req_gen = self._published_gen
        method_upper = method.upper() if isinstance(method, str) else str(method).upper()

        max_retries = kwargs.pop("max_retries", None)
        if max_retries is None:
            max_retries = self.max_retries

        url = self.build_url(url, kwargs.pop("params", None))

        parsed_origin = urlparse(url)
        if run_proxy.watched and not self.proxy_exempt and not self._client_kwargs.get("proxies"):
            try:
                run_proxy.check(parsed_origin.hostname, sys._getframe(1))
            except Exception:  # nosec B110 - the proxy check only warns, it must never fail a request
                pass
        if not self.verify:
            kwargs.setdefault("verify", False)

        # Remove kwargs rnet doesn't understand
        kwargs.pop("stream", None)  # rnet responses are always lazy

        data = kwargs.pop("data", None)
        if data is not None:
            if isinstance(data, dict):
                kwargs["form"] = list(data.items())
            elif isinstance(data, (str, bytes)):
                kwargs["body"] = data
            else:
                kwargs["body"] = data

        rnet_method = METHOD_MAP.get(method_upper)
        if rnet_method is None:
            raise ValueError(f"Unsupported HTTP method: {method}")

        # rnet merges client defaults back into each hop. Keep removable headers on the request.
        headers = CaseInsensitiveDict({k: v for k, v in self.headers.items() if k.lower() in _REDIRECT_HEADERS})
        headers.update(kwargs.get("headers") or {})
        if headers or kwargs.get("headers") is not None:
            kwargs["headers"] = dict(headers)

        if method_upper not in self.allowed_methods:
            return self._request_once(client, req_gen, rnet_method, method_upper, url, **kwargs)

        last_exception: Optional[Exception] = None
        response: Optional[RnetResponse] = None

        for attempt in range(max_retries + 1):
            try:
                response = self._request_once(client, req_gen, rnet_method, method_upper, url, **kwargs)

                if config.debug_requests:
                    parsed_url = urlparse(url)
                    port_str = f":{parsed_url.port}" if parsed_url.port else ""
                    if not port_str:
                        port_str = ":443" if parsed_url.scheme == "https" else ":80"
                    host_url = f"{parsed_url.scheme}://{parsed_url.hostname}{port_str}"
                    path_and_query = parsed_url.path + (f"?{parsed_url.query}" if parsed_url.query else "")
                    if not path_and_query:
                        path_and_query = "/"
                    content_length = response.headers.get("content-length") or response.content_length

                    log_msg = f'{host_url} "{method_upper} {path_and_query} {response.version}" {response.status_code} {content_length}'
                    self.log.debug(log_msg)

                if response.status_code not in self.status_forcelist:
                    return response
                last_exception = HTTPError(
                    f"Received status code: {response.status_code}",
                    response=response,  # type: ignore[arg-type]
                )
                failure = failure_reason(last_exception)

            except self.catch_exceptions as e:
                last_exception = e
                response = None
                failure = failure_reason(e)

            if attempt < max_retries:
                self.log.warning(f"{failure}({urlparse(url).path}). Retrying... ({attempt + 1}/{max_retries})")
                if sleep_duration := self.get_sleep_time(response, attempt + 1):
                    if sleep_duration > 0:
                        time.sleep(sleep_duration)
            else:
                break

        attempts = f" after {max_retries + 1} attempts" if max_retries else ""
        raise MaxRetriesError(
            f"{method_upper} {parsed_origin.hostname} failed{attempts}: {failure}", cause=last_exception
        )

    def get(self, url: str, **kwargs: Any) -> RnetResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> RnetResponse:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> RnetResponse:
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> RnetResponse:
        return self.request("DELETE", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> RnetResponse:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> RnetResponse:
        return self.request("OPTIONS", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> RnetResponse:
        return self.request("PATCH", url, **kwargs)

    def prepare_request(self, req: Request) -> Request:
        """Compatibility shim for services using prepared requests."""
        # Merge session headers into request headers
        if req.headers:
            merged = dict(self.headers)
            merged.update(req.headers)
            req.headers = merged
        else:
            req.headers = dict(self.headers)
        return req

    def send(self, req: Request, **kwargs: Any) -> RnetResponse:
        """Compatibility shim for services using prepared requests."""
        method = req.method or "GET"
        url = req.url or ""

        send_kwargs: dict[str, Any] = {}
        if req.headers:
            send_kwargs["headers"] = dict(req.headers)
        if req.data:
            send_kwargs["data"] = req.data
        if req.json:
            send_kwargs["json"] = req.json

        send_kwargs.update(kwargs)
        return self.request(method, url, **send_kwargs)

    def mount(self, prefix: str, adapter: Any) -> None:
        """No-op. rnet does TLS and connection pooling natively."""
        pass

    def close(self) -> None:
        """No-op. rnet manages its own resources."""
        pass


AnySession = Union[Session, RnetSession]


def session(
    browser: Optional[str] = None,
    **kwargs: Any,
) -> RnetSession:
    """
    Make an rnet HTTP session with TLS fingerprinting (browser/app impersonation).

    Args:
        browser: Exact rnet.Impersonate preset name. Examples:
                 "Chrome131", "OkHttp4_12", "Edge101", "Firefox135",
                 "Safari18", "OkHttp5", "Opera118"
                 Uses the configured default from config if not specified.
                 See rnet.Impersonate for all available presets.
        **kwargs: Additional arguments passed to RnetSession constructor.

    Returns:
        RnetSession configured with browser impersonation and retry behaviour.

    Examples:
        session()                               # Default browser from config
        session("OkHttp4_12")                   # OkHttp 4.12 fingerprint
        session("Chrome131")                    # Chrome 131
        session("Edge101", max_retries=3)       # Edge 101 with custom retry
    """
    if browser is None:
        browser = config.network.get("browser", "Chrome131")

    impersonate = resolve_impersonate(browser)

    session_kwargs: dict[str, Any] = {"impersonate": impersonate}
    # optional rnet client knobs, see docs/NETWORK_CONFIG.md
    for key in (
        "http1_only",
        "http2_only",
        "pool_max_idle_per_host",
        "pool_max_size",
        "tcp_nodelay",
        "connect_timeout",
        "read_timeout",
        "timeout",
        "pool_idle_timeout",
        "tcp_keepalive",
        "tcp_keepalive_interval",
        "tcp_keepalive_retries",
        "allow_redirects",
    ):
        if key in config.network:
            session_kwargs[key] = config.network[key]
    session_kwargs.update(kwargs)

    # Connection-pool / timeout defaults applied only when neither config.network nor the caller set them.
    # connect_timeout + read_timeout mirror the requests-path default timeout (CONNECT_TIMEOUT, READ_TIMEOUT)
    # so an unset config still gets a bounded connect and read like requests; pool_idle_timeout stays under
    # the typical ~60s CDN idle kill; pool_max_idle_per_host follows POOL_MAX_SIZE, sized above the worker
    # cap because hedge racers and tail-boost parts push in-flight requests past it; tcp_keepalive keeps
    # long idle segments warm.
    session_kwargs.setdefault("connect_timeout", CONNECT_TIMEOUT)
    session_kwargs.setdefault("read_timeout", READ_TIMEOUT)
    session_kwargs.setdefault("pool_idle_timeout", 55)
    session_kwargs.setdefault("pool_max_idle_per_host", POOL_MAX_SIZE)
    session_kwargs.setdefault("tcp_keepalive", 30)

    session_obj = RnetSession(**session_kwargs)
    session_obj.headers.update(config.headers)
    return session_obj
