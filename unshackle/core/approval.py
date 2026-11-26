"""Transient device-approval payloads."""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Optional, Union
from urllib.parse import unquote_plus, urlsplit, urlunsplit

ALLOWED_APPROVAL_KEYS = frozenset({"message", "url", "code", "expires_at"})
MAX_APPROVAL_MESSAGE_LENGTH = 2048
MAX_APPROVAL_URL_LENGTH = 2048
MAX_APPROVAL_CODE_LENGTH = 128
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_PRIVATE_DOMAINS = {
    "localhost",
    "local",
    "localdomain",
    "internal",
    "arpa",
    "lan",
    "home",
    "corp",
    "intranet",
    "private",
    "invalid",
}
_SECRET_PARAM = re.compile(
    r"^auth$|^authorization$|device[_-]?(?:code|id|secret)|client[_-]?secret|password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|cookie|session[_-]?id",
    re.I,
)
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:[Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)")


def format_approval_expiry(value: Optional[Union[str, datetime]]) -> Optional[str]:
    if value is None:
        return None
    try:
        if isinstance(value, str) and _TIMESTAMP.fullmatch(value):
            value = datetime.fromisoformat(value.upper().replace("Z", "+00:00"))
        if isinstance(value, datetime) and value.utcoffset() is not None:
            return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, ValueError):
        pass
    raise ValueError("Invalid approval expires_at")


def _control(char: str) -> bool:
    return ord(char) < 32 or 127 <= ord(char) <= 159


def _approval_url(url: str) -> str:
    error = "Invalid approval url"
    if not isinstance(url, str) or not 1 <= len(url) <= MAX_APPROVAL_URL_LENGTH or "\\" in url:
        raise ValueError(error)
    if any(_control(char) or char.isspace() for char in url):
        raise ValueError(error)
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        raise ValueError(error) from None
    labels = host.split(".")
    if (
        parts.scheme != "https"
        or any(c in parts.netloc for c in "@%[]")
        or port == 0
        or parts.netloc.endswith(":")
        or len(host) > 253
        or len(labels) < 2
        or labels[-1] in _PRIVATE_DOMAINS
        or labels[-1].isdigit()
        or not all(_HOST_LABEL.fullmatch(label) for label in labels)
    ):
        raise ValueError(error)
    try:
        socket.inet_aton(host)
    except OSError:
        pass
    else:
        raise ValueError(error)
    chunks = [parts.query]
    if "=" in parts.fragment:
        chunks.append(parts.fragment)
    if "?" in parts.fragment:
        chunks.append(parts.fragment.partition("?")[2])
    for chunk in chunks:
        for segment in re.split(r"[&;]", chunk):
            if _SECRET_PARAM.search(unquote_plus(segment.partition("=")[0])):
                raise ValueError(error)
    return urlunsplit(("https", f"{host}:{port}" if port else host, parts.path, parts.query, parts.fragment))


@dataclass(frozen=True)
class ApprovalNotice:
    """A device-approval message that must not enter durable logs."""

    message: str
    url: Optional[str] = None
    code: Optional[str] = None
    expires_at: Optional[str] = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.message, str)
            or len(self.message) > MAX_APPROVAL_MESSAGE_LENGTH
            or not self.message.strip()
            or any(_control(c) and c != "\n" for c in self.message)
        ):
            raise ValueError("Invalid approval message")
        if self.url is not None:
            object.__setattr__(self, "url", _approval_url(self.url))
        if self.code is not None:
            if (
                not isinstance(self.code, str)
                or any(_control(c) or (c.isspace() and c != " ") for c in self.code)
                or not 1 <= len(self.code.strip()) <= MAX_APPROVAL_CODE_LENGTH
            ):
                raise ValueError("Invalid approval code")
            object.__setattr__(self, "code", self.code.strip())
        if self.expires_at is not None:
            if not isinstance(self.expires_at, str):
                raise ValueError("Invalid approval expires_at")
            object.__setattr__(self, "expires_at", format_approval_expiry(self.expires_at))

    def __repr__(self) -> str:
        return "ApprovalNotice(<redacted>)"

    def to_dict(self) -> dict[str, str]:
        return {key: value for key, value in vars(self).items() if key in ALLOWED_APPROVAL_KEYS and value is not None}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ApprovalNotice:
        if not isinstance(value, Mapping) or set(value) - ALLOWED_APPROVAL_KEYS:
            raise ValueError("Invalid approval payload")
        if "message" not in value:
            raise ValueError("Invalid approval message")
        return cls(**value)
