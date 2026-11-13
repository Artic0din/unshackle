"""Redacted authentication-lifecycle observations."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Literal, Mapping, Optional, get_args

AuthMethod = Literal["cookies", "credentials", "pairing"]
AUTH_METHODS = frozenset(get_args(AuthMethod))


class AuthenticationState(str, Enum):
    """A provider authentication lifecycle state safe to expose to clients."""

    READY = "ready"
    SESSION_PRESENT = "session_present"
    SESSION_EXPIRED = "session_expired"
    SESSION_REJECTED = "session_rejected"
    RENEWING = "renewing"
    REPAIRING = "repairing"
    FALLBACK = "fallback"
    WAITING = "waiting"
    AUTHENTICATED = "authenticated"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    ERROR = "error"


class AuthenticationFailure(str, Enum):
    """Coarse failure classes that never contain provider error text."""

    AUTHENTICATION_REJECTED = "authentication_rejected"
    ENTITLEMENT = "entitlement"
    REGION = "region"
    CONCURRENCY = "concurrency"
    NETWORK = "network"
    MANIFEST = "manifest"
    DRM = "drm"
    LICENCE = "licence"
    APPLICATION = "application"


TERMINAL_AUTHENTICATION_STATES = frozenset(
    {
        AuthenticationState.AUTHENTICATED,
        AuthenticationState.TIMED_OUT,
        AuthenticationState.CANCELLED,
        AuthenticationState.ERROR,
    }
)


@dataclass(frozen=True)
class AuthenticationObservation:
    """A structured lifecycle snapshot with no free-text or secret-bearing fields."""

    state: AuthenticationState
    method: Optional[AuthMethod] = None
    available_methods: tuple[AuthMethod, ...] = ()
    next_method: Optional[AuthMethod] = None
    failure: Optional[AuthenticationFailure] = None

    def __post_init__(self) -> None:
        def valid_method(method: Optional[str]) -> bool:
            return method is None or method in AUTH_METHODS

        if not isinstance(self.state, AuthenticationState):
            raise ValueError("Invalid authentication observation")
        if not valid_method(self.method) or not valid_method(self.next_method):
            raise ValueError("Invalid authentication observation")
        if not isinstance(self.available_methods, tuple) or any(
            method not in AUTH_METHODS for method in self.available_methods
        ):
            raise ValueError("Invalid authentication observation")
        if len(set(self.available_methods)) != len(self.available_methods):
            raise ValueError("Invalid authentication observation")
        if self.failure is not None and not isinstance(self.failure, AuthenticationFailure):
            raise ValueError("Invalid authentication observation")

        if self.state is AuthenticationState.READY:
            if not self.available_methods or self.method or self.next_method or self.failure:
                raise ValueError("Invalid authentication observation")
        elif self.available_methods:
            raise ValueError("Invalid authentication observation")

        if self.state is AuthenticationState.FALLBACK:
            if not self.method or not self.next_method or self.method == self.next_method or self.failure is None:
                raise ValueError("Invalid authentication observation")
        elif self.next_method is not None:
            raise ValueError("Invalid authentication observation")

        if self.state is AuthenticationState.ERROR:
            if self.failure is None:
                raise ValueError("Invalid authentication observation")
        elif self.state is not AuthenticationState.FALLBACK and self.failure is not None:
            raise ValueError("Invalid authentication observation")

    @property
    def is_terminal(self) -> bool:
        return self.state in TERMINAL_AUTHENTICATION_STATES

    @property
    def active_method(self) -> Optional[AuthMethod]:
        return self.next_method or self.method

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"state": self.state.value}
        if self.method is not None:
            payload["method"] = self.method
        if self.available_methods:
            payload["available_methods"] = list(self.available_methods)
        if self.next_method is not None:
            payload["next_method"] = self.next_method
        if self.failure is not None:
            payload["failure"] = self.failure.value
        return payload

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> AuthenticationObservation:
        allowed = {"state", "method", "available_methods", "next_method", "failure"}
        try:
            if not isinstance(value, Mapping) or set(value) - allowed:
                raise ValueError
            raw_methods = value.get("available_methods", ())
            if not isinstance(raw_methods, (list, tuple)):
                raise ValueError
            methods = tuple(raw_methods)
            if any(not isinstance(method, str) for method in methods):
                raise ValueError
            raw_failure = value.get("failure")
            return cls(
                state=AuthenticationState(value["state"]),
                method=value.get("method"),
                available_methods=methods,
                next_method=value.get("next_method"),
                failure=AuthenticationFailure(raw_failure) if raw_failure is not None else None,
            )
        except (KeyError, TypeError, ValueError):
            raise ValueError("Invalid authentication observation") from None
