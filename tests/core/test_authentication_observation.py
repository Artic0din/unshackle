"""Tests for the redacted authentication-observation contract."""

from __future__ import annotations

import pytest

from unshackle.core import console
from unshackle.core.api.input_bridge import InputBridge
from unshackle.core.authentication import (
    AuthenticationFailure,
    AuthenticationObservation,
    AuthenticationState,
)
from unshackle.core.service import Service

pytestmark = pytest.mark.unit


def test_ready_observation_round_trips_supported_methods() -> None:
    observation = AuthenticationObservation(
        state=AuthenticationState.READY,
        available_methods=("pairing", "cookies", "credentials"),
    )

    payload = observation.to_dict()

    assert payload == {
        "state": "ready",
        "available_methods": ["pairing", "cookies", "credentials"],
    }
    assert AuthenticationObservation.from_dict(payload) == observation


def test_fallback_records_only_methods_and_a_classified_reason() -> None:
    observation = AuthenticationObservation(
        state=AuthenticationState.FALLBACK,
        method="pairing",
        next_method="cookies",
        failure=AuthenticationFailure.AUTHENTICATION_REJECTED,
    )

    assert observation.to_dict() == {
        "state": "fallback",
        "method": "pairing",
        "next_method": "cookies",
        "failure": "authentication_rejected",
    }


@pytest.mark.parametrize(
    "payload",
    [
        {"state": "error", "failure": "network", "message": "private material"},
        {"state": "ready", "available_methods": ["password"]},
        {"state": "fallback", "method": "pairing", "next_method": "pairing", "failure": "network"},
        {"state": "error"},
    ],
)
def test_unstructured_or_invalid_observations_are_rejected(payload: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="authentication observation"):
        AuthenticationObservation.from_dict(payload)


def test_failure_classifications_stay_distinct() -> None:
    assert {failure.value for failure in AuthenticationFailure} == {
        "authentication_rejected",
        "entitlement",
        "region",
        "concurrency",
        "network",
        "manifest",
        "drm",
        "licence",
        "application",
    }


def test_only_terminal_states_are_retained_as_final_observations() -> None:
    waiting = AuthenticationObservation(AuthenticationState.WAITING, method="pairing")
    authenticated = AuthenticationObservation(AuthenticationState.AUTHENTICATED, method="pairing")

    assert waiting.is_terminal is False
    assert authenticated.is_terminal is True


def test_service_routes_observation_to_its_remote_session() -> None:
    bridge = InputBridge()
    service = type("ObservedService", (), {"_input_bridge": bridge})()
    observation = AuthenticationObservation(AuthenticationState.REPAIRING, method="pairing")

    Service.observe_authentication(service, observation)

    assert bridge.get_authentication_observation() == observation


def test_service_routes_observation_to_the_active_local_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    observed = []
    monkeypatch.setattr(console, "_authentication_handler", observed.append)
    service = type("ObservedService", (), {"_input_bridge": None})()
    observation = AuthenticationObservation(AuthenticationState.SESSION_PRESENT, method="cookies")

    Service.observe_authentication(service, observation)

    assert observed == [observation]
