from datetime import datetime, timezone

import pytest

from unshackle.core.approval import ApprovalNotice, format_approval_expiry
from unshackle.core.utils.redact import REDACTED, redact_secrets


def test_notice_round_trip() -> None:
    payload = dict(
        message="Pair", url="HTTPS://TV.Example/pair?user_code=AB", code=" AB ", expires_at="2030-01-02T12:00:00+02:00"
    )
    notice = ApprovalNotice.from_dict(payload)
    assert notice.to_dict() == dict(
        message="Pair", url="https://tv.example/pair?user_code=AB", code="AB", expires_at="2030-01-02T10:00:00Z"
    )
    assert ApprovalNotice.from_dict(notice.to_dict()) == notice
    assert repr(notice) == "ApprovalNotice(<redacted>)"
    assert ApprovalNotice("Pair").to_dict() == {"message": "Pair"}
    assert format_approval_expiry(datetime(2030, 1, 1, tzinfo=timezone.utc)) == "2030-01-01T00:00:00Z"


@pytest.mark.parametrize(
    "field,value",
    [
        ("message", "  "),
        ("message", "a\x85b"),
        ("message", "a" * 2049),
        *[
            ("url", url)
            for url in (
                "http://tv.example",
                "https://127.1",
                "https://tv.local",
                "https://host.example.",
                "https://u@tv.example",
                "https://tv.example:0",
                "https://tv.example/#device_code=x",
                "https://tv.example/?access_token=x",
                "https://tv.example/ a",
                "https://0x7f000001",
            )
        ],
        ("code", "\tAB"),
        ("code", "AB\u00a0"),
        ("code", "a" * 129),
        ("expires_at", False),
        ("expires_at", "2030-01-01"),
        ("expires_at", datetime(2030, 1, 1)),
    ],
)
def test_invalid_notice(field: str, value: object) -> None:
    with pytest.raises(ValueError, match=f"^Invalid approval {field}$"):
        ApprovalNotice.from_dict({"message": "Pair", field: value})


def test_unknown_keys_rejected() -> None:
    with pytest.raises(ValueError, match="^Invalid approval payload$"):
        ApprovalNotice.from_dict({"message": "Pair", "extra": True})


@pytest.mark.parametrize("value", [datetime(2030, 1, 1), True, 42, "0001-01-01T00:00:00+01:00"])
def test_expiry_errors_are_redacted(value: object) -> None:
    with pytest.raises(ValueError, match="^Invalid approval expires_at$"):
        format_approval_expiry(value)  # type: ignore[arg-type]  # Exercise invalid runtime inputs.


@pytest.mark.parametrize(
    "suffix",
    [
        "#?auth=secret",
        "#/pair?auth=secret",
        "#?authorization=Bearer123",
        "?a=1;device_code=secret",
        "?a=1;token=secret",
        "#/pair?%61uth=secret",
    ],
)
def test_rejects_private_approval_parameters(suffix: str) -> None:
    with pytest.raises(ValueError, match="^Invalid approval url$"):
        ApprovalNotice("Pair", url="https://tv.example/" + suffix)


@pytest.mark.parametrize("query", ["user_code=ABCD-1234", "code=XYZ"])
def test_preserves_public_pairing_parameters(query: str) -> None:
    url = "https://tv.example/?" + query
    assert ApprovalNotice("Pair", url=url).url == url


@pytest.mark.parametrize("offset", ["+00:99", "+24:00"])
def test_invalid_offset(offset: str) -> None:
    with pytest.raises(ValueError, match="^Invalid approval expires_at$"):
        format_approval_expiry("2030-01-01T00:00:00" + offset)


@pytest.mark.parametrize("key", ["device_code", "device_secret", "authorization"])
def test_device_error_redaction(key: str) -> None:

    assert redact_secrets(f"failure {key}=Bearer123;suffix") == f"failure {key}={REDACTED}"
    assert redact_secrets("failure password=abc;def") == f"failure password={REDACTED}"
    assert (
        redact_secrets(f"https://tv.example/?{key}=Bearer123;next=public")
        == f"https://tv.example/?{key}={REDACTED};next=public"
    )
    url = "https://tv.example/?a=1;"
    assert redact_secrets(f"{url}{key}=Bearer123") == f"{url}{key}={REDACTED}"


@pytest.mark.parametrize("url", ["socks5://host/?token=", "see //tv.example/?token=", "/pair?device_code="])
def test_url_redaction_preserves_delimiter(url: str) -> None:
    assert redact_secrets(url + "secret;next=public") == url + "***;next=public"


def test_url_userinfo_and_free_text_redaction() -> None:
    assert (
        redact_secrets("socks5://user:pass@host/?token=secret;next=public")
        == "socks5://***@host/?token=***;next=public"
    )
    for value in ("abc;def", "https://host;tail"):
        assert redact_secrets("password=" + value) == "password=***"
