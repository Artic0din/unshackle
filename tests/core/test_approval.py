from datetime import datetime, timezone

import pytest

from unshackle.core.approval import ApprovalNotice, format_approval_expiry


def test_notice_round_trip():
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
def test_invalid_notice(field, value):
    with pytest.raises(ValueError, match=f"^Invalid approval {field}$"):
        ApprovalNotice.from_dict({"message": "Pair", field: value})


def test_unknown_keys_rejected():
    with pytest.raises(ValueError, match="^Invalid approval payload$"):
        ApprovalNotice.from_dict({"message": "Pair", "extra": True})


@pytest.mark.parametrize("value", [datetime(2030, 1, 1), True, 42, "0001-01-01T00:00:00+01:00"])
def test_expiry_errors_are_redacted(value):
    with pytest.raises(ValueError, match="^Invalid approval expires_at$"):
        format_approval_expiry(value)


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
def test_rejects_private_approval_parameters(suffix):
    with pytest.raises(ValueError, match="^Invalid approval url$"):
        ApprovalNotice("Pair", url="https://tv.example/" + suffix)


@pytest.mark.parametrize("query", ["user_code=ABCD-1234", "code=XYZ"])
def test_preserves_public_pairing_parameters(query):
    url = "https://tv.example/?" + query
    assert ApprovalNotice("Pair", url=url).url == url


@pytest.mark.parametrize("offset", ["+00:99", "+24:00"])
def test_invalid_offset(offset):
    with pytest.raises(ValueError, match="^Invalid approval expires_at$"):
        format_approval_expiry("2030-01-01T00:00:00" + offset)


@pytest.mark.parametrize("key", ["device_code", "device_secret", "authorization"])
def test_device_error_redaction(key):
    from unshackle.core.utils.redact import REDACTED, redact_secrets

    assert redact_secrets(f"failure {key}=Bearer123;next=public") == f"failure {key}={REDACTED};next=public"
