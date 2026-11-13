"""Transient device-approval payloads."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class ApprovalNotice:
    """A device-approval message that must not enter durable logs."""

    message: str

    def to_dict(self) -> dict[str, str]:
        return {"message": self.message}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ApprovalNotice:
        if not isinstance(value, Mapping):
            raise ValueError("Approval payload must be an object")
        message = value.get("message")
        if not isinstance(message, str) or not message:
            raise ValueError("Approval payload requires a non-empty message")
        return cls(message)
