from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from guardrail_kit.core import Decision


class SensitiveEntity(StrEnum):
    EMAIL = "email"
    PHONE = "phone"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    PAYMENT_CARD = "payment_card"
    INDIAN_PAN = "indian_pan"
    INDIAN_AADHAAR = "indian_aadhaar"
    CUSTOM_IDENTIFIER = "custom_identifier"
    AWS_ACCESS_KEY_ID = "aws_access_key_id"
    GITHUB_TOKEN = "github_token"
    API_KEY = "api_key"
    PEM_PRIVATE_KEY = "pem_private_key"
    BEARER_TOKEN = "bearer_token"
    HIGH_ENTROPY = "high_entropy"


class SensitiveAction(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    MASK = "mask"
    REDACT = "redact"


@dataclass(frozen=True, slots=True)
class SensitiveMatch:
    """A sensitive-data match using half-open offsets into the original input.

    The matched value is intentionally not retained. ``label`` identifies a
    configured custom rule and must never contain input-derived data.
    """

    entity_type: SensitiveEntity
    start: int
    end: int
    label: str | None = None

    def __post_init__(self) -> None:
        if self.start < 0 or self.end <= self.start:
            raise ValueError("match offsets must define a non-empty span")


@dataclass(frozen=True, slots=True, repr=False)
class PIIResult:
    decision: Decision
    action: SensitiveAction
    reason_code: str
    output_text: str | None
    matches: tuple[SensitiveMatch, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.reason_code or not self.reason_code.isascii():
            raise ValueError("reason_code must be a non-empty ASCII string")
        object.__setattr__(self, "matches", tuple(self.matches))
        object.__setattr__(self, "metadata", _freeze_mapping(self.metadata))

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW

    def __repr__(self) -> str:
        return (
            f"PIIResult(decision={self.decision!r}, action={self.action!r}, "
            f"reason_code={self.reason_code!r}, match_count={len(self.matches)}, "
            f"has_output={self.output_text is not None})"
        )

    def to_safe_dict(self) -> dict[str, Any]:
        """Serialize decisions and offsets without serializing text content."""

        return {
            "decision": self.decision.value,
            "action": self.action.value,
            "reason_code": self.reason_code,
            "matches": [
                {
                    "entity_type": match.entity_type.value,
                    "start": match.start,
                    "end": match.end,
                    "label": match.label,
                }
                for match in self.matches
            ],
            "metadata": _thaw_value(self.metadata),
            "has_output": self.output_text is not None,
        }


def _freeze_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType({key: _freeze_value(item) for key, item in value.items()})


def _freeze_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return _freeze_mapping(value)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_value(item) for item in value)
    return value


def _thaw_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_value(item) for item in value]
    return value
