from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any


class Decision(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"


@dataclass(frozen=True, slots=True)
class GuardrailResult:
    decision: Decision
    reason_code: str
    message: str
    normalized_input: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.reason_code or not self.reason_code.isascii():
            raise ValueError("reason_code must be a non-empty ASCII string")
        if not self.message:
            raise ValueError("message must not be empty")
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW
