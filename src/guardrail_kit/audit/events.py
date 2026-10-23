from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any

from guardrail_kit.core import Decision


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """A deliberately input-free audit record."""

    guardrail: str
    decision: Decision
    reason_code: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))
