from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

AuditSink = Callable[["MCPAuditEvent"], Awaitable[None] | None]


@dataclass(frozen=True, slots=True)
class MCPAuditEvent:
    correlation_id: str
    server_id: str
    tool_name: str
    decision: str
    reason_code: str
    duration_ms: float
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))
