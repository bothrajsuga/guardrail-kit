from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from guardrail_kit.pii import PIIGuard
from guardrail_kit.sql import SQLValidator

MCPInputHook = Callable[[Mapping[str, Any]], bool]


@dataclass(frozen=True, slots=True)
class MCPToolPolicy:
    approved_schema_fingerprint: str
    deny: bool = False
    sql_validator: SQLValidator | None = None
    sql_argument: str = "query"
    input_guard: PIIGuard | None = None
    output_guard: PIIGuard | None = None
    input_hooks: tuple[MCPInputHook, ...] = ()
    allow_non_text_response: bool = False

    def __post_init__(self) -> None:
        fingerprint = self.approved_schema_fingerprint
        if len(fingerprint) != 64 or any(char not in "0123456789abcdef" for char in fingerprint):
            raise ValueError("approved_schema_fingerprint must be a lowercase SHA-256 digest")
        if self.sql_validator is not None and not self.sql_argument:
            raise ValueError("sql_argument must not be empty")
        object.__setattr__(self, "input_hooks", tuple(self.input_hooks))


@dataclass(frozen=True, slots=True)
class MCPGatewayPolicy:
    server_id: str
    tools: Mapping[str, MCPToolPolicy]
    timeout_seconds: float = 30.0
    audit_sink: Any = None
    audit_required: bool = False
    _tools: Mapping[str, MCPToolPolicy] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.server_id or not self.server_id.isascii():
            raise ValueError("server_id must be a non-empty ASCII string")
        if not isinstance(self.timeout_seconds, int | float) or self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        copied: dict[str, MCPToolPolicy] = {}
        for name, policy in self.tools.items():
            if not isinstance(name, str) or not _SAFE_TOOL_NAME.fullmatch(name):
                raise ValueError("tool names must use the supported ASCII identifier syntax")
            if name in copied:
                raise ValueError("duplicate tool policy")
            copied[name] = policy
        object.__setattr__(self, "_tools", MappingProxyType(copied))
        object.__setattr__(self, "tools", MappingProxyType(copied))
        if self.audit_required and self.audit_sink is None:
            raise ValueError("audit_required needs an audit_sink")

    def tool_policy(self, name: str) -> MCPToolPolicy | None:
        return self._tools.get(name)


_SAFE_TOOL_NAME = re.compile(r"[A-Za-z0-9_.:/-]{1,128}")
