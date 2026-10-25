from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from guardrail_kit.pii import PIIGuard
from guardrail_kit.sql import SQLValidator

InputPolicyHook = Callable[[Mapping[str, Any]], bool]


@dataclass(frozen=True, slots=True)
class ToolInspection:
    allowed: bool
    value: Any = None
    reason_code: str = "policy_allowed"


@dataclass(frozen=True, slots=True)
class ToolGuardPolicy:
    """Immutable policy configuration for a guarded LangChain tool.

    ``pii_guard`` inspects every string value in JSON-like input and output
    containers. Its configured mask/redact transformation is passed onward;
    block decisions stop execution. SQL inspection applies only to the named
    top-level argument. Custom hooks are allow/block-only and receive a deeply
    immutable view of the copied arguments.
    """

    sql_validator: SQLValidator | None = None
    sql_argument: str = "query"
    input_guard: PIIGuard | None = None
    output_guard: PIIGuard | None = None
    input_hooks: tuple[InputPolicyHook, ...] = ()

    def __post_init__(self) -> None:
        if self.sql_validator is not None and not self.sql_argument:
            raise ValueError("sql_argument must not be empty")
        object.__setattr__(self, "input_hooks", tuple(self.input_hooks))

    def inspect_input(self, arguments: Mapping[str, Any]) -> ToolInspection:
        try:
            copied = _copy_json_like(arguments)
            if not isinstance(copied, dict):
                return ToolInspection(False, reason_code="invalid_arguments")
            if self.input_guard is not None:
                transformed = _inspect_strings(copied, self.input_guard)
                if not transformed.allowed:
                    return transformed
                copied = transformed.value
            if self.sql_validator is not None:
                sql = copied.get(self.sql_argument)
                result = self.sql_validator.validate(sql)
                if not result.allowed:
                    return ToolInspection(False, reason_code=result.reason_code)
            frozen = _freeze(copied)
            for hook in self.input_hooks:
                if hook(frozen) is not True:
                    return ToolInspection(False, reason_code="custom_policy_blocked")
            return ToolInspection(True, copied)
        except Exception:
            return ToolInspection(False, reason_code="policy_error")

    def inspect_output(self, output: Any) -> ToolInspection:
        if self.output_guard is None:
            return ToolInspection(True, output)
        try:
            return _inspect_strings(_copy_json_like(output), self.output_guard)
        except Exception:
            return ToolInspection(False, reason_code="output_policy_error")


def _inspect_strings(value: Any, guard: PIIGuard) -> ToolInspection:
    if isinstance(value, str):
        result = guard.inspect(value)
        if not result.allowed:
            return ToolInspection(False, reason_code=result.reason_code)
        return ToolInspection(True, result.output_text)
    if isinstance(value, dict):
        output: dict[Any, Any] = {}
        for key, item in value.items():
            inspected = _inspect_strings(item, guard)
            if not inspected.allowed:
                return inspected
            output[key] = inspected.value
        return ToolInspection(True, output)
    if isinstance(value, list):
        output_list: list[Any] = []
        for item in value:
            inspected = _inspect_strings(item, guard)
            if not inspected.allowed:
                return inspected
            output_list.append(inspected.value)
        return ToolInspection(True, output_list)
    if isinstance(value, tuple):
        output_tuple: list[Any] = []
        for item in value:
            inspected = _inspect_strings(item, guard)
            if not inspected.allowed:
                return inspected
            output_tuple.append(inspected.value)
        return ToolInspection(True, tuple(output_tuple))
    return ToolInspection(True, value)


def _copy_json_like(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _copy_json_like(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_copy_json_like(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_copy_json_like(item) for item in value)
    return value

def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list | tuple):
        return tuple(_freeze(item) for item in value)
    return value
