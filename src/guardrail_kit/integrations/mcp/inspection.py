from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from guardrail_kit.pii import PIIGuard


def copy_json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: copy_json_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [copy_json_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(copy_json_value(item) for item in value)
    return value


def freeze_json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: freeze_json_value(item) for key, item in value.items()})
    if isinstance(value, list | tuple):
        return tuple(freeze_json_value(item) for item in value)
    return value


def inspect_json_strings(value: Any, guard: PIIGuard) -> tuple[bool, Any, str]:
    if isinstance(value, str):
        result = guard.inspect(value)
        return result.allowed, result.output_text, result.reason_code
    if isinstance(value, dict):
        output: dict[Any, Any] = {}
        for key, item in value.items():
            allowed, transformed, reason = inspect_json_strings(item, guard)
            if not allowed:
                return False, None, reason
            output[key] = transformed
        return True, output, "policy_allowed"
    if isinstance(value, list):
        output_list: list[Any] = []
        for item in value:
            allowed, transformed, reason = inspect_json_strings(item, guard)
            if not allowed:
                return False, None, reason
            output_list.append(transformed)
        return True, output_list, "policy_allowed"
    if isinstance(value, tuple):
        output_tuple: list[Any] = []
        for item in value:
            allowed, transformed, reason = inspect_json_strings(item, guard)
            if not allowed:
                return False, None, reason
            output_tuple.append(transformed)
        return True, tuple(output_tuple), "policy_allowed"
    return True, value, "policy_allowed"
