from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any


def fingerprint_tool_schema(tool: Any) -> str:
    """Fingerprint security-relevant MCP tool identity and JSON schemas."""

    value = {
        "name": getattr(tool, "name", None),
        "inputSchema": getattr(tool, "input_schema", None),
        "outputSchema": getattr(tool, "output_schema", None),
    }
    encoded = canonical_schema_json(value).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def canonical_schema_json(value: Mapping[str, Any]) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("tool schema is not canonically serializable") from exc


def validate_arguments(schema: Mapping[str, Any], arguments: Mapping[str, Any]) -> None:
    validate_json_schema(schema, arguments)


def validate_json_schema(schema: Mapping[str, Any], value: Any) -> None:
    try:
        from jsonschema import Draft202012Validator
        from jsonschema.exceptions import SchemaError, ValidationError
    except ImportError as exc:  # pragma: no cover - clean optional-dependency smoke
        raise ImportError("MCP integration requires: pip install 'guardrail-kit[mcp]'") from exc
    try:
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(value)
    except (SchemaError, ValidationError, TypeError, ValueError) as exc:
        raise ValueError("tool arguments do not match the approved schema") from exc
