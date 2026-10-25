from __future__ import annotations

import inspect
import re
import time
import uuid
from collections.abc import Mapping
from typing import Any, NoReturn, cast

import anyio

from guardrail_kit.integrations.mcp.audit import MCPAuditEvent
from guardrail_kit.integrations.mcp.exceptions import MCPGatewayError
from guardrail_kit.integrations.mcp.identity import MCPServerIdentity
from guardrail_kit.integrations.mcp.inspection import (
    copy_json_value,
    freeze_json_value,
    inspect_json_strings,
)
from guardrail_kit.integrations.mcp.policy import MCPGatewayPolicy, MCPToolPolicy
from guardrail_kit.integrations.mcp.schema import (
    fingerprint_tool_schema,
    validate_arguments,
    validate_json_schema,
)


class MCPGateway:
    """Default-deny in-process adapter for the official async MCP client API."""

    def __init__(self, *, client: Any, identity: MCPServerIdentity, policy: MCPGatewayPolicy):
        if identity.identifier != policy.server_id:
            raise ValueError("configured server identity does not match the gateway policy")
        if not callable(getattr(client, "list_tools", None)) or not callable(
            getattr(client, "call_tool", None)
        ):
            raise TypeError("client must provide async list_tools and call_tool methods")
        self._client = client
        self.identity = identity
        self.policy = policy

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        correlation_id: str | None = None,
    ) -> Any:
        started = time.monotonic()
        generated_correlation = uuid.uuid4().hex
        if correlation_id is not None and (
            not isinstance(correlation_id, str)
            or not _SAFE_CORRELATION.fullmatch(correlation_id)
        ):
            await self._reject(generated_correlation, "", "invalid_correlation_id", started)
        correlation = correlation_id or generated_correlation
        if not isinstance(name, str) or not _SAFE_TOOL_NAME.fullmatch(name):
            await self._reject(correlation, "", "invalid_tool_name", started)
        tool_policy = self.policy.tool_policy(name)
        if tool_policy is None:
            await self._reject(correlation, "", "tool_not_allowed", started)
        assert tool_policy is not None
        if tool_policy.deny:
            await self._reject(correlation, name, "tool_denied", started)
        try:
            with anyio.fail_after(self.policy.timeout_seconds):
                listed = await self._client.list_tools()
        except TimeoutError:
            await self._reject(correlation, name, "tool_discovery_timeout", started)
        except Exception:
            await self._reject(correlation, name, "tool_discovery_error", started)
        tools = getattr(listed, "tools", None)
        if not isinstance(tools, list):
            await self._reject(correlation, name, "invalid_tool_list", started)
        matches = [tool for tool in tools if getattr(tool, "name", None) == name]
        if len(matches) != 1:
            reason = "tool_not_discovered" if not matches else "ambiguous_tool_identity"
            await self._reject(correlation, name, reason, started)
        tool = matches[0]
        try:
            fingerprint = fingerprint_tool_schema(tool)
        except Exception:
            await self._reject(correlation, name, "invalid_tool_schema", started)
        if fingerprint != tool_policy.approved_schema_fingerprint:
            await self._reject(correlation, name, "schema_changed", started)
        payload = await self._inspect_input(
            correlation,
            name,
            {} if arguments is None else arguments,
            tool,
            tool_policy,
            started,
        )
        await self._audit(correlation, name, "allow", "call_authorized", started, fingerprint)
        try:
            with anyio.fail_after(self.policy.timeout_seconds):
                response = await self._client.call_tool(
                    name, payload, read_timeout_seconds=self.policy.timeout_seconds
                )
        except TimeoutError:
            await self._reject(correlation, name, "tool_call_timeout", started)
        except Exception:
            await self._reject(correlation, name, "tool_call_error", started)
        inspected = await self._inspect_response(
            correlation, name, response, tool, tool_policy, started
        )
        await self._audit(correlation, name, "allow", "response_allowed", started, fingerprint)
        return inspected

    async def _inspect_input(
        self,
        correlation: str,
        name: str,
        arguments: Mapping[str, Any],
        tool: Any,
        policy: MCPToolPolicy,
        started: float,
    ) -> dict[str, Any]:
        try:
            payload = copy_json_value(arguments)
            if not isinstance(payload, dict):
                await self._reject(correlation, name, "invalid_arguments", started)
            if policy.input_guard is not None:
                allowed, transformed, reason = inspect_json_strings(payload, policy.input_guard)
                if not allowed:
                    await self._reject(correlation, name, reason, started)
                payload = transformed
            if not isinstance(payload, dict):
                await self._reject(correlation, name, "invalid_arguments", started)
            if policy.sql_validator is not None:
                sql = cast(str, payload.get(policy.sql_argument))
                result = policy.sql_validator.validate(sql)
                if not result.allowed:
                    await self._reject(correlation, name, result.reason_code, started)
            for hook in policy.input_hooks:
                if hook(freeze_json_value(payload)) is not True:
                    await self._reject(correlation, name, "custom_policy_blocked", started)
            schema = getattr(tool, "input_schema", None)
            if not isinstance(schema, Mapping):
                await self._reject(correlation, name, "invalid_tool_schema", started)
            try:
                validate_arguments(cast(Mapping[str, Any], schema), payload)
            except ValueError:
                await self._reject(correlation, name, "argument_schema_invalid", started)
            return cast(dict[str, Any], payload)
        except MCPGatewayError:
            raise
        except Exception:
            await self._reject(correlation, name, "input_policy_error", started)

    async def _inspect_response(
        self,
        correlation: str,
        name: str,
        response: Any,
        tool: Any,
        policy: MCPToolPolicy,
        started: float,
    ) -> Any:
        try:
            from mcp.types import CallToolResult, TextContent
        except ImportError as exc:  # pragma: no cover - clean optional-dependency smoke
            raise ImportError("MCP integration requires: pip install 'guardrail-kit[mcp]'") from exc
        if not isinstance(response, CallToolResult):
            await self._reject(correlation, name, "unsupported_response", started)
        copied = response.model_copy(deep=True)
        copied.meta = None
        if copied.result_type != "complete":
            await self._reject(correlation, name, "unsupported_response_state", started)
        output_guard = policy.output_guard
        for index, content in enumerate(copied.content):
            if isinstance(content, TextContent):
                content = content.model_copy(update={"meta": None})
                if output_guard is not None:
                    result = output_guard.inspect(content.text)
                    if not result.allowed:
                        await self._reject(correlation, name, result.reason_code, started)
                    content = content.model_copy(update={"text": result.output_text})
                copied.content[index] = content
            elif not policy.allow_non_text_response:
                await self._reject(correlation, name, "unsupported_response_content", started)
        if copied.structured_content is not None and output_guard is not None:
            allowed, transformed, reason = inspect_json_strings(
                copy_json_value(copied.structured_content), output_guard
            )
            if not allowed:
                await self._reject(correlation, name, reason, started)
            copied.structured_content = transformed
        output_schema = getattr(tool, "output_schema", None)
        if output_schema is not None and not copied.is_error:
            if not isinstance(output_schema, Mapping):
                await self._reject(correlation, name, "invalid_tool_schema", started)
            try:
                validate_json_schema(output_schema, copied.structured_content)
            except ValueError:
                await self._reject(correlation, name, "response_schema_invalid", started)
        return copied

    async def _reject(
        self, correlation: str, name: str, reason: str, started: float
    ) -> NoReturn:
        await self._audit(correlation, name, "block", reason, started)
        raise MCPGatewayError(reason)

    async def _audit(
        self,
        correlation: str,
        name: str,
        decision: str,
        reason: str,
        started: float,
        schema_fingerprint: str | None = None,
    ) -> None:
        sink = self.policy.audit_sink
        if sink is None:
            return
        event = MCPAuditEvent(
            correlation_id=correlation,
            server_id=self.identity.identifier,
            tool_name=name,
            decision=decision,
            reason_code=reason,
            duration_ms=max(0.0, (time.monotonic() - started) * 1000),
            metadata={"schema_fingerprint": schema_fingerprint} if schema_fingerprint else {},
        )
        try:
            result = sink(event)
            if inspect.isawaitable(result):
                await result
        except Exception:
            if self.policy.audit_required:
                raise MCPGatewayError("audit_failure") from None


_SAFE_TOOL_NAME = re.compile(r"[A-Za-z0-9_.:/-]{1,128}")
_SAFE_CORRELATION = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
