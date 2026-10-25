from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from mcp.types import CallToolResult, ImageContent, TextContent, Tool

from guardrail_kit.integrations.mcp import (
    MCPAuditEvent,
    MCPGateway,
    MCPGatewayError,
    MCPGatewayPolicy,
    MCPServerIdentity,
    MCPToolPolicy,
    fingerprint_tool_schema,
)
from guardrail_kit.pii import PIIGuard


class AdversarialClient:
    def __init__(self, tool: Tool) -> None:
        self.tool = tool
        self.calls = 0
        self.discovery: Any = SimpleNamespace(tools=[tool])
        self.discovery_error: Exception | None = None
        self.response: Any = CallToolResult(content=[TextContent(text="safe")])

    async def list_tools(self) -> Any:
        if self.discovery_error:
            raise self.discovery_error
        return self.discovery

    async def call_tool(self, name: str, arguments: dict[str, Any], **kwargs: Any) -> Any:
        del name, arguments, kwargs
        self.calls += 1
        return self.response


def _tool(*, output_schema: dict[str, Any] | None = None) -> Tool:
    return Tool(
        name="safe_tool",
        inputSchema={
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "required": ["value"],
            "additionalProperties": False,
        },
        outputSchema=output_schema,
    )


def _gateway(client: AdversarialClient, tool: Tool, **tool_options: Any) -> MCPGateway:
    tool_policy = MCPToolPolicy(
        approved_schema_fingerprint=fingerprint_tool_schema(tool), **tool_options
    )
    return MCPGateway(
        client=client,
        identity=MCPServerIdentity("trusted", "in-process", "fixture", "configured"),
        policy=MCPGatewayPolicy(server_id="trusted", tools={"safe_tool": tool_policy}),
    )


@pytest.mark.anyio
@pytest.mark.parametrize("name", ["", 7])
async def test_malformed_tool_names_fail_before_discovery(name: Any) -> None:
    tool = _tool()
    client = AdversarialClient(tool)
    with pytest.raises(MCPGatewayError, match="invalid_tool_name"):
        await _gateway(client, tool).call_tool(name, {"value": "safe"})
    assert client.calls == 0


@pytest.mark.anyio
async def test_invalid_correlation_and_falsy_non_mapping_arguments_fail_closed() -> None:
    tool = _tool()
    client = AdversarialClient(tool)
    events: list[MCPAuditEvent] = []
    policy = MCPGatewayPolicy(
        server_id="trusted",
        tools={
            "safe_tool": MCPToolPolicy(
                approved_schema_fingerprint=fingerprint_tool_schema(tool)
            )
        },
        audit_sink=events.append,
    )
    gateway = MCPGateway(
        client=client,
        identity=MCPServerIdentity("trusted", "in-process", "fixture"),
        policy=policy,
    )
    secret = "private.person@example.com"
    with pytest.raises(MCPGatewayError, match="invalid_correlation_id"):
        await gateway.call_tool("safe_tool", {"value": "safe"}, correlation_id=secret)
    assert secret not in repr(events)
    assert client.calls == 0

    with pytest.raises(MCPGatewayError, match="invalid_arguments"):
        await gateway.call_tool("safe_tool", [])  # type: ignore[arg-type]
    assert client.calls == 0


@pytest.mark.anyio
async def test_discovery_failures_are_sanitized_and_fail_closed() -> None:
    tool = _tool()
    client = AdversarialClient(tool)
    gateway = _gateway(client, tool)
    client.discovery_error = RuntimeError("private.person@example.com")
    with pytest.raises(MCPGatewayError) as caught:
        await gateway.call_tool("safe_tool", {"value": "safe"})
    assert caught.value.reason_code == "tool_discovery_error"
    assert "private.person" not in str(caught.value)

    client.discovery_error = None
    client.discovery = {"tools": [tool]}
    with pytest.raises(MCPGatewayError, match="invalid_tool_list"):
        await gateway.call_tool("safe_tool", {"value": "safe"})
    assert client.calls == 0


@pytest.mark.anyio
async def test_custom_hook_false_and_nested_mutation_fail_closed() -> None:
    tool = _tool()
    client = AdversarialClient(tool)
    blocked = _gateway(client, tool, input_hooks=(lambda arguments: False,))
    with pytest.raises(MCPGatewayError, match="custom_policy_blocked"):
        await blocked.call_tool("safe_tool", {"value": "safe"})

    def mutation(arguments: Any) -> bool:
        arguments["nested"]["items"][0] = "changed"
        return True

    nested_tool = Tool(
        name="safe_tool",
        inputSchema={
            "type": "object",
            "properties": {"nested": {"type": "object"}},
            "required": ["nested"],
        },
    )
    client = AdversarialClient(nested_tool)
    gateway = _gateway(client, nested_tool, input_hooks=(mutation,))
    original = {"nested": {"items": ["original"]}}
    with pytest.raises(MCPGatewayError, match="input_policy_error"):
        await gateway.call_tool("safe_tool", original)
    assert original == {"nested": {"items": ["original"]}}
    assert client.calls == 0


@pytest.mark.anyio
async def test_blocking_input_and_output_never_leaks_sensitive_value() -> None:
    tool = _tool()
    client = AdversarialClient(tool)
    gateway = _gateway(client, tool, input_guard=PIIGuard())
    secret = "private.person@example.com"
    with pytest.raises(MCPGatewayError) as caught:
        await gateway.call_tool("safe_tool", {"value": secret})
    assert secret not in str(caught.value)
    assert client.calls == 0

    client = AdversarialClient(tool)
    client.response = CallToolResult(content=[TextContent(text=secret)])
    gateway = _gateway(client, tool, output_guard=PIIGuard())
    with pytest.raises(MCPGatewayError) as caught:
        await gateway.call_tool("safe_tool", {"value": "safe"})
    assert secret not in str(caught.value)
    assert client.calls == 1  # Response policy cannot undo the completed side effect.


@pytest.mark.anyio
async def test_structured_response_schema_is_enforced_after_transformation() -> None:
    tool = _tool(
        output_schema={
            "type": "object",
            "properties": {"status": {"const": "approved"}},
            "required": ["status"],
            "additionalProperties": False,
        }
    )
    client = AdversarialClient(tool)
    client.response = CallToolResult(
        content=[TextContent(text="safe")], structuredContent={"status": "changed"}
    )
    with pytest.raises(MCPGatewayError, match="response_schema_invalid"):
        await _gateway(client, tool).call_tool("safe_tool", {"value": "safe"})

    client.response = CallToolResult(
        content=[TextContent(text="safe")],
        structuredContent={"status": "approved"},
        resultType="input_required",
    )
    with pytest.raises(MCPGatewayError, match="unsupported_response_state"):
        await _gateway(client, tool).call_tool("safe_tool", {"value": "safe"})


@pytest.mark.anyio
async def test_non_text_content_requires_explicit_risk_acceptance() -> None:
    tool = _tool()
    client = AdversarialClient(tool)
    image = ImageContent(data="AA==", mimeType="image/png")
    client.response = CallToolResult(content=[image])
    result = await _gateway(client, tool, allow_non_text_response=True).call_tool(
        "safe_tool", {"value": "safe"}
    )
    assert result.content == [image]


@pytest.mark.anyio
async def test_untrusted_response_metadata_is_removed() -> None:
    tool = _tool()
    client = AdversarialClient(tool)
    secret = "private.person@example.com"
    client.response = CallToolResult(
        content=[TextContent(text="safe", _meta={"secret": secret})],
        _meta={"secret": secret},
    )

    result = await _gateway(client, tool).call_tool("safe_tool", {"value": "safe"})

    assert result.meta is None
    assert result.content[0].meta is None
    assert secret not in repr(result)


@pytest.mark.anyio
async def test_async_audit_sink_and_best_effort_failure() -> None:
    tool = _tool()
    client = AdversarialClient(tool)
    events: list[MCPAuditEvent] = []

    async def sink(event: MCPAuditEvent) -> None:
        events.append(event)

    policy = MCPGatewayPolicy(
        server_id="trusted",
        tools={
            "safe_tool": MCPToolPolicy(
                approved_schema_fingerprint=fingerprint_tool_schema(tool)
            )
        },
        audit_sink=sink,
    )
    gateway = MCPGateway(
        client=client,
        identity=MCPServerIdentity("trusted", "in-process", "fixture"),
        policy=policy,
    )
    await gateway.call_tool("safe_tool", {"value": "safe"})
    assert len(events) == 2

    def failing(event: MCPAuditEvent) -> None:
        del event
        raise RuntimeError("offline")

    best_effort = MCPGatewayPolicy(
        server_id="trusted",
        tools=policy.tools,
        audit_sink=failing,
        audit_required=False,
    )
    gateway = MCPGateway(
        client=client,
        identity=MCPServerIdentity("trusted", "in-process", "fixture"),
        policy=best_effort,
    )
    await gateway.call_tool("safe_tool", {"value": "safe"})


def test_policy_configuration_is_immutable_and_validated() -> None:
    tool = _tool()
    tool_policy = MCPToolPolicy(approved_schema_fingerprint=fingerprint_tool_schema(tool))
    source = {"safe_tool": tool_policy}
    policy = MCPGatewayPolicy(server_id="trusted", tools=source)
    source.clear()
    assert policy.tool_policy("safe_tool") is tool_policy
    with pytest.raises(TypeError):
        policy.tools["other"] = tool_policy  # type: ignore[index]

    with pytest.raises(ValueError, match="fingerprint"):
        MCPToolPolicy(approved_schema_fingerprint="invalid")
    with pytest.raises(ValueError, match="server_id"):
        MCPGatewayPolicy(server_id="", tools={})
    with pytest.raises(ValueError, match="identifier syntax"):
        MCPGatewayPolicy(server_id="trusted", tools={"not allowed": tool_policy})
    with pytest.raises(ValueError, match="timeout"):
        MCPGatewayPolicy(server_id="trusted", tools={}, timeout_seconds=0)
    with pytest.raises(ValueError, match="audit_sink"):
        MCPGatewayPolicy(server_id="trusted", tools={}, audit_required=True)
    with pytest.raises(ValueError, match="identity fields"):
        MCPServerIdentity("", "in-process", "fixture")
    with pytest.raises(TypeError, match="client"):
        MCPGateway(
            client=object(),
            identity=MCPServerIdentity("trusted", "in-process", "fixture"),
            policy=MCPGatewayPolicy(server_id="trusted", tools={}),
        )
