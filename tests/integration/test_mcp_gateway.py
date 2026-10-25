from __future__ import annotations

import asyncio
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
from guardrail_kit.pii import PIIGuard, PIIPolicy
from guardrail_kit.sql import SQLPolicy, SQLValidator


def _tool(name: str = "echo", schema: dict[str, Any] | None = None) -> Tool:
    return Tool(
        name=name,
        description="Untrusted server description",
        inputSchema=schema
        or {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "required": ["value"],
            "additionalProperties": False,
        },
    )


class FakeClient:
    def __init__(self, tools: list[Tool], response: Any | None = None) -> None:
        self.tools = tools
        self.response = response or CallToolResult(content=[TextContent(text="safe")])
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.list_count = 0
        self.delay = 0.0
        self.call_error: Exception | None = None

    async def list_tools(self) -> Any:
        self.list_count += 1
        return SimpleNamespace(tools=self.tools)

    async def call_tool(
        self, name: str, arguments: dict[str, Any], **kwargs: Any
    ) -> Any:
        del kwargs
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.call_error is not None:
            raise self.call_error
        self.calls.append((name, arguments))
        return self.response


def _gateway(
    client: FakeClient,
    tool: Tool,
    *,
    tool_policy: MCPToolPolicy | None = None,
    audit_sink: Any = None,
    audit_required: bool = False,
    timeout: float = 1.0,
) -> MCPGateway:
    configured = tool_policy or MCPToolPolicy(
        approved_schema_fingerprint=fingerprint_tool_schema(tool)
    )
    policy = MCPGatewayPolicy(
        server_id="local-test",
        tools={tool.name: configured},
        audit_sink=audit_sink,
        audit_required=audit_required,
        timeout_seconds=timeout,
    )
    return MCPGateway(
        client=client,
        identity=MCPServerIdentity(
            identifier="local-test",
            transport="in-process",
            endpoint="synthetic-fixture",
        ),
        policy=policy,
    )


@pytest.mark.anyio
async def test_authorized_call_executes_once() -> None:
    tool = _tool()
    client = FakeClient([tool])
    gateway = _gateway(client, tool)

    result = await gateway.call_tool("echo", {"value": "hello"})

    assert result.content[0].text == "safe"
    assert client.calls == [("echo", {"value": "hello"})]
    assert client.list_count == 1


@pytest.mark.anyio
@pytest.mark.parametrize("configured", [False, True])
async def test_unknown_or_explicitly_denied_tool_executes_zero_times(configured: bool) -> None:
    tool = _tool()
    client = FakeClient([tool])
    denied = MCPToolPolicy(
        approved_schema_fingerprint=fingerprint_tool_schema(tool), deny=True
    )
    policy = MCPGatewayPolicy(
        server_id="local-test", tools={"echo": denied} if configured else {}
    )
    gateway = MCPGateway(
        client=client,
        identity=MCPServerIdentity("local-test", "in-process", "fixture"),
        policy=policy,
    )

    with pytest.raises(MCPGatewayError) as caught:
        await gateway.call_tool("echo", {"value": "safe"})
    assert caught.value.reason_code == ("tool_denied" if configured else "tool_not_allowed")
    assert client.calls == []
    assert client.list_count == 0


def test_unknown_server_identity_is_rejected_at_construction() -> None:
    with pytest.raises(ValueError, match="identity"):
        MCPGateway(
            client=FakeClient([]),
            identity=MCPServerIdentity("unexpected", "in-process", "fixture"),
            policy=MCPGatewayPolicy(server_id="approved", tools={}),
        )


@pytest.mark.anyio
async def test_schema_change_and_duplicate_identity_fail_closed() -> None:
    approved = _tool()
    changed = _tool(schema={"type": "object", "properties": {"other": {"type": "string"}}})
    client = FakeClient([changed])
    gateway = _gateway(client, approved)
    with pytest.raises(MCPGatewayError, match="schema_changed"):
        await gateway.call_tool("echo", {"value": "safe"})
    assert client.calls == []

    client.tools = [approved, approved]
    with pytest.raises(MCPGatewayError, match="ambiguous_tool_identity"):
        await gateway.call_tool("echo", {"value": "safe"})


@pytest.mark.anyio
async def test_invalid_argument_schema_fails_closed_without_value_leak() -> None:
    tool = _tool()
    client = FakeClient([tool])
    gateway = _gateway(client, tool)
    secret = "private.person@example.com"

    with pytest.raises(MCPGatewayError) as caught:
        await gateway.call_tool("echo", {"unexpected": secret})

    assert caught.value.reason_code == "argument_schema_invalid"
    assert secret not in str(caught.value)
    assert client.calls == []


@pytest.mark.anyio
async def test_input_redaction_does_not_mutate_caller_arguments() -> None:
    tool = _tool()
    client = FakeClient([tool])
    tool_policy = MCPToolPolicy(
        approved_schema_fingerprint=fingerprint_tool_schema(tool),
        input_guard=PIIGuard(PIIPolicy(action="redact")),
    )
    gateway = _gateway(client, tool, tool_policy=tool_policy)
    arguments = {"value": "private.person@example.com"}

    await gateway.call_tool("echo", arguments)

    assert arguments == {"value": "private.person@example.com"}
    assert client.calls == [("echo", {"value": "[REDACTED]"})]


@pytest.mark.anyio
async def test_final_transformed_sql_is_validated_before_forwarding() -> None:
    tool = _tool(
        "query",
        {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
            "additionalProperties": False,
        },
    )
    client = FakeClient([tool])
    validator = SQLValidator(SQLPolicy(dialect="sqlite", allowed_tables={"users"}))
    tool_policy = MCPToolPolicy(
        approved_schema_fingerprint=fingerprint_tool_schema(tool),
        input_guard=PIIGuard(PIIPolicy(action="redact")),
        sql_validator=validator,
    )
    gateway = _gateway(client, tool, tool_policy=tool_policy)

    await gateway.call_tool(
        "query", {"query": "SELECT id FROM users /* private.person@example.com */"}
    )
    assert client.calls[0][1]["query"] == "SELECT id FROM users /* [REDACTED] */"

    with pytest.raises(MCPGatewayError, match="parse_error"):
        await gateway.call_tool(
            "query", {"query": "SELECT id FROM users WHERE x='private.person@example.com'"}
        )
    assert len(client.calls) == 1


@pytest.mark.anyio
async def test_text_and_structured_responses_are_redacted() -> None:
    tool = _tool()
    response = CallToolResult(
        content=[TextContent(text="private.person@example.com")],
        structuredContent={"nested": ["other.person@example.com"]},
    )
    client = FakeClient([tool], response)
    tool_policy = MCPToolPolicy(
        approved_schema_fingerprint=fingerprint_tool_schema(tool),
        output_guard=PIIGuard(PIIPolicy(action="redact")),
    )
    result = await _gateway(client, tool, tool_policy=tool_policy).call_tool(
        "echo", {"value": "safe"}
    )

    assert result.content[0].text == "[REDACTED]"
    assert result.structured_content == {"nested": ["[REDACTED]"]}
    assert response.content[0].text == "private.person@example.com"


@pytest.mark.anyio
async def test_non_text_and_malformed_responses_fail_closed() -> None:
    tool = _tool()
    client = FakeClient(
        [tool], CallToolResult(content=[ImageContent(data="AA==", mimeType="image/png")])
    )
    gateway = _gateway(client, tool)
    with pytest.raises(MCPGatewayError, match="unsupported_response_content"):
        await gateway.call_tool("echo", {"value": "safe"})

    client.response = {"content": []}
    with pytest.raises(MCPGatewayError, match="unsupported_response"):
        await gateway.call_tool("echo", {"value": "safe"})


@pytest.mark.anyio
async def test_policy_hook_exception_and_transport_error_are_sanitized() -> None:
    tool = _tool()

    def broken(arguments: Any) -> bool:
        del arguments
        raise RuntimeError("private.person@example.com")

    policy = MCPToolPolicy(
        approved_schema_fingerprint=fingerprint_tool_schema(tool), input_hooks=(broken,)
    )
    client = FakeClient([tool])
    gateway = _gateway(client, tool, tool_policy=policy)
    with pytest.raises(MCPGatewayError) as policy_error:
        await gateway.call_tool("echo", {"value": "safe"})
    assert policy_error.value.reason_code == "input_policy_error"
    assert client.calls == []

    client.call_error = RuntimeError("private.person@example.com")
    gateway = _gateway(client, tool)
    with pytest.raises(MCPGatewayError) as transport_error:
        await gateway.call_tool("echo", {"value": "safe"})
    assert transport_error.value.reason_code == "tool_call_error"
    assert "private.person" not in str(transport_error.value)


@pytest.mark.anyio
async def test_concurrent_calls_are_isolated_and_tool_list_rechecked() -> None:
    tool = _tool()
    client = FakeClient([tool])
    gateway = _gateway(client, tool)

    await asyncio.gather(
        *(gateway.call_tool("echo", {"value": str(index)}) for index in range(12))
    )

    assert len(client.calls) == 12
    assert client.list_count == 12
    assert sorted((item[1]["value"] for item in client.calls), key=int) == [
        str(i) for i in range(12)
    ]

    client.tools = []
    with pytest.raises(MCPGatewayError, match="tool_not_discovered"):
        await gateway.call_tool("echo", {"value": "reconnected"})


@pytest.mark.anyio
async def test_timeout_fails_closed_and_cancellation_propagates() -> None:
    tool = _tool()
    client = FakeClient([tool])
    client.delay = 0.1
    gateway = _gateway(client, tool, timeout=0.01)
    with pytest.raises(MCPGatewayError, match="tool_call_timeout"):
        await gateway.call_tool("echo", {"value": "safe"})
    assert client.calls == []

    client.delay = 1
    gateway = _gateway(client, tool, timeout=10)
    task = asyncio.create_task(gateway.call_tool("echo", {"value": "safe"}))
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.anyio
async def test_safe_audit_events_and_mandatory_failure() -> None:
    tool = _tool()
    events: list[MCPAuditEvent] = []
    gateway = _gateway(client := FakeClient([tool]), tool, audit_sink=events.append)

    await gateway.call_tool(
        "echo", {"value": "private.person@example.com"}, correlation_id="correlation-1"
    )

    assert [event.reason_code for event in events] == ["call_authorized", "response_allowed"]
    assert all(event.correlation_id == "correlation-1" for event in events)
    assert "private.person" not in repr(events)
    assert client.calls

    def failing_sink(event: MCPAuditEvent) -> None:
        del event
        raise RuntimeError("audit offline")

    mandatory = _gateway(
        FakeClient([tool]), tool, audit_sink=failing_sink, audit_required=True
    )
    with pytest.raises(MCPGatewayError, match="audit_failure"):
        await mandatory.call_tool("echo", {"value": "safe"})
    assert mandatory._client.calls == []


@pytest.mark.anyio
async def test_direct_client_access_is_outside_gateway_boundary() -> None:
    tool = _tool()
    client = FakeClient([tool])
    gateway = _gateway(client, tool)
    del gateway

    await client.call_tool("not-allowed", {"value": "direct"})

    assert client.calls == [("not-allowed", {"value": "direct"})]
