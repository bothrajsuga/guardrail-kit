from __future__ import annotations

import pytest
from mcp import Client
from mcp.server.mcpserver import MCPServer

from guardrail_kit.integrations.mcp import (
    MCPGateway,
    MCPGatewayPolicy,
    MCPServerIdentity,
    MCPToolPolicy,
    fingerprint_tool_schema,
)


@pytest.mark.anyio
async def test_official_mcp_230_in_memory_client_server_round_trip() -> None:
    server = MCPServer("synthetic-guardrail-kit-server")
    calls: list[str] = []

    @server.tool()
    def echo(value: str) -> str:
        """Synthetic local echo tool."""
        calls.append(value)
        return value

    async with Client(server) as client:
        listed = await client.list_tools()
        approved = next(tool for tool in listed.tools if tool.name == "echo")
        gateway = MCPGateway(
            client=client,
            identity=MCPServerIdentity(
                identifier="official-in-memory",
                transport="in-process",
                endpoint="synthetic-server-object",
                verification="object-reference",
            ),
            policy=MCPGatewayPolicy(
                server_id="official-in-memory",
                tools={
                    "echo": MCPToolPolicy(
                        approved_schema_fingerprint=fingerprint_tool_schema(approved)
                    )
                },
            ),
        )

        result = await gateway.call_tool("echo", {"value": "safe"})

    assert calls == ["safe"]
    assert result.content[0].text == "safe"
