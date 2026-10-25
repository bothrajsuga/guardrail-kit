from mcp import Client
from mcp.server.mcpserver import MCPServer

from guardrail_kit.integrations.mcp import (
    MCPGateway,
    MCPGatewayPolicy,
    MCPServerIdentity,
    MCPToolPolicy,
    fingerprint_tool_schema,
)


async def main() -> None:
    server = MCPServer("local-example")

    @server.tool()
    def echo(value: str) -> str:
        """Return a synthetic local value."""
        return value

    async with Client(server) as client:
        listed = await client.list_tools()
        approved = next(tool for tool in listed.tools if tool.name == "echo")
        gateway = MCPGateway(
            client=client,
            identity=MCPServerIdentity(
                "local-example", "in-process", "server-object", "object-reference"
            ),
            policy=MCPGatewayPolicy(
                server_id="local-example",
                tools={
                    "echo": MCPToolPolicy(
                        approved_schema_fingerprint=fingerprint_tool_schema(approved)
                    )
                },
            ),
        )
        result = await gateway.call_tool("echo", {"value": "safe"})
        print(result.content[0].text)


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
