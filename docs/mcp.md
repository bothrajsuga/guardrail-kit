# MCP Security Gateway

Install the optional integration:

```bash
pip install 'guardrail-kit[mcp]'
```

Phase 4 is verified with the official Python MCP SDK 2.3.0 and an in-memory
`MCPServer`/`Client` connection that negotiated protocol version `2026-07-28`.
The declared range is `mcp>=2.3,<3`; other releases in that range are not
individually certified. CI tests both the 2.3.0 lower bound and the newest
resolver-selected compatible release.

## Configuration and use

Discover and review a server's tool schemas in a trusted enrollment process,
then store the approved fingerprints as configuration:

```python
from guardrail_kit.integrations.mcp import (
    MCPGateway,
    MCPGatewayPolicy,
    MCPServerIdentity,
    MCPToolPolicy,
    fingerprint_tool_schema,
)

listed = await trusted_client.list_tools()
approved = next(tool for tool in listed.tools if tool.name == "read_database")

gateway = MCPGateway(
    client=trusted_client,
    identity=MCPServerIdentity(
        identifier="analytics-prod",
        transport="streamable-http",
        endpoint="https://mcp.example.internal",
        verification="application-verified-tls",
    ),
    policy=MCPGatewayPolicy(
        server_id="analytics-prod",
        tools={
            "read_database": MCPToolPolicy(
                approved_schema_fingerprint=fingerprint_tool_schema(approved),
                sql_validator=validator,
                sql_argument="query",
                input_guard=redacting_guard,
                output_guard=redacting_guard,
            )
        },
    ),
)

result = await gateway.call_tool(
    "read_database", {"query": "SELECT id FROM users LIMIT 10"}
)
```

Never enroll a newly discovered schema automatically. Compare and approve it
out of band, then update the configured fingerprint. The fingerprint is SHA-256
over canonical JSON containing the exact tool name, input schema, and output
schema. Descriptions, annotations, icons, and other display metadata are
intentionally excluded because they are untrusted and non-authoritative.
Canonical JSON sorts object keys and removes insignificant whitespace, but it
does not prove semantic equivalence between different JSON Schemas.

## Execution flow

For every call the gateway:

1. resolves an exact configured tool policy using a trusted configured server
   identity;
2. lists tools again and requires exactly one matching tool;
3. compares its schema fingerprint to the approved fingerprint;
4. copies arguments, applies configured PII/secrets transformation, validates
   explicitly configured SQL arguments, applies immutable custom hooks, and
   validates the final payload against the approved JSON Schema;
5. writes the authorization audit event and forwards exactly that payload;
6. accepts only a complete `CallToolResult`, filters supported text and
   structured content, strips untrusted `_meta`, validates structured output
   against the approved output schema, and writes the response decision event.

Unknown servers and tools are denied. An explicit deny rule wins. Tool names
are exact and case-sensitive. Policy and transport errors use value-free reason
codes. Timeout and cancellation behavior is tested; caller cancellation is not
converted into authorization success.

## Identity and transport boundary

`MCPServerIdentity` is trusted application configuration. It is never derived
from a server-provided name, title, description, or tool metadata. The gateway
does not create or authenticate network transports. The application must bind
the supplied client to the configured endpoint using an appropriate mechanism,
such as a direct in-process object reference, authenticated subprocess launch,
TLS certificate verification, network policy, or mutually authenticated TLS.
The free-form `verification` label documents that external binding; the gateway
cannot independently prove the label.

Only the official asynchronous `list_tools` and `call_tool` client path is
verified. The adapter rechecks the first returned tool-list page for every call.
A tool that exists only on a later paginated page is conservatively denied.
Stdio, SSE, and streamable HTTP are not independently integration-tested here;
transport setup, authentication headers, reconnection, and session security
remain application responsibilities.

## Responses and auditing

Text content and JSON-like structured content can be blocked or redacted.
Binary resources, images, audio, resource links, embedded resources, streaming,
and input-required/multi-round results are unsupported and fail closed by
default. `allow_non_text_response=True` is an explicit risk acceptance that
passes non-text content without inspection. Response filtering occurs after
the server operation and cannot undo side effects.

Audit events include correlation ID, trusted server identifier, configured tool
identifier, decision, reason code, duration, and approved schema fingerprint.
They never contain arguments, response content, authentication headers, or raw
exceptions. Best-effort audit failures are ignored. With `audit_required=True`,
an audit failure blocks forwarding if it happens before the call and blocks the
response if it happens after the server already executed; it cannot undo that
execution.

## Threat model and limitations

Protected assets include tool authority, SQL/data access, sensitive arguments,
responses, schema approvals, and security telemetry. Attackers may control tool
names and arguments, server-provided schemas and metadata, response content,
timing, disconnects, and malicious or compromised MCP servers.

The gateway addresses default-deny authorization, schema poisoning, unexpected
tool-list changes, argument-based exfiltration detectable by configured guards,
and response leakage in supported content. It cannot force a compromised server
to keep the same implementation after discovery; the MCP call request does not
carry the approved schema fingerprint. It cannot stop a server from performing
side effects before returning a blocked response. Response text may still
contain prompt injection even after PII inspection.

Direct use of the underlying client bypasses the gateway. This phase is not a
standalone proxy, prompt-injection defense, sandbox, credential vault, binary
scanner, DLP replacement, transport authenticator, or network security system.
