# Phase 4 MCP Security Gateway Report

Date: 2026-10-25

Branch: `feat/phase-04-mcp-security-gateway`

Baseline: Phase 3 commit `f8840a02b89c4f81b00bde5b1af1c0ecce9eb097`

Scope: Phase 4 only. No Phase 5 work, merge, version change, publication, tag,
or release was performed. The Phase 4 branch was committed and pushed only
after separate owner authorization and final security review.

## Executive summary

Phase 4 adds an optional, in-process MCP client security adapter around the
official asynchronous Python SDK call path. It binds trusted configured server
identity to immutable default-deny tool policies, rechecks advertised tools on
every call, verifies approved schema fingerprints, validates the final
transformed payload, inspects supported responses, and emits value-free audit
events.

The final local suite contains 468 passing tests with 91.29% total statement
coverage. Focused MCP tests provide 93% coverage for the new integration
modules. An official MCP 2.3.0 `MCPServer`/`Client` in-memory round trip passed
and negotiated protocol version `2026-07-28`.

## Preflight and baseline

- Phase 3 local and remote branch commit:
  `f8840a02b89c4f81b00bde5b1af1c0ecce9eb097`.
- Phase 3 GitHub Actions run `40156479148`: completed successfully with all 15
  jobs passing.
- Phase 4 branch was created from that exact clean baseline.
- Baseline result: 441 passed, 0 failed, 0 skipped; 90.82% coverage.

## Architecture and execution flow

`MCPGateway` wraps a client exposing the official async `list_tools` and
`call_tool` methods. It does not construct or authenticate a transport. An
`MCPServerIdentity` supplied by trusted application configuration must match the
`MCPGatewayPolicy.server_id`; server-provided display metadata is never used as
identity.

For each call:

1. Validate safe correlation and exact tool-name syntax.
2. Resolve the configured per-tool policy; unknown tools are denied and an
   explicit deny rule wins.
3. Refresh the first tool-list page and require exactly one exact name match.
4. Compare SHA-256 of canonical name/input-schema/output-schema JSON with the
   approved fingerprint.
5. Copy the input, apply PII/secrets transformation, validate only the
   explicitly configured SQL argument, execute immutable custom hooks, and
   validate the exact final payload against the approved JSON Schema.
6. Emit the pre-forward authorization audit event and call the client with that
   exact payload under a timeout.
7. Require a complete `CallToolResult`, deep-copy it, remove response and text
   `_meta`, inspect supported text and structured content, and validate final
   structured content against the approved output schema.
8. Emit a response decision event and return the inspected copy.

There is no shared per-request mutable state. The tool list and schema are
rechecked for concurrent and subsequent calls, including after a simulated
reconnection/list change.

## Public API

```python
from guardrail_kit.integrations.mcp import (
    MCPGateway,
    MCPGatewayPolicy,
    MCPServerIdentity,
    MCPToolPolicy,
    fingerprint_tool_schema,
)

gateway = MCPGateway(
    client=trusted_client,
    identity=MCPServerIdentity(
        "analytics-prod",
        "streamable-http",
        "https://mcp.example.internal",
        "application-verified-tls",
    ),
    policy=MCPGatewayPolicy(
        server_id="analytics-prod",
        tools={
            "read_database": MCPToolPolicy(
                approved_schema_fingerprint=fingerprint_tool_schema(approved_tool),
                sql_validator=validator,
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

Schema enrollment is intentionally external and trusted. Operators inspect a
discovered schema and explicitly store its fingerprint. A changed or newly
discovered tool is never silently trusted.

## Implemented security controls

- Trusted configured server identifier separate from malicious display data.
- Default-deny exact per-server tool authorization and explicit deny rules.
- Immutable copied policy mappings and per-call copied JSON-like arguments.
- Schema fingerprint bound to exact tool name, input schema, and output schema.
- Canonical JSON with sorted keys, compact separators, UTF-8, and non-finite
  number rejection.
- Tool-list refresh and fingerprint comparison immediately before payload
  inspection and forwarding.
- PII/secrets transformation before final SQL and JSON Schema validation.
- SQL inspection only for an explicitly configured top-level argument.
- Immutable custom hook input and fail-closed hook exceptions.
- Value-free gateway errors for policy, schema, timeout, discovery, and
  transport failures.
- Supported text/structured response blocking or redaction.
- Output-schema validation after response transformation.
- Untrusted response/result text `_meta` removal.
- Non-text response denial by default, with explicit pass-through risk option.
- Configurable timeout, caller cancellation propagation, and concurrency tests.
- Safe audit events with validated correlation ID, trusted identifiers, reason,
  decision, duration, and schema fingerprint only.
- Mandatory audit mode blocks before forwarding when its authorization event
  cannot be recorded.

## Confirmed findings and fixes

### P4-01 — Falsy non-mapping arguments could be normalized to an empty mapping

Severity: Medium

During adversarial review, `arguments or {}` would have converted an empty list
or other falsy unsupported object into `{}`. A permissive zero-property schema
could then authorize a value that was not the submitted argument type.

Fix: only `None` means omitted arguments. Every other value is copied and must
remain a dictionary before forwarding. Regression coverage submits an empty
list and confirms zero execution.

### P4-02 — Untrusted identifiers could enter audit telemetry

Severity: Low

Caller-controlled correlation IDs and unconfigured tool names were initially
eligible for direct inclusion in audit events. This could place sensitive or
hostile strings in telemetry.

Fix: correlation IDs and tool names use bounded ASCII syntax. Invalid
correlations are replaced by an internally generated ID for the block event;
unconfigured tool names are not recorded. Tests confirm a synthetic sensitive
correlation value is absent from audit representations.

### P4-03 — Uninspected MCP `_meta` could carry sensitive response values

Severity: Medium

Text and structured response content was inspected, but result/content `_meta`
was initially preserved without inspection.

Fix: gateway-returned result and text content metadata are stripped. Unsupported
non-text content remains denied unless explicitly accepted without inspection.

### P4-04 — Approved output schema was fingerprinted but not enforced

Severity: Medium

The initial response path bound authorization to an output schema fingerprint
without validating the returned structured content against that schema.

Fix: final transformed structured content is validated against the approved
output schema. Invalid response schemas and input-required states fail closed.

All findings were fixed before final verification. No unresolved authorization
bypass remains in the verified execution path.

## Tests and coverage

Final full command:

```bash
GUARDRAIL_KIT_REQUIRE_ADK=1 .venv/bin/python -m pytest \
  --cov=guardrail_kit --cov-report=term-missing --cov-fail-under=75
```

Result: 468 passed, 0 failed, 0 skipped in 2.53 seconds, with one non-failing
upstream Google ADK experimental JSON-schema warning. Coverage was 91.29%
(1,562 statements, 136 missed).

Focused MCP result: 26 synthetic gateway/adversarial tests passed with 93%
combined MCP module coverage. One additional official-SDK in-memory test passed.

Coverage includes allowed and denied calls, unknown tools/servers, explicit
deny, malformed names and arguments, schema drift, duplicate tool identity,
input and output schema failures, final transformed SQL, PII input/output
redaction and blocking, custom hook mutation/error, text/structured/non-text
responses, response metadata removal, transport and discovery errors,
concurrent requests, tool-list changes, timeout, cancellation, mandatory and
best-effort audit behavior, safe error/audit representations, and direct-client
bypass demonstration.

## MCP SDK compatibility

```text
Python             3.12.15
mcp                2.3.0
mcp-types          2.3.0
Negotiated MCP     2026-07-28 (official in-memory test)
SQLGlot            30.24.0
Google ADK         2.12.0
langchain-core     1.7.0
langgraph          1.2.17
pytest             9.1.1
coverage           7.17.0
Ruff               0.17.2
mypy               1.20.2
build              1.6.1
Twine              6.2.0
```

The optional constraint is `mcp>=2.3,<3`. CI includes exact lower-bound 2.3.0
and resolver-selected latest-compatible jobs. This does not claim that every
intermediate 2.x release was individually tested.

## Quality gates

- Ruff: passed.
- Strict mypy: passed for 42 source files.
- Build: wheel and source distribution built successfully.
- Twine: both distributions passed validation.
- Fresh core wheel: installed without MCP and passed SQL smoke validation.
- Fresh `[mcp]` wheel: installed MCP 2.3.0 and passed fingerprint/policy smoke.
- `git diff --check`: passed.
- Package version remains `0.1.0`; Python remains `>=3.11`.

No live external MCP service, production database, or real credential was used.

## Files created

- `src/guardrail_kit/integrations/mcp/__init__.py`
- `src/guardrail_kit/integrations/mcp/audit.py`
- `src/guardrail_kit/integrations/mcp/exceptions.py`
- `src/guardrail_kit/integrations/mcp/gateway.py`
- `src/guardrail_kit/integrations/mcp/identity.py`
- `src/guardrail_kit/integrations/mcp/inspection.py`
- `src/guardrail_kit/integrations/mcp/policy.py`
- `src/guardrail_kit/integrations/mcp/schema.py`
- `tests/integration/test_mcp_gateway.py`
- `tests/integration/test_mcp_sdk.py`
- `tests/security/test_mcp_adversarial.py`
- `examples/mcp_gateway.py`
- `docs/mcp.md`
- `PHASE_04_REPORT.md`

## Files modified

- `.github/workflows/ci.yml`
- `pyproject.toml`
- `README.md`
- `docs/architecture.md`
- `docs/security.md`
- `docs/roadmap.md`
- `CHANGELOG.md`

## Known bypasses and limitations

- Direct use of the underlying MCP client bypasses the gateway by design.
- The configured identity describes an external trust binding; the gateway does
  not authenticate processes, TLS peers, bearer tokens, or network endpoints.
- MCP calls do not carry the approved schema fingerprint. A malicious server
  can change implementation behavior after tool discovery without changing its
  advertised schema; least privilege and server isolation remain required.
- Only the first `list_tools` page is checked. Later-page tools are rejected
  conservatively rather than fetched.
- Only official async `list_tools`/`call_tool` and in-memory transport were
  integration-tested. Stdio, SSE, streamable HTTP, reconnection authentication,
  and session hijacking defenses remain outside the gateway.
- Images, audio, binary resources, links, embedded resources, streaming, and
  input-required flows are unsupported and blocked by default. Explicit
  non-text pass-through is uninspected.
- Dictionary keys and arbitrary Python objects are not PII-inspected; approved
  JSON Schema and custom hooks must constrain them.
- PII/secrets detection retains unavoidable false positives and negatives.
- Response filtering cannot undo side effects and does not provide complete
  response-based prompt-injection defense.
- Canonical fingerprints establish byte-stable canonical JSON identity, not
  semantic equivalence or safety of a JSON Schema.
- Best-effort audit can lose events. Mandatory post-call audit failure blocks
  the response but cannot undo the server call.
- This phase is not a standalone proxy, sandbox, vault, DLP system, or network
  security control.

## Phase 5 readiness

Phase 4 is ready for owner review. Phase 5 has not started. The owner separately
authorized committing and pushing this reviewed Phase 4 branch; no merge,
release, publication, or Phase 5 work was authorized.
