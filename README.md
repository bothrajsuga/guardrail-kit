# guardrail-kit

`guardrail-kit` is a framework-independent Python toolkit for applying explicit policies to AI-generated operations. It provides structural SQL validation, deterministic PII and secret inspection, and optional Google Agent Development Kit (ADK) integration. It inspects content but does not execute SQL or verify a person's identity.

> Alpha software and one defense-in-depth layer—not a complete security boundary. Always use a read-only database identity, least-privilege grants, statement timeouts, resource limits, and database-side auditing.

## Install

Python 3.11–3.14 is supported.

```bash
pip install guardrail-kit
pip install 'guardrail-kit[google-adk]'  # optional ADK 2.0+ integration
```

## Inspect PII and secrets

```python
from guardrail_kit.pii import PIIGuard, PIIPolicy

guard = PIIGuard(PIIPolicy(action="redact"))
result = guard.inspect("Contact john@example.com")

print(result.output_text)  # Contact [REDACTED]
```

The safe default action is `block`. Explicit actions are `allow`, `block`, `mask`, and `redact`. Detection covers email addresses, configured regional phone formats, validated IP addresses, Luhn-valid payment-card candidates, format-valid Indian PAN candidates, checksum-valid Aadhaar candidates, configured custom identifiers, and common synthetic secret formats. High-entropy candidates are disabled by default and remain heuristic even when explicitly enabled.

Matches contain entity types and half-open offsets into the original input, never matched values. `PIIResult.to_safe_dict()` omits all text. `output_text` is intentionally available to the direct caller and can contain original input with the explicit `allow` action; never log it blindly. Custom regular expressions are configuration, not untrusted runtime input, and are subject to length and construct restrictions. See the [PII and secrets example](examples/pii_secrets_guard.py) and [security limitations](docs/security.md#pii-and-secrets-threat-model).

## Validate SQL

```python
from guardrail_kit import SQLPolicy, SQLValidator

validator = SQLValidator(
    SQLPolicy(
        dialect="postgres",
        allowed_tables={"analytics.orders"},
        allowed_columns={"analytics.orders": {"id", "total"}},
        unlisted_table_columns="block",
        require_limit=True,
        max_limit=100,
    )
)

result = validator.validate("SELECT id, total FROM analytics.orders LIMIT 25")
if not result.allowed:
    print(result.reason_code, result.message)
```

The default policy fails closed: it has no table allowlist and therefore blocks queries until `allowed_tables` is explicitly configured. An empty allowlist permits table-free queries such as `SELECT 1`. Database functions are blocked unless named in `allowed_functions`; this matters because some databases permit volatile or side-effecting functions inside `SELECT`. Joins, subqueries, and CTEs are disabled by default. Multiple statements, writes (including writes nested in CTEs), DDL, `SELECT INTO`, locking reads, unresolved column scopes, and unsupported structures are blocked. Normalized SQL is omitted unless `include_normalized_sql=True`.

`allowed_columns` is per table. For backward compatibility, an allowed table omitted from that mapping has unrestricted columns. Set `unlisted_table_columns="block"` for the safer exhaustive mode, in which every referenced table must have an explicit column entry. An explicitly empty column set permits no named columns. Wildcards are blocked whenever column restrictions or exhaustive mode are active.

`SQLPolicy` resolves a configured dialect through a closed registry. Canonical names and the documented aliases below are accepted exactly; whitespace-padded, case-modified, unknown, and unlisted SQLGlot dialect names are rejected rather than guessed or trimmed.

| Database | Dialect | Aliases | Identifier behavior | Security tests | Status | Known limitation |
| --- | --- | --- | --- | --- | --- | --- |
| PostgreSQL | `postgres` | `postgresql` | Lowercase unquoted; preserve quoted | Yes | Supported | Search path remains database-controlled |
| SQLite | `sqlite` | `sqlite3` | Case-insensitive | Yes | Supported | Attached database identity is not inspected |
| MySQL | `mysql` | — | Exact tables/aliases; insensitive columns/functions | Yes | Supported | Conservative across `lower_case_table_names` modes |
| SQL Server | `tsql` | `mssql`, `sqlserver` | Exact matching | Yes | Supported | Conservative across catalog collations |
| Oracle | `oracle` | — | Uppercase unquoted; preserve quoted | Yes | Supported | Database links and synonyms are not resolved |
| DuckDB | `duckdb` | — | Case-insensitive, including quoted names | Yes | Supported | External table functions still require function allowlisting |
| Snowflake | `snowflake` | — | Uppercase unquoted; preserve quoted | Yes | Supported | Assumes default quoted-identifier behavior |
| BigQuery | `bigquery` | — | Exact table paths; insensitive columns/aliases | Yes | Supported | Conservative with case-insensitive datasets; UDF names are exact |
| Redshift | `redshift` | — | Lowercase unquoted; preserve quoted | Yes | Supported | Conservative across case-sensitive-identifier settings |
| Databricks SQL | `databricks` | — | Exact matching | Yes | Supported | Conservative across catalog/analyzer settings |
| Spark SQL | `spark` | — | Exact matching | Yes | Supported | Conservative across analyzer/catalog settings |

Set operations, recursive CTEs, table hints, locking reads, and `SELECT INTO` remain blocked for every dialect. See the [full dialect support notes](docs/dialects.md), including intentionally unsupported SQLGlot dialects.

MySQL's exact-spelling table rule can reject a query that the configured server would resolve successfully, but it avoids treating differently cased tables as interchangeable on case-sensitive deployments. Applications should use a consistent table-name convention and validate their actual server configuration.

Column rules are resolved per physical table and alias using the selected dialect's identifier rules. Policy names may use that dialect's quoting and schema qualification. Unqualified columns in multi-source scopes, wildcards under column restrictions, and derived columns that cannot be established are rejected rather than guessed. Set operations are intentionally unsupported in v0.1.0.

When column restrictions are active, every `JOIN ... USING` column must be allowed by both participating sources. This also applies to chained joins and derived or CTE sources. `NATURAL JOIN` is rejected because its implicit join columns cannot be authorized conclusively. Wildcards are rejected anywhere in the relevant expression tree, including `COUNT(*)` and qualified stars. Without column restrictions, existing wildcard and natural-join behavior is preserved.

Function policies accept unqualified or schema-qualified names. Unqualified names still depend on database-specific name resolution, and overloads cannot be distinguished structurally; use schema-qualified policy entries and controlled connection resolution settings where function identity is security-sensitive.

## Google ADK 2.0+

ADK's `before_tool_callback` returns `None` to continue or a dictionary to skip the tool and use that dictionary as its result:

```python
from guardrail_kit.integrations.google_adk import create_guarded_google_adk_tool

guarded_run_sql = create_guarded_google_adk_tool(run_sql, validator)

# LlmAgent(..., tools=[guarded_run_sql])
```

The wrapper validates inside the ADK tool's `run_async` execution boundary. The exact argument dictionary passed to the protected tool is the one validated; missing, malformed, rejected SQL, and validation exceptions produce a safe `guardrail_blocked` result without invoking it. The wrapper supports Python callables/ADK `FunctionTool` and ordinary `BaseTool` implementations that use ADK's standard request processing. Tools overriding `process_llm_request` are rejected because delegating that hook can cause ADK to register the unguarded underlying tool. A compatibility callback and plugin factory remain available for application-wide early rejection:

```python
from guardrail_kit.integrations.google_adk import create_google_adk_plugin

plugin = create_google_adk_plugin(validator, tool_names={"run_sql"})
# App(..., plugins=[plugin])
```

The plugin alone is not an execution boundary: ADK runs plugins before agent callbacks, so later callbacks can mutate an allowed argument. Use the guarded tool wrapper even when the plugin is installed. The optional dependency accepts `google-adk>=2.0.0`; representative releases are tested in CI and unknown future releases are capability-checked rather than claimed as verified. The wrapper relies on the private `_get_declaration` method because no verified public registration API preserves this execution boundary. Core imports do not require ADK. See [the executable example](examples/google_adk_integration.py) and [compatibility matrix](docs/google-adk.md). Streaming/live behavior is outside the verified surface.

## Security and privacy

Results use stable reason codes and safe messages. Raw SQL and matched sensitive values are not placed in result metadata, audit events, errors, or privacy-safe serialization. Direct output fields may contain caller-requested original or transformed content and must be handled as sensitive. Parsing and pattern matching are not proof that content is safe, and this library does not prevent prompt injection, every form of SQL injection, or every form of data loss. Parameterize SQL values and layer PII detection with access controls and DLP appropriate to the deployment.

Read [the security model](docs/security.md) and report vulnerabilities according to [SECURITY.md](SECURITY.md).

## Develop and release

```bash
python -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
.venv/bin/ruff check .
.venv/bin/mypy
.venv/bin/python -m build
.venv/bin/twine check dist/*
```

TestPyPI and trusted-publishing instructions are in [the contributing guide](CONTRIBUTING.md). Production publishing requires an explicit GitHub release and a separately configured PyPI trusted publisher. The name `guardrail-kit` returned 404 from PyPI on 2026-10-23; re-check it immediately before release because availability can change.

## Roadmap

The development branch includes the Phase 2 PII and secrets guard. Later phases may add framework adapters only after separate design and review; see [the roadmap](docs/roadmap.md).

Apache-2.0 licensed. Contributions are welcome—see [CONTRIBUTING.md](CONTRIBUTING.md).

