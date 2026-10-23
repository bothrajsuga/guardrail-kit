# guardrail-kit

`guardrail-kit` is a framework-independent Python toolkit for applying explicit policies to AI-generated operations. Version 0.1.0 validates SQL and optionally integrates with Google Agent Development Kit (ADK). It parses and inspects SQL; it never executes or repairs queries.

> Alpha software and one defense-in-depth layer—not a complete security boundary. Always use a read-only database identity, least-privilege grants, statement timeouts, resource limits, and database-side auditing.

## Install

Python 3.11–3.14 is supported.

```bash
pip install guardrail-kit
pip install 'guardrail-kit[google-adk]'  # optional ADK 2.12 integration
```

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

| Database | Status | Canonical value | Aliases | Identifier policy |
| --- | --- | --- | --- | --- |
| PostgreSQL | Supported | `postgres` | `postgresql` | Unquoted identifiers fold to lowercase; quoted identifiers preserve case. |
| SQLite | Supported | `sqlite` | `sqlite3` | Identifiers are compared case-insensitively; double-quoted identifiers are supported. |
| MySQL | Supported, conservative case mode | `mysql` | None | Columns and routines are case-insensitive. Database/table and table-alias spelling must match exactly because server behavior depends on `lower_case_table_names` and platform. Backtick quoting is supported. |
| Other SQLGlot dialects | Unsupported | — | — | Policy construction fails closed until dialect-specific security coverage is added. |

MySQL's exact-spelling table rule can reject a query that the configured server would resolve successfully, but it avoids treating differently cased tables as interchangeable on case-sensitive deployments. Applications should use a consistent table-name convention and validate their actual server configuration.

Column rules are resolved per physical table and alias using the selected dialect's identifier rules. Policy names may use that dialect's quoting and schema qualification. Unqualified columns in multi-source scopes, wildcards under column restrictions, and derived columns that cannot be established are rejected rather than guessed. Set operations are intentionally unsupported in v0.1.0.

Function policies accept unqualified or schema-qualified names. Unqualified names still depend on database-specific name resolution, and overloads cannot be distinguished structurally; use schema-qualified policy entries and controlled connection resolution settings where function identity is security-sensitive.

## Google ADK 2.12

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

The plugin alone is not an execution boundary: ADK runs plugins before agent callbacks, so later callbacks can mutate an allowed argument. Use the guarded tool wrapper even when the plugin is installed. The supported version is `google-adk==2.12.0`; the wrapper relies on ADK's private `_get_declaration` method, so other versions are not claimed as compatible. Core imports do not require ADK. See [the executable example](examples/google_adk_integration.py). Streaming/live behavior is outside the currently verified integration surface and must be tested in the host application.

## Security and privacy

Results use stable reason codes and safe messages. Raw SQL is not placed in result metadata, audit events, or errors. Opt-in normalization returns a canonical form to the direct caller and should not be enabled where SQL itself is sensitive. Parsing is not proof that a query is safe, and this library does not prevent prompt injection or every form of SQL injection. Parameterize values separately and never concatenate untrusted data.

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

Version 0.2.0 plans PII detection and masking. Later versions may add LangChain, LangGraph, and other adapters. These features are not present in v0.1.0; see [the roadmap](docs/roadmap.md).

Apache-2.0 licensed. Contributions are welcome—see [CONTRIBUTING.md](CONTRIBUTING.md).

