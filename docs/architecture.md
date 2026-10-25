# Architecture

The core package defines immutable context, decision, result, and guardrail contracts without importing an agent framework. SQL policy and validation depend only on SQLGlot. Integrations translate framework lifecycle calls into core validation and translate a block into a framework-native response. Audit events contain decisions and non-sensitive metadata, never raw input.

The PII and secrets guard follows the same boundary without altering `SQLValidator` or importing SQLGlot into its detector modules. `PIIDetector` and `SecretDetector` produce value-free, immutable spans. `PIIGuard` combines those spans, applies exclusions, resolves overlap during transformation, and returns a privacy-aware `PIIResult`. Policies are immutable after dialect-independent validation. Framework dependencies remain optional and isolated under `integrations`.

The LangChain adapter constructs a schema-preserving `StructuredTool` whose
sync and async callables copy and inspect arguments immediately before invoking
the protected tool. `ToolGuardPolicy` composes SQL validation, recursive
PII/secrets inspection, and immutable allow/block hooks. It holds no per-call
mutable state. Output inspection runs only after the protected operation. The
LangGraph helper admits only tools with explicit policies and places those same
wrappers in a `ToolNode`; it does not claim to guard an entire graph.

The MCP gateway is an in-process client adapter. Trusted server identity and
immutable tool policies form the authorization boundary. Every call refreshes
the advertised tool list, matches one exact configured name, verifies the
approved schema fingerprint, transforms a copied payload, validates the final
payload, and only then forwards it. Supported responses are copied, stripped of
untrusted metadata, inspected, and output-schema validated. Audit events contain
decision metadata only. Transport creation and authentication remain outside
the adapter.

Detection, policy, and transformation are intentionally separate. Detectors identify candidates and original-input offsets. Policy selects enabled entity families, regional phone rules, custom/exclusion patterns, input bounds, secret heuristics, and the action. Masking/redaction operates from the end-user text and spans without putting matched values in metadata. Unexpected detector exceptions are converted to a block result.

SQL dialect support is closed and explicit. `guardrail_kit.sql.dialects` resolves each accepted canonical name or documented alias to one immutable `DialectSpec`. The specification records SQLGlot mapping, quoting, identifier cases by kind, qualification order, pagination, blocked complex constructs, and support status. The policy stores that resolved specification once, and parsing, identifier handling, function matching, normalization, and validation all consume it. Adding a SQLGlot dialect does not make it supported automatically; it requires an explicit specification, database-specific identifier rules, adversarial tests, and documentation.

Validation walks the complete parsed statement and every optimizer scope before authorization succeeds. It rejects non-`SELECT` roots, nested DML/DDL, commands, multiple statements, `SELECT INTO`, table hints, locking reads, set operations, and recursive CTEs. Physical sources are checked against table policies; derived outputs and aliases are resolved scope-by-scope. Unknown source or identifier shapes fail closed.

