# Security model

The validator is a fail-closed structural policy layer. It accepts one supported read-only `SELECT`, validates every physical table, requires an explicit allowlist for database functions, resolves restricted columns conservatively, and applies structural and resource-oriented rules. It never connects to a database.

It is not a SQL sandbox, query cost estimator, injection detector, prompt-injection defense, or substitute for database authorization. SQLGlot parsing alone does not establish safety. Use a dedicated read-only database account with explicit grants, parameterized values, database statement and lock timeouts, row/resource limits, network restrictions, and monitoring. Consider a database proxy or allowlisted stored interface for higher-risk systems.

Raw SQL can contain secrets. The library does not log it. Normalized SQL is opt-in and is returned only to the caller; applications must treat it as sensitive. Audit metadata should contain opaque correlation identifiers only.

PostgreSQL, SQLite, MySQL, SQL Server/T-SQL, Oracle, DuckDB, Snowflake, BigQuery, Redshift, Databricks SQL, and Spark SQL have dialect-specific identifier and adversarial test coverage. The closed registry accepts only documented exact names and aliases. Unsupported or ambiguous AST shapes fail closed. Column restrictions reject wildcards and ambiguous multi-source unqualified references. This intentionally trades SQL coverage for predictable enforcement.

Case rules that depend on deployment configuration use conservative exact matching. This affects MySQL table names, SQL Server collations, BigQuery dataset options, Redshift case-sensitive identifiers, and Databricks/Spark catalog or analyzer settings. Such matching can block a query the server would accept, but does not deliberately equate two names that the server might treat as different. Applications must keep those settings stable and align allowlists with the deployed catalog.

With column restrictions enabled, `JOIN ... USING` columns are authorized against every participating source, including accumulated sources in chained joins. Derived tables and CTEs must expose the joined column through an already-validated output. `NATURAL JOIN` is blocked because its implicit column set depends on database schema. Wildcards are blocked throughout expressions, including function arguments such as `COUNT(*)`. These restrictions do not apply when no column policy is configured.

An explicit CTE output-column list can rename derived outputs in a way the validator cannot safely resolve back to authorized source columns. Such a query may therefore be rejected conservatively under column restrictions even when a database would execute it. This is a fail-closed compatibility limitation, not evidence that the query is malicious and not an authorization bypass; see the example in the [dialect support notes](dialects.md#deliberately-restricted-behavior).

Unexpected internal validation exceptions are converted to a `validation_error` block result. Process-control exceptions such as `KeyboardInterrupt` and `SystemExit` are not intercepted. Safe public results do not contain the input SQL or internal exception details.

PostgreSQL quoted identifiers preserve case and unquoted identifiers fold to lowercase. SQLite identifiers are handled case-insensitively. MySQL columns and routines are case-insensitive, while database/table and table-alias spellings are compared exactly because their server-side behavior varies with platform and `lower_case_table_names`. The MySQL rule is deliberately conservative and may produce false negatives.

Schema-qualify tables and functions and control database-specific name-resolution settings when identity is security-sensitive. Function overload identity is not available to this structural validator. SQLGlot parser acceptance is not proof that the target database will accept or safely execute a statement.

The validator does not establish tenant isolation, row-level security, schema/search-path safety, database permissions, function overload identity, or query-cost bounds. Enforce those controls in the database and connection layer. No live database-server compatibility is claimed by the parser-based test matrix.

Google ADK callback ordering allows later callbacks to change arguments. The provided guarded-tool wrapper therefore validates again inside the protected tool's `run_async` boundary. The callback/plugin APIs are retained for early rejection and must not be used alone as the database execution boundary.

The guarded wrapper rejects ADK tools with custom `process_llm_request` implementations. ADK may use that hook to register a different underlying tool, which would bypass the wrapper. Wrap the final database callable as a `FunctionTool`, or provide a purpose-built guarded implementation for such specialized tools.

The guarded wrapper supports Google ADK 2.0.0 and later through a centralized BaseTool capability adapter and uses the private `_get_declaration` method to preserve wrapper registration. Capability checks reject incompatible APIs before a tool can be exposed. Representative releases are tested; future releases are not considered verified until the latest-version CI job passes. Streaming/live execution remains outside the verified integration surface.

