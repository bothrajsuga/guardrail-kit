# Security model

The validator is a fail-closed structural policy layer. It accepts one supported read-only `SELECT`, validates every physical table, requires an explicit allowlist for database functions, resolves restricted columns conservatively, and applies structural and resource-oriented rules. It never connects to a database.

It is not a SQL sandbox, query cost estimator, injection detector, prompt-injection defense, or substitute for database authorization. SQLGlot parsing alone does not establish safety. Use a dedicated read-only database account with explicit grants, parameterized values, database statement and lock timeouts, row/resource limits, network restrictions, and monitoring. Consider a database proxy or allowlisted stored interface for higher-risk systems.

Raw SQL can contain secrets. The library does not log it. Normalized SQL is opt-in and is returned only to the caller; applications must treat it as sensitive. Audit metadata should contain opaque correlation identifiers only.

PostgreSQL, SQLite, and MySQL are tested dialects. The dialect registry accepts only their documented exact names and aliases. Unsupported or ambiguous AST shapes fail closed. Column restrictions reject wildcards and ambiguous multi-source unqualified references. This intentionally trades SQL coverage for predictable enforcement.

Unexpected internal validation exceptions are converted to a `validation_error` block result. Process-control exceptions such as `KeyboardInterrupt` and `SystemExit` are not intercepted. Safe public results do not contain the input SQL or internal exception details.

PostgreSQL quoted identifiers preserve case and unquoted identifiers fold to lowercase. SQLite identifiers are handled case-insensitively. MySQL columns and routines are case-insensitive, while database/table and table-alias spellings are compared exactly because their server-side behavior varies with platform and `lower_case_table_names`. The MySQL rule is deliberately conservative and may produce false negatives.

Schema-qualify tables and functions and control database-specific name-resolution settings when identity is security-sensitive. Function overload identity is not available to this structural validator. SQLGlot parser acceptance is not proof that the target database will accept or safely execute a statement.

Google ADK callback ordering allows later callbacks to change arguments. The provided guarded-tool wrapper therefore validates again inside the protected tool's `run_async` boundary. The callback/plugin APIs are retained for early rejection and must not be used alone as the database execution boundary.

The guarded wrapper rejects ADK tools with custom `process_llm_request` implementations. ADK may use that hook to register a different underlying tool, which would bypass the wrapper. Wrap the final database callable as a `FunctionTool`, or provide a purpose-built guarded implementation for such specialized tools.

The guarded wrapper is verified against Google ADK 2.12.0 and uses its private `_get_declaration` method to preserve wrapper registration. Other ADK versions, including streaming/live execution behavior, are outside the verified integration surface.

