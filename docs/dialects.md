# SQL dialect support

`dialects.py` is the authoritative, closed registry. A dialect being available in SQLGlot does not make it accepted by guardrail-kit. Values and aliases are exact: whitespace-padded, case-modified, empty, non-string, and unknown values are rejected. The policy resolves the value once and reuses the immutable specification for parsing and authorization.

## Supported matrix

| Database | Canonical value | Aliases | Identifier behavior | Security tests | Status | Known limitations |
| --- | --- | --- | --- | --- | --- | --- |
| PostgreSQL | `postgres` | `postgresql` | Unquoted names fold lowercase; quoted names preserve case | Adversarial matrix | **Supported** | Search path, overloads, and server privileges are external |
| SQLite | `sqlite` | `sqlite3` | Names compare case-insensitively | Adversarial matrix | **Supported** | Attached schemas and extensions remain external controls |
| MySQL | `mysql` | — | Tables and aliases exact; columns/functions insensitive | Adversarial matrix | **Supported** | Conservative across platform and `lower_case_table_names` |
| SQL Server | `tsql` | `mssql`, `sqlserver` | Exact for tables, columns, aliases, and functions | Adversarial matrix | **Supported** | Conservative across server/database catalog collations |
| Oracle Database | `oracle` | — | Unquoted names uppercase; quoted names preserve case | Adversarial matrix | **Supported** | Synonyms and database links are not resolved |
| DuckDB | `duckdb` | — | Quoted and unquoted identifiers compare case-insensitively | Adversarial matrix | **Supported** | External access through functions requires explicit function allowance |
| Snowflake | `snowflake` | — | Unquoted names uppercase; quoted names preserve case | Adversarial matrix | **Supported** | Non-default `QUOTED_IDENTIFIERS_IGNORE_CASE` is handled conservatively |
| Google BigQuery | `bigquery` | — | Table paths exact; columns/aliases insensitive; functions exact | Adversarial matrix | **Supported** | Conservative for datasets configured case-insensitive |
| Amazon Redshift | `redshift` | — | Unquoted names lowercase; quoted names preserve case | Adversarial matrix | **Supported** | Conservative across `enable_case_sensitive_identifier` settings |
| Databricks SQL | `databricks` | — | Exact matching | Adversarial matrix | **Supported** | Conservative across catalogs and analyzer configuration |
| Spark SQL | `spark` | — | Exact matching | Adversarial matrix | **Supported** | Conservative across analyzer/catalog configuration |

## Deliberately restricted behavior

All supported dialects accept only one structurally inspected `SELECT`. Set operations, recursive CTEs, locking reads, table hints, `SELECT INTO`, transaction/control commands, and unknown AST forms are blocked. Joins, subqueries, and non-recursive CTEs require explicit policy flags. Under column restrictions, `JOIN ... USING` is authorized against every participating source, `NATURAL JOIN` is rejected, and wildcards such as `table.*` and `COUNT(*)` are rejected wherever they occur. Pagination must be a positive integer literal and forms such as `PERCENT` or `WITH TIES` are rejected because they do not provide the configured absolute row bound.

CTEs with declared output-column lists may be conservatively rejected when column authorization cannot safely map the renamed outputs back to validated source columns. For example:

```sql
WITH t(join_id) AS (
    SELECT id FROM teams
)
SELECT u.join_id
FROM users u
JOIN t USING (join_id)
```

Rejection of this form is fail-closed compatibility behavior, not a determination that the query is malicious. Applications should not assume it will be accepted under a restricted column policy unless the output mapping is supported and covered by the application's tests. This limitation is distinct from an authorization bypass: the validator denies an unresolved query instead of authorizing it.

Other SQLGlot dialects—including Athena, ClickHouse, Hive, Presto/Trino, Teradata, and engine-specific variants—are currently **Unsupported**. Their names are rejected during policy construction because their security-relevant identifier, external-source, command, and function semantics have not completed this library's adversarial review. None are marked experimental in version 0.1.0.

These tests exercise parser and authorization behavior, not live database servers. SQLGlot parsing is structural validation, not proof that a statement will execute or that a database will enforce read-only access. Use least-privilege database identities, fixed schema/search paths, tenant and row-level controls, statement/resource limits, and database auditing.
