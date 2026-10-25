# Phase 1 Core Security Audit, Hardening, and Test Coverage

Date: 2026-10-25

Branch: `feat/phase-01-security-hardening`

Starting commit: `ff80f4e` (`ci: verify release tag matches package version`)
Scope: Phase 1 only; no production SQL was executed and no package publish or release was performed. The Phase 1 branch was committed and pushed only after the owner separately reviewed the result and authorized those Git actions.

## Executive summary

The audit confirmed two related medium-severity CTE policy bypasses and one low-severity configuration ambiguity. A CTE nested inside a derived table could bypass `allow_ctes=False`, and a recursively marked CTE at that nesting depth could bypass the library-wide recursive-CTE prohibition. Separately, distinct `allowed_columns` table keys that normalized to the same dialect identifier silently overwrote one another.

All three findings are fixed with narrow, API-compatible changes. Regression tests cover every registered dialect. The complete suite, including the installed Google ADK 2.12.0 execution-boundary tests, passes with 85.29% statement coverage.

No critical or high-severity authorization bypass was confirmed. Physical table allowlists still caught disallowed tables inside the nested CTE reproducer, so the CTE findings bypassed structural policy controls rather than the physical table allowlist.

## Threat model and trust boundaries

Attacker-controlled inputs include SQL text, identifier spelling and quoting, aliases, qualification, nesting, CTEs, joins, wildcards, functions, pagination syntax, multiple statements, dialect-specific constructs, and Google ADK tool argument mappings.

Security-sensitive boundaries reviewed:

1. `SQLPolicy` construction converts operator-controlled configuration into immutable, dialect-normalized allowlists. Invalid or ambiguous configuration must raise `ConfigurationError`.
2. `SQLValidator.validate` parses exactly one statement using the policy's resolved dialect, walks the AST and optimizer scopes, and must return a block result on parse, resolution, or validation errors.
3. Table, column, function, alias, derived-output, join, subquery, and CTE authorization must account for every nesting level without guessing ambiguous identity.
4. `create_guarded_google_adk_tool` must validate immediately inside `run_async` and pass the same validated argument mapping to the protected tool. Validation rejection or exception must prevent invocation.
5. The database remains a separate trust boundary. The library never executes SQL and cannot replace read-only credentials, grants, row-level controls, fixed search paths, timeouts, resource governance, or audit logging.

## Baseline evidence

Initial working tree: clean `main`, matching `origin/main` at `ff80f4e`.

Command:

```bash
.venv/bin/python -m pytest --cov=guardrail_kit --cov-report=term-missing \
  --cov-report=json:phase01-baseline-coverage.json --cov-fail-under=75
```

Result: 312 collected; 280 passed and 32 skipped in 0.63 seconds. Coverage was 78.71%. The skipped tests reported that the Google ADK extra was unavailable because imports from the existing environment were incomplete at collection time.

Commands and results:

```text
.venv/bin/python -m ruff check .    -> passed
.venv/bin/python -m mypy src        -> passed; 19 source files
```

The project-declared `.[dev,google-adk]` extra was then installed into the local virtual environment. Google ADK 2.12.0 integration tests ran rather than skipping: 36 passed with one upstream experimental-feature warning.

## Findings and remediation

### P1-01 — Nested CTE bypassed `allow_ctes=False`

Severity: **Medium**

Status: **Fixed**

Reproducer before remediation:

```sql
SELECT d.id
FROM (
  WITH x AS (SELECT id FROM users)
  SELECT id FROM x
) AS d
```

With `allow_subqueries=True` and `allow_ctes=False`, this returned `query_allowed`. The validator checked only the root expression's `with_` argument even though optimizer scope traversal included the nested query.

Remediation: collect and inspect every `exp.With` node in the complete expression tree. Any CTE now yields `cte_not_allowed` when CTEs are disabled.

Regression coverage: `test_nested_ctes_cannot_bypass_cte_policy_for_any_dialect`, parameterized across PostgreSQL, SQLite, MySQL, T-SQL, Oracle, DuckDB, Snowflake, BigQuery, Redshift, Databricks, and Spark.

### P1-02 — Nested recursive CTE bypassed the global prohibition

Severity: **Medium**

Status: **Fixed**

Reproducer before remediation:

```sql
SELECT d.id
FROM (
  WITH RECURSIVE x AS (SELECT id FROM users)
  SELECT id FROM x
) AS d
```

With subqueries enabled, this returned `query_allowed` even though all registered dialect specifications mark recursive CTEs unsupported.

Remediation: inspect the recursive flag on every `exp.With` node before applying the ordinary CTE policy. A recursive CTE at any depth now returns `unsupported_construct`.

Regression coverage: `test_nested_recursive_ctes_are_rejected_for_every_dialect`, parameterized across all registered dialects.

### P1-03 — Normalized column-policy table keys could silently collide

Severity: **Low**

Status: **Fixed**

Reproducer before remediation, using SQLite's case-insensitive identifier policy:

```python
SQLPolicy(
    dialect="sqlite",
    allowed_tables={"users"},
    allowed_columns={"users": {"id"}, '"USERS"': {"secret"}},
)
```

Both keys normalized to `users`; the latter silently replaced the former, making authorization dependent on mapping insertion order.

Remediation: policy construction now raises `ConfigurationError` when multiple column-policy keys normalize to the same table identifier.

Regression coverage: `test_policy_rejects_column_table_keys_that_collide_after_normalization`.

## Audit results without confirmed defects

- Exactly one SQL statement is required; parse errors and unexpected validation exceptions fail closed without returning raw SQL.
- Only a `SELECT` root is accepted. Nested DML/DDL, transaction operations, commands, `SELECT INTO`, locking reads, table hints, and set operations remain denied.
- Physical table allowlists remained effective in nested CTE and derived-table probes, including the pre-fix nested CTE case.
- Restricted columns, aliases, qualified sources, `JOIN ... USING`, restricted `NATURAL JOIN`, nested wildcards, and derived outputs are resolved conservatively or denied.
- The closed dialect registry and the same immutable dialect specification are used for parsing and identifier authorization.
- External/dangerous dialect probes (`COPY ... TO PROGRAM`, `pg_read_file`, MySQL `INTO OUTFILE`, T-SQL `OPENROWSET`, SQLite `PRAGMA`, DuckDB `read_csv`, Snowflake stage access, BigQuery `EXTERNAL_QUERY`, and Databricks/Spark file sources) were denied under a `users`-only policy. These probes do not replace live-server tests.
- Google ADK 2.12.0 tests confirmed execution-boundary revalidation, exact mapping identity, missing/invalid argument rejection, exception fail-closed behavior, custom registration rejection, and post-callback mutation blocking. No ADK execution bypass was reproduced.

## Final verification

Environment versions:

```text
Python      3.12.15
SQLGlot     30.24.0
Google ADK  2.12.0
pytest      9.1.1
pytest-cov  7.1.0
coverage    7.17.0
Ruff        0.17.2
mypy        1.20.2
build       1.6.1
Twine       6.2.0
```

Executed commands:

```bash
GUARDRAIL_KIT_REQUIRE_ADK=1 .venv/bin/python -m pytest \
  --cov=guardrail_kit --cov-report=term-missing \
  --cov-report=json:phase01-final-coverage.json --cov-fail-under=75
.venv/bin/python -m ruff check .
.venv/bin/python -m mypy src
.venv/bin/python -m build
.venv/bin/python -m twine check dist/*
git diff --check
```

Results:

- Tests: **335 passed, 0 failed, 0 skipped** in 1.92 seconds.
- Warning: one Google ADK warning for its experimental JSON-schema feature; no test failure.
- Coverage: **85.29%** overall (639 statements, 94 missed), above the 75% threshold.
- Ruff: passed.
- Strict mypy: passed for 19 source files.
- Build: source distribution and wheel built successfully.
- Twine: both distributions passed validation.
- Diff integrity: passed.

## Files changed

- `src/guardrail_kit/sql/validator.py`
- `src/guardrail_kit/sql/policy.py`
- `tests/security/test_dialect_security.py`
- `tests/unit/test_policy.py`
- `docs/security.md`
- `PHASE_01_REPORT.md`

## Known limitations and remaining risks

- Parser-based tests do not prove live behavior on all supported database servers or deployment-specific collation/catalog settings.
- SQL authorization is defense in depth, not a database sandbox. Explicitly allowlisted functions may still have side effects or sensitive-data access depending on database grants and overload resolution.
- `LIMIT` bounds outer result rows, not scan volume, intermediate rows, CPU, memory, locks, or runtime.
- The validator does not provide tenant isolation, row-level security, schema/search-path safety, parameter binding, prompt-injection protection, or query-cost estimation.
- MySQL table casing, SQL Server collation, BigQuery dataset options, Redshift identifier settings, and Databricks/Spark catalogs require deployment-aligned allowlists.
- Google ADK relies on the private `_get_declaration` capability. Only representative releases and the locally installed 2.12.0 were verified here; streaming/live execution remains unsupported.
- Coverage remains intentionally low in placeholder audit/policy modules and some defensive/error branches. Security-critical SQL validator and ADK paths have substantially higher coverage, but coverage alone is not proof of absence of vulnerabilities.

## Phase 2 readiness

**Ready for Phase 1 branch review.** The confirmed Phase 1 defects are remediated and all required local checks pass. Phase 2 has not started. The owner separately authorized committing and pushing this Phase 1 branch after the audit; no release was authorized or performed.
