import pytest

from guardrail_kit.sql import SQLPolicy, SQLValidator, UnlistedColumnPolicy


def validator(**overrides: object) -> SQLValidator:
    values: dict[str, object] = {"allowed_tables": {"users"}, "max_limit": 100}
    values.update(overrides)
    return SQLValidator(SQLPolicy(**values))  # type: ignore[arg-type]


def test_requires_explicit_table_allowlist() -> None:
    result = SQLValidator(SQLPolicy()).validate("SELECT 1")
    assert not result.allowed
    assert result.reason_code == "table_allowlist_required"


def test_allows_read_only_query() -> None:
    assert validator().validate("SELECT id FROM users LIMIT 10").allowed


def test_functions_require_an_explicit_allowlist() -> None:
    assert validator().validate("SELECT pg_sleep(10)").reason_code == "function_not_allowed"
    assert validator(allowed_functions={"count"}).validate("SELECT COUNT(id) FROM users").allowed


def test_function_policy_preserves_quotes_and_schema() -> None:
    quoted = validator(allowed_functions={'"MyFunc"'})
    assert quoted.validate('SELECT "MyFunc"(id) FROM users').allowed
    assert quoted.validate("SELECT myfunc(id) FROM users").reason_code == "function_not_allowed"

    qualified = validator(allowed_functions={"public.f"})
    assert qualified.validate("SELECT public.f(id) FROM users").allowed
    assert qualified.validate("SELECT f(id) FROM users").reason_code == "function_not_allowed"


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT INTO users VALUES (1)",
        "UPDATE users SET id=2",
        "DELETE FROM users",
        "DROP TABLE users",
        "CREATE TABLE x (id INT)",
    ],
)
def test_blocks_non_select(sql: str) -> None:
    assert validator().validate(sql).reason_code == "statement_not_allowed"


def test_blocks_multiple_statements() -> None:
    result = validator().validate("SELECT id FROM users; DROP TABLE users")
    assert result.reason_code == "multiple_statements"


def test_table_and_schema_allowlist() -> None:
    checked = validator(allowed_tables={"analytics.users"})
    assert checked.validate("SELECT id FROM analytics.users").allowed
    assert checked.validate("SELECT id FROM public.users").reason_code == "table_not_allowed"


def test_columns_resolve_through_alias() -> None:
    checked = validator(allowed_columns={"users": {"id"}})
    assert checked.validate("SELECT u.id FROM users AS u").allowed
    assert checked.validate("SELECT u.secret FROM users AS u").reason_code == "column_not_allowed"


def test_postgres_quoted_table_and_schema_semantics() -> None:
    lower = validator(allowed_tables={"users"})
    assert lower.validate("SELECT id FROM users").allowed
    assert lower.validate('SELECT id FROM "users"').allowed
    assert lower.validate('SELECT id FROM "Users"').reason_code == "table_not_allowed"

    mixed = validator(allowed_tables={'"Analytics"."Users"'})
    assert mixed.validate('SELECT id FROM "Analytics"."Users"').allowed
    assert mixed.validate("SELECT id FROM analytics.users").reason_code == "table_not_allowed"


def test_postgres_quoted_column_and_alias_semantics() -> None:
    checked = validator(
        allowed_tables={'"Users"'},
        allowed_columns={'"Users"': {"id", '"ID"'}},
    )
    assert checked.validate('SELECT "U".id, "U"."ID" FROM "Users" AS "U"').allowed
    assert (
        checked.validate('SELECT "U"."Id" FROM "Users" AS "U"').reason_code == "column_not_allowed"
    )
    assert (
        checked.validate('SELECT u.id FROM "Users" AS "U"').reason_code == "column_scope_ambiguous"
    )


def test_quoted_policy_does_not_allow_distinct_unquoted_identifiers() -> None:
    checked = validator(
        allowed_tables={'"App"."Users"'},
        allowed_columns={'"App"."Users"': {'"ID"'}},
    )
    assert checked.validate('SELECT "U"."ID" FROM "App"."Users" AS "U"').allowed
    assert checked.validate("SELECT u.id FROM app.users AS u").reason_code == "table_not_allowed"
    assert (
        checked.validate('SELECT U.ID FROM "App"."Users" AS "U"').reason_code
        == "column_scope_ambiguous"
    )


def test_column_policy_for_omitted_and_explicitly_empty_tables() -> None:
    backward_compatible = validator(
        allowed_tables={"users", "secrets"}, allowed_columns={"users": {"id"}}
    )
    assert backward_compatible.validate("SELECT token FROM secrets").allowed

    strict = validator(
        allowed_tables={"users", "secrets"},
        allowed_columns={"users": {"id"}},
        unlisted_table_columns=UnlistedColumnPolicy.BLOCK,
    )
    assert strict.validate("SELECT token FROM secrets").reason_code == "column_policy_required"
    assert strict.validate("SELECT * FROM secrets").reason_code == "wildcard_not_allowed"

    empty = validator(allowed_columns={"users": set()})
    assert empty.validate("SELECT id FROM users").reason_code == "column_not_allowed"
    assert empty.validate("SELECT users.id FROM users").reason_code == "column_not_allowed"


def test_wildcard_is_blocked_with_column_policy() -> None:
    assert (
        validator(allowed_columns={"users": {"id"}}).validate("SELECT * FROM users").reason_code
        == "wildcard_not_allowed"
    )


def test_ambiguous_unqualified_join_column_fails_closed() -> None:
    checked = validator(
        allowed_tables={"users", "teams"},
        allowed_columns={"users": {"id"}, "teams": {"id"}},
        allow_joins=True,
    )
    assert (
        checked.validate("SELECT id FROM users u JOIN teams t ON u.id=t.id").reason_code
        == "column_scope_ambiguous"
    )


def test_qualified_join_columns_are_allowed() -> None:
    checked = validator(
        allowed_tables={"users", "teams"},
        allowed_columns={"users": {"id"}, "teams": {"id"}},
        allow_joins=True,
    )
    assert checked.validate("SELECT u.id FROM users u JOIN teams t ON u.id=t.id").allowed


def test_join_policy() -> None:
    result = validator(allowed_tables={"users", "teams"}).validate(
        "SELECT u.id FROM users u JOIN teams t ON u.id=t.id"
    )
    assert result.reason_code == "join_not_allowed"


def test_cte_and_subquery_policies() -> None:
    sql = "WITH active AS (SELECT id FROM users) SELECT id FROM active"
    assert validator().validate(sql).reason_code == "cte_not_allowed"
    assert validator(allow_ctes=True, allow_subqueries=True).validate(sql).allowed


def test_derived_tables_resolve_outputs_and_underlying_policies() -> None:
    checked = validator(
        allowed_columns={"users": {"id"}},
        allow_subqueries=True,
    )
    assert checked.validate("SELECT d.id FROM (SELECT id FROM users) AS d").allowed
    assert (
        checked.validate("SELECT d.secret FROM (SELECT id FROM users) AS d").reason_code
        == "column_scope_ambiguous"
    )
    assert (
        checked.validate("SELECT d.id FROM (SELECT id FROM secrets) AS d").reason_code
        == "table_not_allowed"
    )
    assert (
        checked.validate("SELECT d.id FROM (SELECT secret AS id FROM users) AS d").reason_code
        == "column_not_allowed"
    )


def test_nested_derived_tables_are_resolved() -> None:
    checked = validator(allow_subqueries=True)
    sql = "SELECT outer_q.id FROM (SELECT inner_q.id FROM (SELECT id FROM users) inner_q) outer_q"
    assert checked.validate(sql).allowed


def test_chained_ctes_resolve_only_referenced_sources() -> None:
    checked = validator(allow_ctes=True, allow_subqueries=True)
    sql = (
        "WITH a AS (SELECT id FROM users), "
        "b AS (SELECT id FROM a), c AS (SELECT id FROM b) SELECT id FROM c"
    )
    assert checked.validate(sql).allowed


def test_unexpected_internal_error_returns_fail_closed_result() -> None:
    class BrokenValidator(SQLValidator):
        def _inspect(self, expression: object) -> object:
            del expression
            raise RuntimeError("sensitive internal failure")

    result = BrokenValidator(SQLPolicy(allowed_tables={"users"})).validate("SELECT id FROM users")
    assert not result.allowed
    assert result.reason_code == "validation_error"
    assert "sensitive" not in result.message


@pytest.mark.parametrize(
    "sql,code",
    [
        ("SELECT id FROM users", "limit_required"),
        ("SELECT id FROM users LIMIT 101", "limit_exceeded"),
        ("SELECT id FROM users LIMIT 0", "invalid_limit"),
    ],
)
def test_limit_policy(sql: str, code: str) -> None:
    assert validator(require_limit=True).validate(sql).reason_code == code


def test_normalization_is_opt_in() -> None:
    assert validator().validate("select id from users").normalized_input is None
    assert (
        validator(include_normalized_sql=True).validate("select id from users").normalized_input
        == "SELECT id FROM users"
    )


def test_query_length_and_bad_input() -> None:
    assert (
        validator(max_query_length=5).validate("SELECT id FROM users").reason_code
        == "query_too_long"
    )
    assert validator().validate(123).reason_code == "invalid_input"  # type: ignore[arg-type]
