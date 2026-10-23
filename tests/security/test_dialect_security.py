import pytest

from guardrail_kit.sql import SQLPolicy, SQLValidator


@pytest.mark.parametrize(
    "dialect,table,column,allowed_query,wrong_table_query,wrong_column_query",
    [
        (
            "postgres",
            '"App"."Users"',
            '"ID"',
            'SELECT "U"."ID" FROM "App"."Users" AS "U"',
            "SELECT u.id FROM app.users AS u",
            'SELECT "U".id FROM "App"."Users" AS "U"',
        ),
        (
            "sqlite",
            '"main"."Users"',
            '"ID"',
            "SELECT u.id FROM MAIN.USERS AS U",
            "SELECT id FROM temp.users",
            "SELECT secret FROM main.users",
        ),
        (
            "mysql",
            "`App`.`Users`",
            "`ID`",
            "SELECT U.id FROM App.Users AS U",
            "SELECT id FROM app.Users",
            "SELECT secret FROM App.Users",
        ),
    ],
)
def test_dialect_identifier_and_policy_semantics(
    dialect: str,
    table: str,
    column: str,
    allowed_query: str,
    wrong_table_query: str,
    wrong_column_query: str,
) -> None:
    validator = SQLValidator(
        SQLPolicy(
            dialect=dialect,
            allowed_tables={table},
            allowed_columns={table: {column}},
        )
    )
    assert validator.validate(allowed_query).allowed
    assert validator.validate(wrong_table_query).reason_code == "table_not_allowed"
    assert validator.validate(wrong_column_query).reason_code == "column_not_allowed"


@pytest.mark.parametrize(
    "dialect,table,query",
    [
        ("postgres", '"Odd""Table"', 'SELECT id FROM "Odd""Table"'),
        ("sqlite", '"Odd""Table"', 'SELECT ID FROM "odd""table"'),
        ("mysql", "`Odd``Table`", "SELECT id FROM `Odd``Table`"),
    ],
)
def test_dialect_identifier_escaping(dialect: str, table: str, query: str) -> None:
    validator = SQLValidator(SQLPolicy(dialect=dialect, allowed_tables={table}))
    assert validator.validate(query).allowed


@pytest.mark.parametrize(
    "dialect,table,inner_table",
    [
        ("postgres", "app.users", "app.users"),
        ("sqlite", "main.users", "MAIN.USERS"),
        ("mysql", "App.Users", "App.Users"),
    ],
)
def test_nested_queries_and_chained_ctes_by_dialect(
    dialect: str, table: str, inner_table: str
) -> None:
    validator = SQLValidator(
        SQLPolicy(
            dialect=dialect,
            allowed_tables={table},
            allowed_columns={table: {"id"}},
            allow_subqueries=True,
            allow_ctes=True,
        )
    )
    assert validator.validate(f"SELECT d.id FROM (SELECT id FROM {inner_table}) d").allowed
    assert validator.validate(
        f"WITH a AS (SELECT id FROM {inner_table}), "
        "b AS (SELECT id FROM a) SELECT id FROM b"
    ).allowed
    assert (
        validator.validate(
            f"SELECT d.id FROM (SELECT secret AS id FROM {inner_table}) d"
        ).reason_code
        == "column_not_allowed"
    )
    assert (
        validator.validate(
            "WITH users AS (SELECT id FROM secrets) SELECT id FROM users"
        ).reason_code
        == "table_not_allowed"
    )


@pytest.mark.parametrize("dialect", ["postgres", "sqlite", "mysql"])
@pytest.mark.parametrize(
    "operation",
    [
        "INSERT INTO secrets VALUES (1) RETURNING id",
        "UPDATE secrets SET id=2 RETURNING id",
        "DELETE FROM secrets RETURNING id",
        "CREATE TABLE secrets (id INT)",
        "BEGIN",
        "COMMIT",
    ],
)
def test_nested_non_read_operations_are_blocked_for_every_dialect(
    dialect: str, operation: str
) -> None:
    validator = SQLValidator(
        SQLPolicy(dialect=dialect, allowed_tables={"users"}, allow_ctes=True)
    )
    result = validator.validate(f"WITH users AS ({operation}) SELECT id FROM users")
    assert not result.allowed
    assert result.reason_code == "write_operation_not_allowed"


@pytest.mark.parametrize(
    "dialect,sql",
    [
        ("postgres", "SELECT id FROM users FOR UPDATE"),
        ("sqlite", "PRAGMA writable_schema=ON"),
        ("sqlite", "ATTACH DATABASE 'other.db' AS other"),
        ("mysql", "LOCK TABLES users WRITE"),
        ("mysql", "SELECT id FROM users INTO OUTFILE '/tmp/export'"),
    ],
)
def test_dialect_specific_dangerous_statements_fail_closed(dialect: str, sql: str) -> None:
    validator = SQLValidator(SQLPolicy(dialect=dialect, allowed_tables={"users"}))
    assert not validator.validate(sql).allowed


@pytest.mark.parametrize("dialect", ["postgres", "sqlite", "mysql"])
def test_malformed_and_unsupported_sql_fails_closed(dialect: str) -> None:
    validator = SQLValidator(
        SQLPolicy(
            dialect=dialect,
            allowed_tables={"users"},
            allowed_columns={"users": {"id"}},
        )
    )
    assert validator.validate("SELECT ( FROM users").reason_code == "parse_error"
    assert not validator.validate("SELECT id FROM users UNION SELECT id FROM users").allowed
    assert validator.validate("SELECT id FROM users; DELETE FROM users").reason_code == (
        "multiple_statements"
    )
    assert validator.validate("SELECT * FROM users").reason_code == "wildcard_not_allowed"


@pytest.mark.parametrize(
    "dialect,policy_function,query",
    [
        ("postgres", "public.f", "SELECT public.f(id) FROM users"),
        ("sqlite", "main.myfunc", "SELECT MAIN.MYFUNC(ID) FROM USERS"),
        ("mysql", "App.MyFunc", "SELECT App.MYFUNC(ID) FROM Users"),
    ],
)
def test_dialect_function_qualification(
    dialect: str, policy_function: str, query: str
) -> None:
    table = "Users" if dialect == "mysql" else "users"
    validator = SQLValidator(
        SQLPolicy(
            dialect=dialect,
            allowed_tables={table},
            allowed_functions={policy_function},
        )
    )
    assert validator.validate(query).allowed
    assert not validator.validate(
        query.replace("MYFUNC", "OTHER").replace("f(id)", "g(id)")
    ).allowed


@pytest.mark.parametrize(
    "dialect,query",
    [
        ("postgres", "SELECT id FROM users LIMIT 10 OFFSET 5"),
        ("sqlite", "SELECT id FROM users LIMIT 10 OFFSET 5"),
        ("mysql", "SELECT id FROM users LIMIT 5, 10"),
    ],
)
def test_understood_limit_forms(dialect: str, query: str) -> None:
    validator = SQLValidator(
        SQLPolicy(dialect=dialect, allowed_tables={"users"}, require_limit=True, max_limit=10)
    )
    assert validator.validate(query).allowed
