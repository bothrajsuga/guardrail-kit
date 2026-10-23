import pytest

from guardrail_kit.sql import SQLPolicy, SQLValidator

_DIALECTS = (
    "postgres",
    "sqlite",
    "mysql",
    "tsql",
    "oracle",
    "duckdb",
    "snowflake",
    "bigquery",
    "redshift",
    "databricks",
    "spark",
)


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
        ("tsql", "[Odd]]Table]", "SELECT id FROM [Odd]]Table]"),
        ("oracle", '"Odd""Table"', 'SELECT id FROM "Odd""Table"'),
        ("duckdb", '"Odd""Table"', 'SELECT id FROM "odd""table"'),
        ("snowflake", '"Odd""Table"', 'SELECT id FROM "Odd""Table"'),
        ("redshift", '"Odd""Table"', 'SELECT id FROM "Odd""Table"'),
        ("databricks", "`Odd``Table`", "SELECT id FROM `Odd``Table`"),
        ("spark", "`Odd``Table`", "SELECT id FROM `Odd``Table`"),
    ],
)
def test_dialect_identifier_escaping(dialect: str, table: str, query: str) -> None:
    validator = SQLValidator(SQLPolicy(dialect=dialect, allowed_tables={table}))
    assert validator.validate(query).allowed


def test_bigquery_escaped_table_identifier_fails_closed_when_parser_cannot_resolve_it() -> None:
    validator = SQLValidator(SQLPolicy(dialect="bigquery", allowed_tables={"users"}))
    assert not validator.validate(r"SELECT id FROM `Odd\`Table`").allowed


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


@pytest.mark.parametrize("dialect", _DIALECTS)
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
    assert result.reason_code in {
        "write_operation_not_allowed",
        "parse_error",
        "unsupported_construct",
    }


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


@pytest.mark.parametrize("dialect", _DIALECTS)
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
    "dialect,table,query,wrong_query",
    [
        ("postgres", '"App"."Users"', 'SELECT id FROM "App"."Users"', "SELECT id FROM app.users"),
        ("sqlite", '"main"."Users"', "SELECT id FROM MAIN.USERS", "SELECT id FROM temp.users"),
        ("mysql", "`App`.`Users`", "SELECT id FROM App.Users", "SELECT id FROM app.Users"),
        ("tsql", "[App].[Users]", "SELECT id FROM [App].[Users]", "SELECT id FROM app.users"),
        ("oracle", '"App"."Users"', 'SELECT id FROM "App"."Users"', "SELECT id FROM app.users"),
        ("duckdb", '"main"."Users"', "SELECT id FROM MAIN.USERS", "SELECT id FROM temp.users"),
        (
            "snowflake",
            '"App"."Users"',
            'SELECT id FROM "App"."Users"',
            "SELECT id FROM app.users",
        ),
        (
            "bigquery",
            "`project.dataset.Users`",
            "SELECT id FROM `project.dataset.Users`",
            "SELECT id FROM `other.dataset.Users`",
        ),
        (
            "redshift",
            '"App"."Users"',
            'SELECT id FROM "App"."Users"',
            "SELECT id FROM app.users",
        ),
        (
            "databricks",
            "`App`.`Users`",
            "SELECT id FROM `App`.`Users`",
            "SELECT id FROM app.users",
        ),
        ("spark", "`App`.`Users`", "SELECT id FROM `App`.`Users`", "SELECT id FROM app.users"),
    ],
)
def test_catalog_and_schema_table_allowlists_by_dialect(
    dialect: str, table: str, query: str, wrong_query: str
) -> None:
    validator = SQLValidator(
        SQLPolicy(dialect=dialect, allowed_tables={table}, allowed_columns={table: {"id"}})
    )
    assert validator.validate(query).allowed
    assert validator.validate(wrong_query).reason_code == "table_not_allowed"


@pytest.mark.parametrize(
    "dialect,accepted,rejected,reason",
    [
        (
            "oracle",
            ("SELECT id FROM users", "SELECT id FROM USERS"),
            'SELECT id FROM "Users"',
            "table_not_allowed",
        ),
        (
            "snowflake",
            ("SELECT id FROM users", "SELECT id FROM USERS"),
            'SELECT id FROM "Users"',
            "table_not_allowed",
        ),
        (
            "duckdb",
            ("SELECT ID FROM users", 'SELECT "ID" FROM "USERS"'),
            "SELECT secret FROM users",
            "column_not_allowed",
        ),
        (
            "bigquery",
            ("SELECT ID FROM users", "SELECT id FROM users"),
            "SELECT id FROM USERS",
            "table_not_allowed",
        ),
    ],
)
def test_dialect_specific_identifier_folding(
    dialect: str, accepted: tuple[str, ...], rejected: str, reason: str
) -> None:
    validator = SQLValidator(
        SQLPolicy(dialect=dialect, allowed_tables={"users"}, allowed_columns={"users": {"id"}})
    )
    for query in accepted:
        assert validator.validate(query).allowed
    assert validator.validate(rejected).reason_code == reason


@pytest.mark.parametrize(
    "dialect,query,over_limit",
    [
        ("postgres", "SELECT id FROM users LIMIT 10", "SELECT id FROM users LIMIT 11"),
        ("sqlite", "SELECT id FROM users LIMIT 10", "SELECT id FROM users LIMIT 11"),
        ("mysql", "SELECT id FROM users LIMIT 10", "SELECT id FROM users LIMIT 11"),
        ("tsql", "SELECT TOP (10) id FROM users", "SELECT TOP (11) id FROM users"),
        (
            "oracle",
            "SELECT id FROM users FETCH FIRST 10 ROWS ONLY",
            "SELECT id FROM users FETCH NEXT 11 ROWS ONLY",
        ),
        ("duckdb", "SELECT id FROM users LIMIT 10", "SELECT id FROM users LIMIT 11"),
        (
            "snowflake",
            "SELECT id FROM users FETCH FIRST 10 ROWS ONLY",
            "SELECT id FROM users FETCH NEXT 11 ROWS ONLY",
        ),
        ("bigquery", "SELECT id FROM users LIMIT 10", "SELECT id FROM users LIMIT 11"),
        ("redshift", "SELECT id FROM users LIMIT 10", "SELECT id FROM users LIMIT 11"),
        ("databricks", "SELECT id FROM users LIMIT 10", "SELECT id FROM users LIMIT 11"),
        ("spark", "SELECT id FROM users LIMIT 10", "SELECT id FROM users LIMIT 11"),
    ],
)
def test_row_caps_are_enforced_for_each_dialect(
    dialect: str, query: str, over_limit: str
) -> None:
    validator = SQLValidator(
        SQLPolicy(dialect=dialect, allowed_tables={"users"}, require_limit=True, max_limit=10)
    )
    assert validator.validate(query).allowed
    assert validator.validate(over_limit).reason_code == "limit_exceeded"


@pytest.mark.parametrize(
    "dialect,query",
    [
        ("tsql", "SELECT TOP (10) PERCENT id FROM users"),
        ("tsql", "SELECT TOP (10) WITH TIES id FROM users ORDER BY id"),
        ("oracle", "SELECT id FROM users FETCH FIRST 10 PERCENT ROWS ONLY"),
        ("oracle", "SELECT id FROM users FETCH FIRST 10 ROWS WITH TIES"),
        ("snowflake", "SELECT id FROM users FETCH FIRST 10 ROWS WITH TIES"),
    ],
)
def test_non_bounding_row_limit_forms_are_rejected(dialect: str, query: str) -> None:
    validator = SQLValidator(
        SQLPolicy(dialect=dialect, allowed_tables={"users"}, require_limit=True, max_limit=10)
    )
    assert validator.validate(query).reason_code == "invalid_limit"


@pytest.mark.parametrize("dialect", _DIALECTS)
def test_recursive_ctes_are_rejected_for_every_dialect(dialect: str) -> None:
    validator = SQLValidator(
        SQLPolicy(dialect=dialect, allowed_tables={"users"}, allow_ctes=True)
    )
    result = validator.validate(
        "WITH RECURSIVE recursive_users AS (SELECT id FROM users) "
        "SELECT id FROM recursive_users"
    )
    assert result.reason_code == "unsupported_construct"


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


@pytest.mark.parametrize("dialect", _DIALECTS)
def test_join_using_authorizes_column_against_both_sources(dialect: str) -> None:
    allowed = SQLValidator(
        SQLPolicy(
            dialect=dialect,
            allowed_tables={"users", "teams"},
            allowed_columns={"users": {"id"}, "teams": {"id"}},
            allow_joins=True,
        )
    )
    assert allowed.validate("SELECT u.id FROM users u JOIN teams t USING (id)").allowed

    for columns in (
        {"users": {"id", "secret"}, "teams": {"id"}},
        {"users": {"id"}, "teams": {"id", "secret"}},
        {"users": {"id"}, "teams": {"id"}},
    ):
        checked = SQLValidator(
            SQLPolicy(
                dialect=dialect,
                allowed_tables={"users", "teams"},
                allowed_columns=columns,
                allow_joins=True,
            )
        )
        assert not checked.validate(
            "SELECT u.id FROM users u JOIN teams t USING (secret)"
        ).allowed


@pytest.mark.parametrize("dialect", _DIALECTS)
def test_natural_join_is_blocked_with_column_restrictions(dialect: str) -> None:
    validator = SQLValidator(
        SQLPolicy(
            dialect=dialect,
            allowed_tables={"users", "teams"},
            allowed_columns={"users": {"id"}, "teams": {"id"}},
            allow_joins=True,
        )
    )
    result = validator.validate("SELECT u.id FROM users u NATURAL JOIN teams t")
    assert result.reason_code == "unsupported_construct"


def test_join_using_handles_chains_ctes_and_derived_tables() -> None:
    validator = SQLValidator(
        SQLPolicy(
            allowed_tables={"users", "teams", "orgs"},
            allowed_columns={
                "users": {"id"},
                "teams": {"id"},
                "orgs": {"id"},
            },
            allow_joins=True,
            allow_ctes=True,
            allow_subqueries=True,
        )
    )
    assert validator.validate(
        "SELECT u.id FROM users u JOIN teams t USING(id) JOIN orgs o USING(id)"
    ).allowed
    assert validator.validate(
        "WITH t AS (SELECT id FROM teams) SELECT u.id FROM users u JOIN t USING(id)"
    ).allowed
    assert validator.validate(
        "SELECT u.id FROM users u JOIN (SELECT id FROM teams) t USING(id)"
    ).allowed
    assert not validator.validate(
        "SELECT u.id FROM users u JOIN (SELECT id FROM teams) t USING(secret)"
    ).allowed


def test_join_using_handles_schema_qualified_sources_and_aliases() -> None:
    validator = SQLValidator(
        SQLPolicy(
            allowed_tables={"app.users", "app.teams"},
            allowed_columns={"app.users": {"id"}, "app.teams": {"id"}},
            allow_joins=True,
        )
    )
    assert validator.validate(
        "SELECT u.id FROM app.users AS u JOIN app.teams AS t USING(id)"
    ).allowed
    assert not validator.validate(
        "SELECT u.id FROM app.users AS u JOIN app.teams AS t USING(secret)"
    ).allowed


@pytest.mark.parametrize("dialect", _DIALECTS)
def test_nested_wildcards_are_blocked_with_column_restrictions(dialect: str) -> None:
    function = (
        "COUNT"
        if dialect in {"bigquery", "databricks", "spark", "tsql"}
        else "count"
    )
    validator = SQLValidator(
        SQLPolicy(
            dialect=dialect,
            allowed_tables={"users"},
            allowed_columns={"users": {"id"}},
            allowed_functions={function},
        )
    )
    assert validator.validate("SELECT COUNT(*) FROM users").reason_code == (
        "wildcard_not_allowed"
    )
    assert validator.validate("SELECT users.* FROM users").reason_code == (
        "wildcard_not_allowed"
    )


def test_wildcards_and_natural_join_remain_available_without_column_restrictions() -> None:
    validator = SQLValidator(
        SQLPolicy(
            allowed_tables={"users", "teams"},
            allowed_functions={"count"},
            allow_joins=True,
        )
    )
    assert validator.validate("SELECT COUNT(*) FROM users").allowed
    assert validator.validate("SELECT u.* FROM users u").allowed
    assert validator.validate("SELECT u.id FROM users u NATURAL JOIN teams t").allowed


def test_wildcards_are_blocked_inside_aliases_subqueries_and_ctes() -> None:
    validator = SQLValidator(
        SQLPolicy(
            allowed_tables={"users"},
            allowed_columns={"users": {"id"}},
            allowed_functions={"count"},
            allow_subqueries=True,
            allow_ctes=True,
        )
    )
    assert validator.validate("SELECT COUNT(*) AS total FROM users").reason_code == (
        "wildcard_not_allowed"
    )
    assert validator.validate(
        "SELECT d.id FROM (SELECT users.* FROM users) AS d"
    ).reason_code == "wildcard_not_allowed"
    assert validator.validate(
        "WITH selected AS (SELECT users.* FROM users) SELECT id FROM selected"
    ).reason_code == "wildcard_not_allowed"
