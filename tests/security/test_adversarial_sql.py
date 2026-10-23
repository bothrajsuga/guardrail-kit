import pytest

from guardrail_kit.sql import SQLPolicy, SQLValidator


@pytest.fixture
def validate() -> SQLValidator:
    return SQLValidator(
        SQLPolicy(
            allowed_tables={"users"},
            allowed_columns={"users": {"id", "name"}},
            allow_subqueries=True,
            allow_ctes=True,
        )
    )


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT id FROM users; -- harmless\n DELETE FROM users",
        "SELECT id FROM users /* ; */; UPDATE users SET name='x'",
        "TRUNCATE TABLE users",
        "MERGE INTO users USING other ON users.id=other.id WHEN MATCHED THEN DELETE",
        "ALTER TABLE users ADD COLUMN secret TEXT",
        "SELECT id INTO stolen FROM users",
        "SELECT id FROM users FOR UPDATE",
        "SELECT secret FROM users",
        "SELECT id FROM other",
    ],
)
def test_adversarial_input_is_blocked(validate: SQLValidator, sql: str) -> None:
    assert not validate.validate(sql).allowed


def test_comments_and_quoted_identifiers_do_not_bypass_policy(validate: SQLValidator) -> None:
    assert validate.validate('SELECT /*comment*/ "id" FROM "users"').allowed
    assert not validate.validate('SELECT "secret" FROM "users"').allowed


def test_nested_disallowed_table_is_found(validate: SQLValidator) -> None:
    result = validate.validate("SELECT id FROM users WHERE id IN (SELECT id FROM secrets)")
    assert result.reason_code == "table_not_allowed"


def test_cte_alias_cannot_shadow_a_disallowed_physical_table(validate: SQLValidator) -> None:
    result = validate.validate("WITH users AS (SELECT id FROM secrets) SELECT id FROM users")
    assert result.reason_code == "table_not_allowed"


def test_disallowed_table_inside_derived_table_is_found(validate: SQLValidator) -> None:
    result = validate.validate("SELECT d.id FROM (SELECT id FROM secrets) AS d")
    assert result.reason_code == "table_not_allowed"


@pytest.mark.parametrize(
    "operation",
    [
        "DELETE FROM secrets RETURNING id",
        "UPDATE secrets SET id = 2 RETURNING id",
        "INSERT INTO secrets VALUES (1) RETURNING id",
    ],
)
def test_data_modifying_cte_cannot_hide_behind_allowed_alias(operation: str) -> None:
    validator = SQLValidator(SQLPolicy(allowed_tables={"users"}, allow_ctes=True))
    result = validator.validate(f"WITH users AS ({operation}) SELECT id FROM users")
    assert result.reason_code == "write_operation_not_allowed"
    assert not result.allowed


@pytest.mark.parametrize(
    "operation",
    [
        (
            "MERGE INTO secrets s USING source_rows r ON s.id = r.id "
            "WHEN MATCHED THEN DELETE RETURNING s.id"
        ),
        "CREATE TABLE secrets (id INT)",
        "DROP TABLE secrets",
    ],
)
def test_other_non_read_only_nodes_are_rejected_anywhere_in_ast(operation: str) -> None:
    validator = SQLValidator(SQLPolicy(allowed_tables={"users", "source_rows"}, allow_ctes=True))
    result = validator.validate(f"WITH users AS ({operation}) SELECT id FROM users")
    assert result.reason_code == "write_operation_not_allowed"


def test_raw_sql_is_not_returned_on_parse_failure(validate: SQLValidator) -> None:
    secret = "SELECT 'api-key-super-secret"
    result = validate.validate(secret)
    assert secret not in result.message
    assert result.normalized_input is None
