import pytest

from guardrail_kit.core.errors import ConfigurationError
from guardrail_kit.sql import SQLPolicy, UnlistedColumnPolicy


def test_policy_normalizes_identifiers() -> None:
    policy = SQLPolicy(
        allowed_tables={" Public.Users "},
        allowed_columns={"PUBLIC.USERS": {"ID", "Name"}},
        allowed_functions={" COUNT "},
    )
    assert policy.allowed_tables == {"public.users"}
    assert policy.allowed_columns["public.users"] == {"id", "name"}
    assert policy.allowed_functions == {"count"}


def test_policy_preserves_postgres_quoted_identifier_semantics() -> None:
    policy = SQLPolicy(
        allowed_tables={"users", '"Users"', '"Mixed.Schema"."Events"'},
        allowed_columns={'"Users"': {"id", '"ID"'}},
        allowed_functions={"count", '"MyFunc"', "public.f"},
    )
    assert policy.allowed_tables == {"users", '"Users"', '"Mixed.Schema"."Events"'}
    assert policy.allowed_columns['"Users"'] == {"id", '"ID"'}
    assert policy.allowed_functions == {"count", '"MyFunc"', "public.f"}


def test_unlisted_column_policy_accepts_documented_string_value() -> None:
    policy = SQLPolicy(
        allowed_tables={"users"},
        unlisted_table_columns="block",  # type: ignore[arg-type]
    )
    assert policy.unlisted_table_columns is UnlistedColumnPolicy.BLOCK


@pytest.mark.parametrize(
    "dialect",
    ["postgres ", " postgres", "", "not-a-real-dialect", "MYSQL", "sqlite ", None, 1],
)
def test_policy_rejects_malformed_or_unsupported_dialects(dialect: object) -> None:
    with pytest.raises(ConfigurationError):
        SQLPolicy(dialect=dialect, allowed_tables={"users"})  # type: ignore[arg-type]


def test_whitespace_dialect_cannot_bypass_postgres_identifier_folding() -> None:
    with pytest.raises(ConfigurationError):
        SQLPolicy(
            dialect="postgres ",
            allowed_tables={'"Users"'},
            allowed_columns={'"Users"': {'"ID"'}},
        )


@pytest.mark.parametrize(
    "configured,canonical",
    [
        ("postgres", "postgres"),
        ("postgresql", "postgres"),
        ("sqlite", "sqlite"),
        ("sqlite3", "sqlite"),
        ("mysql", "mysql"),
    ],
)
def test_policy_resolves_documented_dialect_names(configured: str, canonical: str) -> None:
    policy = SQLPolicy(dialect=configured, allowed_tables={"users"})
    assert policy.dialect == canonical


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_query_length": 0},
        {"max_limit": 0},
        {"dialect": ""},
        {"allowed_tables": {"users"}, "allowed_columns": {"orders": {"id"}}},
        {"dialect": "not-a-real-dialect"},
        {"allowed_tables": "users"},
        {"allowed_functions": ["count"]},
        {"allow_joins": 1},
        {"unsupported_constructs": "allow"},
    ],
)
def test_invalid_policy(kwargs: dict[str, object]) -> None:
    with pytest.raises(ConfigurationError):
        SQLPolicy(**kwargs)  # type: ignore[arg-type]
