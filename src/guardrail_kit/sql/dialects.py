from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from guardrail_kit.core.errors import ConfigurationError


class IdentifierCase(StrEnum):
    LOWER_UNQUOTED = "lower_unquoted"
    UPPER_UNQUOTED = "upper_unquoted"
    LOWER_ALWAYS = "lower_always"
    PRESERVE = "preserve"


class IdentifierKind(StrEnum):
    TABLE = "table"
    COLUMN = "column"
    ALIAS = "alias"
    FUNCTION = "function"


class DialectSupport(StrEnum):
    SUPPORTED = "supported"
    EXPERIMENTAL = "experimental"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class DialectSpec:
    canonical_name: str
    sqlglot_name: str
    aliases: frozenset[str]
    table_case: IdentifierCase
    column_case: IdentifierCase
    alias_case: IdentifierCase
    function_case: IdentifierCase
    quote_styles: tuple[str, ...]
    qualification_order: tuple[str, ...] = ("catalog", "schema", "table")
    pagination_forms: tuple[str, ...] = ("LIMIT",)
    blocked_constructs: tuple[str, ...] = (
        "non-SELECT statements",
        "SELECT INTO",
        "table hints",
        "locking reads",
        "set operations",
        "recursive CTEs",
    )
    supports_set_operations: bool = False
    supports_recursive_ctes: bool = False
    supports_locking_reads: bool = False
    support: DialectSupport = DialectSupport.SUPPORTED

    def case_for(self, kind: IdentifierKind) -> IdentifierCase:
        return {
            IdentifierKind.TABLE: self.table_case,
            IdentifierKind.COLUMN: self.column_case,
            IdentifierKind.ALIAS: self.alias_case,
            IdentifierKind.FUNCTION: self.function_case,
        }[kind]


POSTGRES = DialectSpec(
    canonical_name="postgres",
    sqlglot_name="postgres",
    aliases=frozenset({"postgresql"}),
    table_case=IdentifierCase.LOWER_UNQUOTED,
    column_case=IdentifierCase.LOWER_UNQUOTED,
    alias_case=IdentifierCase.LOWER_UNQUOTED,
    function_case=IdentifierCase.LOWER_UNQUOTED,
    quote_styles=("double quotes",),
)

SQLITE = DialectSpec(
    canonical_name="sqlite",
    sqlglot_name="sqlite",
    aliases=frozenset({"sqlite3"}),
    table_case=IdentifierCase.LOWER_ALWAYS,
    column_case=IdentifierCase.LOWER_ALWAYS,
    alias_case=IdentifierCase.LOWER_ALWAYS,
    function_case=IdentifierCase.LOWER_ALWAYS,
    quote_styles=("double quotes", "backticks", "square brackets"),
)

MYSQL = DialectSpec(
    canonical_name="mysql",
    sqlglot_name="mysql",
    aliases=frozenset(),
    # Table and alias matching stays exact because server behavior depends on
    # lower_case_table_names and platform. Columns and routines are insensitive.
    table_case=IdentifierCase.PRESERVE,
    column_case=IdentifierCase.LOWER_ALWAYS,
    alias_case=IdentifierCase.PRESERVE,
    function_case=IdentifierCase.LOWER_ALWAYS,
    quote_styles=("backticks", "double quotes when ANSI_QUOTES is enabled"),
    pagination_forms=("LIMIT",),
)

TSQL = DialectSpec(
    canonical_name="tsql",
    sqlglot_name="tsql",
    aliases=frozenset({"mssql", "sqlserver"}),
    # SQL Server identifier resolution follows database/catalog collation.
    # Exact spelling is conservative for both case-sensitive and insensitive DBs.
    table_case=IdentifierCase.PRESERVE,
    column_case=IdentifierCase.PRESERVE,
    alias_case=IdentifierCase.PRESERVE,
    function_case=IdentifierCase.PRESERVE,
    quote_styles=("brackets", "double quotes when QUOTED_IDENTIFIER is enabled"),
    pagination_forms=("TOP", "OFFSET/FETCH"),
)

ORACLE = DialectSpec(
    canonical_name="oracle",
    sqlglot_name="oracle",
    aliases=frozenset(),
    table_case=IdentifierCase.UPPER_UNQUOTED,
    column_case=IdentifierCase.UPPER_UNQUOTED,
    alias_case=IdentifierCase.UPPER_UNQUOTED,
    function_case=IdentifierCase.UPPER_UNQUOTED,
    quote_styles=("double quotes",),
    pagination_forms=("FETCH FIRST/NEXT", "OFFSET/FETCH"),
)

DUCKDB = DialectSpec(
    canonical_name="duckdb",
    sqlglot_name="duckdb",
    aliases=frozenset(),
    table_case=IdentifierCase.LOWER_ALWAYS,
    column_case=IdentifierCase.LOWER_ALWAYS,
    alias_case=IdentifierCase.LOWER_ALWAYS,
    function_case=IdentifierCase.LOWER_ALWAYS,
    quote_styles=("double quotes",),
)

SNOWFLAKE = DialectSpec(
    canonical_name="snowflake",
    sqlglot_name="snowflake",
    aliases=frozenset(),
    table_case=IdentifierCase.UPPER_UNQUOTED,
    column_case=IdentifierCase.UPPER_UNQUOTED,
    alias_case=IdentifierCase.UPPER_UNQUOTED,
    function_case=IdentifierCase.UPPER_UNQUOTED,
    quote_styles=("double quotes",),
    pagination_forms=("LIMIT", "FETCH FIRST/NEXT", "OFFSET/FETCH"),
)

BIGQUERY = DialectSpec(
    canonical_name="bigquery",
    sqlglot_name="bigquery",
    aliases=frozenset(),
    # Dataset and table names are case-sensitive unless a dataset option changes
    # resolution. Exact spelling is safe in both modes; columns and aliases are
    # documented as case-insensitive. UDF names are case-sensitive, so function
    # policies also use exact spelling (including for built-ins).
    table_case=IdentifierCase.PRESERVE,
    column_case=IdentifierCase.LOWER_ALWAYS,
    alias_case=IdentifierCase.LOWER_ALWAYS,
    function_case=IdentifierCase.PRESERVE,
    quote_styles=("backticks",),
)

REDSHIFT = DialectSpec(
    canonical_name="redshift",
    sqlglot_name="redshift",
    aliases=frozenset(),
    # The default folds quoted and unquoted ASCII identifiers to lowercase, but
    # enable_case_sensitive_identifier can preserve quoted names. Preserving
    # quoted spelling is conservative across both configurations.
    table_case=IdentifierCase.LOWER_UNQUOTED,
    column_case=IdentifierCase.LOWER_UNQUOTED,
    alias_case=IdentifierCase.LOWER_UNQUOTED,
    function_case=IdentifierCase.LOWER_UNQUOTED,
    quote_styles=("double quotes",),
)

DATABRICKS = DialectSpec(
    canonical_name="databricks",
    sqlglot_name="databricks",
    aliases=frozenset(),
    # Catalog and analyzer case behavior can vary by deployment. Exact matching
    # is conservative and avoids equating distinct external-catalog objects.
    table_case=IdentifierCase.PRESERVE,
    column_case=IdentifierCase.PRESERVE,
    alias_case=IdentifierCase.PRESERVE,
    function_case=IdentifierCase.PRESERVE,
    quote_styles=("backticks",),
)

SPARK = DialectSpec(
    canonical_name="spark",
    sqlglot_name="spark",
    aliases=frozenset(),
    table_case=IdentifierCase.PRESERVE,
    column_case=IdentifierCase.PRESERVE,
    alias_case=IdentifierCase.PRESERVE,
    function_case=IdentifierCase.PRESERVE,
    quote_styles=("backticks",),
)

SUPPORTED_DIALECTS: tuple[DialectSpec, ...] = (
    POSTGRES,
    SQLITE,
    MYSQL,
    TSQL,
    ORACLE,
    DUCKDB,
    SNOWFLAKE,
    BIGQUERY,
    REDSHIFT,
    DATABRICKS,
    SPARK,
)
_DIALECT_NAMES = {
    name: spec
    for spec in SUPPORTED_DIALECTS
    for name in (spec.canonical_name, *spec.aliases)
}


def resolve_dialect(value: object) -> DialectSpec:
    if not isinstance(value, str) or not value:
        raise ConfigurationError("dialect must be a non-empty string")
    try:
        return _DIALECT_NAMES[value]
    except KeyError as exc:
        raise ConfigurationError(f"unsupported SQL dialect: {value!r}") from exc
