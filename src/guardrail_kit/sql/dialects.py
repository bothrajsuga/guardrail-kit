from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from guardrail_kit.core.errors import ConfigurationError


class IdentifierCase(StrEnum):
    LOWER_UNQUOTED = "lower_unquoted"
    LOWER_ALWAYS = "lower_always"
    PRESERVE = "preserve"


class IdentifierKind(StrEnum):
    TABLE = "table"
    COLUMN = "column"
    ALIAS = "alias"
    FUNCTION = "function"


@dataclass(frozen=True, slots=True)
class DialectSpec:
    canonical_name: str
    sqlglot_name: str
    aliases: frozenset[str]
    table_case: IdentifierCase
    column_case: IdentifierCase
    alias_case: IdentifierCase
    function_case: IdentifierCase

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
)

SQLITE = DialectSpec(
    canonical_name="sqlite",
    sqlglot_name="sqlite",
    aliases=frozenset({"sqlite3"}),
    table_case=IdentifierCase.LOWER_ALWAYS,
    column_case=IdentifierCase.LOWER_ALWAYS,
    alias_case=IdentifierCase.LOWER_ALWAYS,
    function_case=IdentifierCase.LOWER_ALWAYS,
)

MYSQL = DialectSpec(
    canonical_name="mysql",
    sqlglot_name="mysql",
    aliases=frozenset(),
    # MySQL database/table and table-alias case resolution varies with
    # lower_case_table_names and platform. Exact spelling is conservative on
    # every deployment; columns and routines are always case-insensitive.
    table_case=IdentifierCase.PRESERVE,
    column_case=IdentifierCase.LOWER_ALWAYS,
    alias_case=IdentifierCase.PRESERVE,
    function_case=IdentifierCase.LOWER_ALWAYS,
)

SUPPORTED_DIALECTS: tuple[DialectSpec, ...] = (POSTGRES, SQLITE, MYSQL)
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
