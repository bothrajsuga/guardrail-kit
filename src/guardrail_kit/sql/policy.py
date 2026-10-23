from collections.abc import Mapping, Set
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType

from guardrail_kit.core.errors import ConfigurationError
from guardrail_kit.sql.dialects import DialectSpec, resolve_dialect
from guardrail_kit.sql.identifiers import (
    canonical_policy_function,
    canonical_policy_identifier,
    canonical_policy_table,
)


class UnsupportedConstructPolicy(StrEnum):
    BLOCK = "block"


class UnlistedColumnPolicy(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"


@dataclass(frozen=True, slots=True)
class SQLPolicy:
    """Secure-by-default SQL validation policy.

    `allowed_tables=None` blocks every query. Use an explicit set of table names;
    an empty set intentionally permits only table-free SELECT statements.
    """

    dialect: str = "postgres"
    allowed_tables: Set[str] | None = None
    allowed_columns: Mapping[str, Set[str]] = field(default_factory=dict)
    allowed_functions: Set[str] = field(default_factory=frozenset)
    unlisted_table_columns: UnlistedColumnPolicy = UnlistedColumnPolicy.ALLOW
    allow_joins: bool = False
    allow_subqueries: bool = False
    allow_ctes: bool = False
    max_query_length: int = 10_000
    require_limit: bool = False
    max_limit: int | None = 1_000
    include_normalized_sql: bool = False
    unsupported_constructs: UnsupportedConstructPolicy = UnsupportedConstructPolicy.BLOCK
    _dialect_spec: DialectSpec = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self._validate_scalar_types()
        dialect_spec = resolve_dialect(self.dialect)
        object.__setattr__(self, "dialect", dialect_spec.canonical_name)
        object.__setattr__(self, "_dialect_spec", dialect_spec)

        unsupported = self._enum_value(
            self.unsupported_constructs,
            UnsupportedConstructPolicy,
            "unsupported_constructs",
        )
        unlisted = self._enum_value(
            self.unlisted_table_columns,
            UnlistedColumnPolicy,
            "unlisted_table_columns",
        )
        object.__setattr__(self, "unsupported_constructs", unsupported)
        object.__setattr__(self, "unlisted_table_columns", unlisted)

        self._validate_name_collections()
        tables = None
        if self.allowed_tables is not None:
            tables = frozenset(
                canonical_policy_table(item, dialect_spec) for item in self.allowed_tables
            )
        columns = {
            canonical_policy_table(table, dialect_spec): frozenset(
                canonical_policy_identifier(column, dialect_spec, kind="column")
                for column in allowed
            )
            for table, allowed in self.allowed_columns.items()
        }
        object.__setattr__(self, "allowed_tables", tables)
        object.__setattr__(self, "allowed_columns", MappingProxyType(columns))
        object.__setattr__(
            self,
            "allowed_functions",
            frozenset(
                canonical_policy_function(function, dialect_spec)
                for function in self.allowed_functions
            ),
        )
        self.validate_configuration()

    def validate_configuration(self) -> None:
        if not self.dialect.strip():
            raise ConfigurationError("dialect must not be empty")
        if self.max_query_length < 1:
            raise ConfigurationError("max_query_length must be positive")
        if self.max_limit is not None and self.max_limit < 1:
            raise ConfigurationError("max_limit must be positive when set")
        if self.allowed_tables is not None:
            unknown = set(self.allowed_columns) - set(self.allowed_tables)
            if unknown:
                raise ConfigurationError("column policies refer to non-allowed tables")

    def _validate_scalar_types(self) -> None:
        if not isinstance(self.dialect, str) or not self.dialect.strip():
            raise ConfigurationError("dialect must be a non-empty string")
        if not isinstance(self.max_query_length, int) or isinstance(self.max_query_length, bool):
            raise ConfigurationError("max_query_length must be an integer")
        if self.max_limit is not None and (
            not isinstance(self.max_limit, int) or isinstance(self.max_limit, bool)
        ):
            raise ConfigurationError("max_limit must be an integer or None")
        for name in (
            "allow_joins",
            "allow_subqueries",
            "allow_ctes",
            "require_limit",
            "include_normalized_sql",
        ):
            if not isinstance(getattr(self, name), bool):
                raise ConfigurationError(f"{name} must be a boolean")

    def _validate_name_collections(self) -> None:
        if self.allowed_tables is not None and (
            not isinstance(self.allowed_tables, Set) or isinstance(self.allowed_tables, str)
        ):
            raise ConfigurationError("allowed_tables must be a set of strings or None")
        if not isinstance(self.allowed_columns, Mapping):
            raise ConfigurationError("allowed_columns must be a mapping")
        if not isinstance(self.allowed_functions, Set) or isinstance(self.allowed_functions, str):
            raise ConfigurationError("allowed_functions must be a set of strings")
        for table, columns in self.allowed_columns.items():
            if not isinstance(table, str):
                raise ConfigurationError("allowed_columns keys must be strings")
            if not isinstance(columns, Set) or isinstance(columns, str):
                raise ConfigurationError("allowed column values must be sets of strings")

    @staticmethod
    def _enum_value(value: object, enum_type: type[StrEnum], name: str) -> StrEnum:
        if not isinstance(value, (str, StrEnum)):
            raise ConfigurationError(f"invalid {name} value: {value!r}")
        try:
            return enum_type(value)
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(f"invalid {name} value: {value!r}") from exc
