from __future__ import annotations

import re

from sqlglot import exp, parse_one
from sqlglot.errors import ParseError, TokenError

from guardrail_kit.core.errors import ConfigurationError
from guardrail_kit.sql.dialects import DialectSpec, IdentifierCase, IdentifierKind

_SIMPLE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")


def canonical_identifier(
    identifier: exp.Identifier, dialect: DialectSpec, *, kind: IdentifierKind
) -> str:
    """Return the configured database's conservative identifier spelling."""

    value = str(identifier.this)
    case = dialect.case_for(kind)
    if case is IdentifierCase.LOWER_ALWAYS or (
        case is IdentifierCase.LOWER_UNQUOTED and not identifier.args.get("quoted")
    ):
        value = value.lower()
    elif case is IdentifierCase.UPPER_UNQUOTED and not identifier.args.get("quoted"):
        value = value.upper()
    if _requires_quotes(value, dialect, kind):
        return exp.Identifier(this=value, quoted=True).sql(dialect=dialect.sqlglot_name)
    return value


def canonical_policy_table(value: str, dialect: DialectSpec) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError("table names must be non-empty strings")
    try:
        table = parse_one(value.strip(), read=dialect.sqlglot_name, into=exp.Table)
    except (ParseError, TokenError, ValueError, TypeError) as exc:
        raise ConfigurationError(f"invalid table identifier: {value!r}") from exc
    if table.args.get("alias") is not None:
        raise ConfigurationError("table policy names must not contain aliases")
    return canonical_table(table, dialect)


def canonical_policy_identifier(value: str, dialect: DialectSpec, *, kind: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"{kind} names must be non-empty strings")
    try:
        identifier = parse_one(value.strip(), read=dialect.sqlglot_name, into=exp.Identifier)
    except (ParseError, TokenError, ValueError, TypeError) as exc:
        raise ConfigurationError(f"invalid {kind} identifier: {value!r}") from exc
    return canonical_identifier(identifier, dialect, kind=IdentifierKind(kind))


def canonical_policy_function(value: str, dialect: DialectSpec) -> str:
    """Normalize a possibly schema-qualified function policy name."""

    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError("function names must be non-empty strings")
    try:
        function = parse_one(value.strip(), read=dialect.sqlglot_name, into=exp.Table)
    except (ParseError, TokenError, ValueError, TypeError) as exc:
        raise ConfigurationError(f"invalid function identifier: {value!r}") from exc
    if function.args.get("alias") is not None:
        raise ConfigurationError("function policy names must not contain aliases")
    identifiers = [
        function.args.get("catalog"),
        function.args.get("db"),
        function.args.get("this"),
    ]
    if not all(item is None or isinstance(item, exp.Identifier) for item in identifiers):
        raise ConfigurationError(f"invalid function identifier: {value!r}")
    present = [item for item in identifiers if isinstance(item, exp.Identifier)]
    return ".".join(
        canonical_identifier(
            item,
            dialect,
            kind=IdentifierKind.FUNCTION if index == len(present) - 1 else IdentifierKind.TABLE,
        )
        for index, item in enumerate(present)
    )


def canonical_table(table: exp.Table, dialect: DialectSpec) -> str:
    identifiers = [table.args.get("catalog"), table.args.get("db"), table.args.get("this")]
    if not all(item is None or isinstance(item, exp.Identifier) for item in identifiers):
        raise ValueError("table name contains an unsupported identifier expression")
    return ".".join(
        canonical_identifier(item, dialect, kind=IdentifierKind.TABLE)
        for item in identifiers
        if isinstance(item, exp.Identifier)
    )


def canonical_source_alias(reference: exp.Expression, dialect: DialectSpec) -> str:
    alias = reference.args.get("alias")
    if isinstance(alias, exp.TableAlias) and isinstance(alias.this, exp.Identifier):
        return canonical_identifier(alias.this, dialect, kind=IdentifierKind.ALIAS)
    this = reference.args.get("this")
    if isinstance(this, exp.Identifier):
        return canonical_identifier(this, dialect, kind=IdentifierKind.ALIAS)
    raise ValueError("source alias could not be resolved")


def canonical_function(function: exp.Func, dialect: DialectSpec) -> str:
    if isinstance(function, exp.Anonymous):
        this = function.args.get("this")
        if isinstance(this, str):
            this = exp.Identifier(this=this, quoted=False)
        if not isinstance(this, exp.Identifier):
            raise ValueError("function name is not an identifier")
        name = canonical_identifier(this, dialect, kind=IdentifierKind.FUNCTION)
    else:
        name = canonical_identifier(
            exp.Identifier(this=function.sql_name(), quoted=False),
            dialect,
            kind=IdentifierKind.FUNCTION,
        )

    parent = function.parent
    if isinstance(parent, exp.Dot) and parent.expression is function:
        prefix = _canonical_dot_prefix(parent.this, dialect)
        return f"{prefix}.{name}"
    return name


def _canonical_dot_prefix(expression: exp.Expression, dialect: DialectSpec) -> str:
    if isinstance(expression, exp.Identifier):
        return canonical_identifier(expression, dialect, kind=IdentifierKind.TABLE)
    if isinstance(expression, exp.Dot):
        left = _canonical_dot_prefix(expression.this, dialect)
        right = expression.expression
        if not isinstance(right, exp.Identifier):
            raise ValueError("qualified name contains an unsupported expression")
        return f"{left}.{canonical_identifier(right, dialect, kind=IdentifierKind.TABLE)}"
    raise ValueError("qualified name contains an unsupported expression")


def _requires_quotes(value: str, dialect: DialectSpec, kind: IdentifierKind) -> bool:
    if dialect.case_for(kind) is IdentifierCase.LOWER_UNQUOTED and value != value.lower():
        return True
    if dialect.case_for(kind) is IdentifierCase.UPPER_UNQUOTED and value != value.upper():
        return True
    if not _SIMPLE_IDENTIFIER.fullmatch(value):
        return True
    try:
        expression = parse_one(
            f"SELECT {value} FROM guardrail_kit_identifier", read=dialect.sqlglot_name
        ).expressions[0]
    except (ParseError, TokenError, ValueError):
        return True
    identifier = expression.args.get("this") if isinstance(expression, exp.Column) else None
    return not (
        isinstance(identifier, exp.Identifier)
        and not identifier.args.get("quoted")
        and identifier.this == value
    )
