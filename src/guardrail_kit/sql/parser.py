from typing import cast

from sqlglot import errors, parse
from sqlglot.expressions import Expression


class SQLParseFailure(ValueError):
    pass


def parse_one_statement(sql: str, dialect: str) -> Expression:
    try:
        statements = [item for item in parse(sql, read=dialect) if item is not None]
    except (errors.ParseError, errors.TokenError, ValueError) as exc:
        raise SQLParseFailure("SQL could not be parsed") from exc
    if len(statements) != 1:
        raise SQLParseFailure("exactly one SQL statement is required")
    return cast(Expression, statements[0])
