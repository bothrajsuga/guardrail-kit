from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ParsedSQL:
    expression: object
    normalized_sql: str | None = None
