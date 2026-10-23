from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

from sqlglot import exp
from sqlglot.errors import ParseError, TokenError
from sqlglot.optimizer.scope import Scope, traverse_scope

from guardrail_kit.core import Decision, GuardrailContext, GuardrailResult
from guardrail_kit.sql.dialects import IdentifierKind
from guardrail_kit.sql.identifiers import (
    canonical_function,
    canonical_identifier,
    canonical_source_alias,
    canonical_table,
)
from guardrail_kit.sql.parser import SQLParseFailure, parse_one_statement
from guardrail_kit.sql.policy import SQLPolicy, UnlistedColumnPolicy


@dataclass(frozen=True, slots=True)
class _Violation:
    code: str
    message: str
    metadata: dict[str, Any] | None = None


class SQLValidator:
    """Parse and structurally validate SQL without executing it."""

    def __init__(self, policy: SQLPolicy):
        self.policy = policy

    def validate(self, sql: str, context: GuardrailContext | None = None) -> GuardrailResult:
        del context  # Reserved for audit correlation; never included in responses.
        if not isinstance(sql, str):
            return self._block("invalid_input", "SQL input must be a string.")
        if not sql.strip():
            return self._block("empty_query", "SQL input must not be empty.")
        if len(sql) > self.policy.max_query_length:
            return self._block(
                "query_too_long",
                "SQL input exceeds the configured maximum length.",
                {"maximum": self.policy.max_query_length},
            )
        if self.policy.allowed_tables is None:
            return self._block(
                "table_allowlist_required",
                "An explicit table allowlist is required by this policy.",
            )

        try:
            expression = parse_one_statement(sql, self.policy._dialect_spec.sqlglot_name)
            violation = self._inspect(expression)
        except SQLParseFailure as exc:
            code = "multiple_statements" if "exactly one" in str(exc) else "parse_error"
            return self._block(code, str(exc).capitalize() + ".")
        except (ParseError, TokenError, ValueError, TypeError, AttributeError):
            return self._block("validation_error", "SQL validation could not be completed safely.")
        except Exception:
            return self._block("validation_error", "SQL validation could not be completed safely.")

        if violation:
            return self._block(violation.code, violation.message, violation.metadata)
        normalized = (
            expression.sql(dialect=self.policy._dialect_spec.sqlglot_name)
            if self.policy.include_normalized_sql
            else None
        )
        return GuardrailResult(
            decision=Decision.ALLOW,
            reason_code="query_allowed",
            message="SQL query is allowed by the configured policy.",
            normalized_input=normalized,
            metadata={"dialect": self.policy.dialect},
        )

    def _inspect(self, expression: exp.Expression) -> _Violation | None:
        if not isinstance(expression, exp.Select):
            return _Violation("statement_not_allowed", "Only SELECT statements are supported.")
        prohibited = (
            exp.DML,
            exp.DDL,
            exp.Drop,
            exp.Alter,
            exp.TruncateTable,
            exp.Grant,
            exp.Revoke,
            exp.Transaction,
            exp.Commit,
            exp.Rollback,
            exp.Execute,
        )
        if any(isinstance(node, prohibited) for node in expression.walk()):
            return _Violation(
                "write_operation_not_allowed",
                "The query contains a non-read-only SQL operation.",
            )
        if expression.find(exp.Into):
            return _Violation("select_into_not_allowed", "SELECT INTO is not allowed.")
        if expression.find(exp.Lock):
            return _Violation("locking_not_allowed", "Locking SELECT statements are not allowed.")
        if expression.find(exp.Command):
            return self._unsupported("The query contains an unsupported construct.")
        for function in expression.find_all(exp.Func):
            name = canonical_function(function, self.policy._dialect_spec)
            if name not in self.policy.allowed_functions:
                return _Violation(
                    "function_not_allowed",
                    "The query calls a function that is not explicitly allowed.",
                )

        scopes = traverse_scope(expression)
        if not scopes:
            return self._unsupported("The query structure is not supported.")
        if any(isinstance(scope.expression, exp.SetOperation) for scope in scopes):
            return self._unsupported("Set operations are not supported.")
        if not self.policy.allow_subqueries and any(scope.is_subquery for scope in scopes):
            return _Violation("subquery_not_allowed", "Subqueries are not allowed by this policy.")
        if not self.policy.allow_ctes and expression.args.get("with_") is not None:
            return _Violation("cte_not_allowed", "CTEs are not allowed by this policy.")

        for scope in scopes:
            select = scope.expression
            if (
                isinstance(select, exp.Select)
                and select.args.get("joins")
                and not self.policy.allow_joins
            ):
                return _Violation("join_not_allowed", "Joins are not allowed by this policy.")
            violation = self._inspect_scope(scope)
            if violation:
                return violation

        limit = expression.args.get("limit")
        if limit is None:
            if self.policy.require_limit:
                return _Violation("limit_required", "A row LIMIT is required by this policy.")
        else:
            limit_expr = limit.expression
            if not isinstance(limit_expr, exp.Literal) or not limit_expr.is_int:
                return _Violation("invalid_limit", "LIMIT must be a positive integer literal.")
            value = int(limit_expr.this)
            if value < 1:
                return _Violation("invalid_limit", "LIMIT must be a positive integer literal.")
            if self.policy.max_limit is not None and value > self.policy.max_limit:
                return _Violation(
                    "limit_exceeded",
                    "LIMIT exceeds the configured maximum.",
                    {"maximum": self.policy.max_limit},
                )
        return None

    def _inspect_scope(self, scope: Scope) -> _Violation | None:
        physical: dict[str, str] = {}
        derived: dict[str, Scope] = {}
        for alias, reference in scope.references:
            source = scope.sources.get(alias)
            if source is None:
                return self._unsupported("A table source alias could not be resolved safely.")
            reference_expression = cast(exp.Expression, reference)
            if isinstance(source, Scope) and isinstance(reference_expression, exp.Select):
                parent = reference_expression.parent
                if not isinstance(parent, exp.Subquery):
                    return self._unsupported("A derived table alias could not be resolved safely.")
                reference_expression = parent
            key = canonical_source_alias(reference_expression, self.policy._dialect_spec)
            if isinstance(source, exp.Table):
                table = canonical_table(source, self.policy._dialect_spec)
                physical[key] = table
                if table not in self.policy.allowed_tables:  # type: ignore[operator]
                    return _Violation(
                        "table_not_allowed", "The query references a table that is not allowed."
                    )
            elif isinstance(source, Scope):
                derived[key] = source
            else:
                return self._unsupported("The query contains an unsupported table source.")

        restricted = bool(self.policy.allowed_columns) or (
            self.policy.unlisted_table_columns is UnlistedColumnPolicy.BLOCK
        )
        if (
            restricted
            and isinstance(scope.expression, exp.Select)
            and any(
                isinstance(selected, exp.Star)
                or (isinstance(selected, exp.Column) and isinstance(selected.this, exp.Star))
                for selected in scope.expression.expressions
            )
        ):
            return _Violation(
                "wildcard_not_allowed",
                "Wildcard columns are not allowed when column restrictions are configured.",
            )
        for column in scope.columns:
            if isinstance(column.this, exp.Star):
                if restricted:
                    return _Violation(
                        "wildcard_not_allowed",
                        "Wildcard columns are not allowed when column restrictions are configured.",
                    )
                continue
            column_identifier = column.args.get("this")
            qualifier_identifier = column.args.get("table")
            if not isinstance(column_identifier, exp.Identifier):
                return self._unsupported("A column name could not be resolved safely.")
            name = canonical_identifier(
                column_identifier, self.policy._dialect_spec, kind=IdentifierKind.COLUMN
            )
            qualifier = (
                canonical_identifier(
                    qualifier_identifier, self.policy._dialect_spec, kind=IdentifierKind.ALIAS
                )
                if isinstance(qualifier_identifier, exp.Identifier)
                else ""
            )
            if qualifier:
                if qualifier in physical:
                    violation = self._check_column(physical[qualifier], name)
                    if violation:
                        return violation
                elif qualifier in derived:
                    if name not in self._scope_outputs(derived[qualifier]):
                        return _Violation(
                            "column_scope_ambiguous",
                            "A column reference could not be resolved safely.",
                        )
                else:
                    return _Violation(
                        "column_scope_ambiguous", "A column qualifier could not be resolved safely."
                    )
            else:
                sources: list[tuple[str, str]] = [("table", table) for table in physical.values()]
                sources.extend(("derived", alias) for alias in derived)
                if len(sources) != 1:
                    return _Violation(
                        "column_scope_ambiguous",
                        "An unqualified column could not be resolved safely.",
                    )
                kind, source_name = sources[0]
                if kind == "table":
                    violation = self._check_column(source_name, name)
                    if violation:
                        return violation
                elif name not in self._scope_outputs(derived[source_name]):
                    return _Violation(
                        "column_scope_ambiguous", "A derived column could not be resolved safely."
                    )
        return None

    def _check_column(self, table: str, column: str) -> _Violation | None:
        allowed = self.policy.allowed_columns.get(table)
        if allowed is None:
            if self.policy.unlisted_table_columns is UnlistedColumnPolicy.ALLOW:
                return None
            return _Violation(
                "column_policy_required",
                "The query references a table without an explicit column policy.",
            )
        if column not in allowed:
            return _Violation(
                "column_not_allowed", "The query references a column that is not allowed."
            )
        return None

    def _scope_outputs(self, scope: Scope) -> set[str]:
        expression = scope.expression
        if not isinstance(expression, exp.Select):
            return set()
        outputs: set[str] = set()
        for selected in expression.expressions:
            if isinstance(selected, exp.Star) or isinstance(selected.this, exp.Star):
                return set()
            name = selected.alias_or_name
            if name:
                alias = selected.args.get("alias")
                if isinstance(alias, exp.Identifier):
                    outputs.add(
                        canonical_identifier(
                            alias, self.policy._dialect_spec, kind=IdentifierKind.COLUMN
                        )
                    )
                elif isinstance(selected, exp.Column):
                    identifier = selected.args.get("this")
                    if isinstance(identifier, exp.Identifier):
                        outputs.add(
                            canonical_identifier(
                                identifier,
                                self.policy._dialect_spec,
                                kind=IdentifierKind.COLUMN,
                            )
                        )
        return outputs

    def _unsupported(self, message: str) -> _Violation:
        # BLOCK is the only accepted policy value in v0.1.x. Keeping this
        # branch explicit makes the compatibility field behavior effective.
        if self.policy.unsupported_constructs.value == "block":
            return _Violation("unsupported_construct", message)
        raise AssertionError("unreachable unsupported-construct policy")

    @staticmethod
    def _block(code: str, message: str, metadata: dict[str, Any] | None = None) -> GuardrailResult:
        return GuardrailResult(
            decision=Decision.BLOCK,
            reason_code=code,
            message=message,
            metadata=metadata or {},
        )
