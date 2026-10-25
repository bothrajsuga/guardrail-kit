from __future__ import annotations

import asyncio
from typing import Any

import pytest
from langchain_core.tools import BaseTool, StructuredTool
from pydantic import BaseModel

from guardrail_kit.integrations.langchain import GuardedToolError, ToolGuardPolicy, guard_tool
from guardrail_kit.pii import PIIGuard, PIIPolicy
from guardrail_kit.sql import SQLPolicy, SQLValidator


class EchoArgs(BaseModel):
    text: str
    nested: dict[str, Any] | None = None


def _echo_tool(calls: list[dict[str, Any]], *, fail: bool = False) -> BaseTool:
    def echo(text: str, nested: dict[str, Any] | None = None) -> dict[str, Any]:
        calls.append({"text": text, "nested": nested})
        if fail:
            raise RuntimeError(text)
        return {"text": text, "nested": nested}

    async def async_echo(text: str, nested: dict[str, Any] | None = None) -> dict[str, Any]:
        await asyncio.sleep(0)
        return echo(text, nested)

    return StructuredTool.from_function(
        echo,
        coroutine=async_echo,
        name="echo",
        description="Echo structured input.",
        args_schema=EchoArgs,
        tags=["synthetic"],
        metadata={"owner": "tests"},
    )


def test_allowed_sync_call_executes_once_and_preserves_metadata() -> None:
    calls: list[dict[str, Any]] = []
    original = _echo_tool(calls)
    guarded = guard_tool(original, policy=ToolGuardPolicy())

    result = guarded.invoke({"text": "hello", "nested": {"items": ["safe"]}})

    assert result == {"text": "hello", "nested": {"items": ["safe"]}}
    assert calls == [{"text": "hello", "nested": {"items": ["safe"]}}]
    assert guarded.name == original.name
    assert guarded.description == original.description
    assert guarded.args_schema is original.args_schema
    assert guarded.tags == ["synthetic"]
    assert guarded.metadata == {"owner": "tests"}


@pytest.mark.anyio
async def test_allowed_async_call_executes_once() -> None:
    calls: list[dict[str, Any]] = []
    guarded = guard_tool(_echo_tool(calls), policy=ToolGuardPolicy())

    assert await guarded.ainvoke({"text": "hello"}) == {"text": "hello", "nested": None}
    assert calls == [{"text": "hello", "nested": None}]


def test_pii_block_executes_zero_times_and_exception_is_sanitized() -> None:
    calls: list[dict[str, Any]] = []
    guarded = guard_tool(_echo_tool(calls), policy=ToolGuardPolicy(input_guard=PIIGuard()))

    with pytest.raises(GuardedToolError) as caught:
        guarded.run({"text": "contact private.person@example.com"})

    assert calls == []
    assert "private.person" not in str(caught.value)
    assert caught.value.reason_code == "sensitive_data_blocked"


def test_nested_input_is_redacted_without_mutating_original_arguments() -> None:
    calls: list[dict[str, Any]] = []
    guarded = guard_tool(
        _echo_tool(calls),
        policy=ToolGuardPolicy(input_guard=PIIGuard(PIIPolicy(action="redact"))),
    )
    arguments = {"text": "safe", "nested": {"contact": "private.person@example.com"}}

    guarded.invoke(arguments)

    assert arguments["nested"] == {"contact": "private.person@example.com"}
    assert calls[0]["nested"] == {"contact": "[REDACTED]"}


def test_sql_policy_blocks_before_execution() -> None:
    class QueryArgs(BaseModel):
        query: str

    calls: list[str] = []

    def query(query: str) -> str:
        calls.append(query)
        return query

    original = StructuredTool.from_function(
        query, name="query", description="Run query", args_schema=QueryArgs
    )
    validator = SQLValidator(SQLPolicy(dialect="sqlite", allowed_tables={"users"}))
    guarded = guard_tool(original, policy=ToolGuardPolicy(sql_validator=validator))

    with pytest.raises(GuardedToolError) as caught:
        guarded.invoke({"query": "DELETE FROM users"})

    assert caught.value.reason_code == "statement_not_allowed"
    assert calls == []


def test_transformed_sql_is_the_exact_sql_validated_and_executed() -> None:
    class QueryArgs(BaseModel):
        query: str

    class RecordingValidator(SQLValidator):
        seen: list[str]

        def __init__(self) -> None:
            super().__init__(SQLPolicy(dialect="sqlite", allowed_tables={"users"}))
            self.seen = []

        def validate(self, sql: str, context: Any = None) -> Any:
            self.seen.append(sql)
            return super().validate(sql, context)

    executed: list[str] = []

    def query(query: str) -> str:
        executed.append(query)
        return query

    original = StructuredTool.from_function(
        query, name="query", description="Run query", args_schema=QueryArgs
    )
    validator = RecordingValidator()
    guarded = guard_tool(
        original,
        policy=ToolGuardPolicy(
            sql_validator=validator,
            input_guard=PIIGuard(PIIPolicy(action="redact")),
        ),
    )

    result = guarded.invoke({"query": "SELECT id FROM users /* private.person@example.com */"})

    expected = "SELECT id FROM users /* [REDACTED] */"
    assert validator.seen == [expected]
    assert executed == [expected]
    assert result == expected


def test_transformation_that_makes_sql_invalid_fails_closed() -> None:
    class QueryArgs(BaseModel):
        query: str

    executed: list[str] = []

    def query(query: str) -> str:
        executed.append(query)
        return query

    original = StructuredTool.from_function(
        query, name="query", description="Run query", args_schema=QueryArgs
    )
    validator = SQLValidator(SQLPolicy(dialect="sqlite", allowed_tables={"users"}))
    guarded = guard_tool(
        original,
        policy=ToolGuardPolicy(
            sql_validator=validator,
            input_guard=PIIGuard(PIIPolicy(action="redact")),
        ),
    )

    with pytest.raises(GuardedToolError, match="parse_error"):
        guarded.invoke(
            {"query": "SELECT id FROM users WHERE email = 'private.person@example.com'"}
        )
    assert executed == []


def test_schema_validation_error_does_not_expose_sensitive_input() -> None:
    class IntegerArgs(BaseModel):
        value: int

    calls: list[int] = []

    def consume(value: int) -> int:
        calls.append(value)
        return value

    original = StructuredTool.from_function(
        consume, name="consume", description="Consume integer", args_schema=IntegerArgs
    )
    guarded = guard_tool(original, policy=ToolGuardPolicy())
    secret = "private.person@example.com"

    result = guarded.invoke({"value": secret})

    assert result == "Tool input rejected by schema validation."
    assert secret not in result
    assert calls == []


def test_policy_exception_fails_closed() -> None:
    calls: list[dict[str, Any]] = []

    def broken_hook(arguments: Any) -> bool:
        del arguments
        raise RuntimeError("private.person@example.com")

    guarded = guard_tool(
        _echo_tool(calls), policy=ToolGuardPolicy(input_hooks=(broken_hook,))
    )
    with pytest.raises(GuardedToolError) as caught:
        guarded.invoke({"text": "private.person@example.com"})
    assert calls == []
    assert str(caught.value) == "Tool execution blocked by guardrail policy (policy_error)."


def test_hook_receives_immutable_arguments() -> None:
    calls: list[dict[str, Any]] = []

    def mutating_hook(arguments: Any) -> bool:
        arguments["nested"]["value"] = "changed"
        return True

    guarded = guard_tool(
        _echo_tool(calls), policy=ToolGuardPolicy(input_hooks=(mutating_hook,))
    )
    with pytest.raises(GuardedToolError) as caught:
        guarded.invoke({"text": "safe", "nested": {"value": "original"}})
    assert caught.value.reason_code == "policy_error"
    assert calls == []


def test_output_is_redacted_after_execution() -> None:
    calls: list[dict[str, Any]] = []
    guarded = guard_tool(
        _echo_tool(calls),
        policy=ToolGuardPolicy(output_guard=PIIGuard(PIIPolicy(action="redact"))),
    )

    result = guarded.invoke({"text": "private.person@example.com"})

    assert len(calls) == 1
    assert result["text"] == "[REDACTED]"


def test_tool_exception_does_not_expose_original_exception() -> None:
    secret = "private.person@example.com"
    guarded = guard_tool(_echo_tool([], fail=True), policy=ToolGuardPolicy())

    with pytest.raises(GuardedToolError) as caught:
        guarded.invoke({"text": secret})

    assert secret not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


@pytest.mark.anyio
async def test_concurrent_calls_keep_arguments_isolated() -> None:
    calls: list[dict[str, Any]] = []
    guarded = guard_tool(
        _echo_tool(calls),
        policy=ToolGuardPolicy(input_guard=PIIGuard(PIIPolicy(action="redact"))),
    )
    inputs = [
        {"text": f"user{i}@example.com", "nested": {"index": i}} for i in range(10)
    ]

    results = await asyncio.gather(*(guarded.ainvoke(value) for value in inputs))

    assert len(calls) == 10
    assert all(result["text"] == "[REDACTED]" for result in results)
    assert sorted(call["nested"]["index"] for call in calls) == list(range(10))


@pytest.mark.anyio
async def test_async_policy_block_and_tool_failure_are_sanitized() -> None:
    blocked_calls: list[dict[str, Any]] = []
    blocked = guard_tool(
        _echo_tool(blocked_calls), policy=ToolGuardPolicy(input_guard=PIIGuard())
    )
    with pytest.raises(GuardedToolError, match="sensitive_data_blocked"):
        await blocked.arun({"text": "private.person@example.com"})
    assert blocked_calls == []

    failing = guard_tool(_echo_tool([], fail=True), policy=ToolGuardPolicy())
    with pytest.raises(GuardedToolError, match="tool_execution_error") as caught:
        await failing.ainvoke({"text": "private.person@example.com"})
    assert caught.value.__context__ is None


def test_output_block_happens_after_one_execution() -> None:
    calls: list[dict[str, Any]] = []
    guarded = guard_tool(_echo_tool(calls), policy=ToolGuardPolicy(output_guard=PIIGuard()))

    with pytest.raises(GuardedToolError, match="sensitive_data_blocked"):
        guarded.invoke({"text": "private.person@example.com"})

    assert len(calls) == 1


def test_custom_policy_false_blocks_and_invalid_configuration_is_rejected() -> None:
    calls: list[dict[str, Any]] = []
    guarded = guard_tool(
        _echo_tool(calls), policy=ToolGuardPolicy(input_hooks=(lambda arguments: False,))
    )
    with pytest.raises(GuardedToolError, match="custom_policy_blocked"):
        guarded.invoke({"text": "safe"})
    assert calls == []

    validator = SQLValidator(SQLPolicy(dialect="sqlite", allowed_tables={"users"}))
    with pytest.raises(ValueError, match="sql_argument"):
        ToolGuardPolicy(sql_validator=validator, sql_argument="")


def test_nested_output_redaction_preserves_container_shapes() -> None:
    policy = ToolGuardPolicy(output_guard=PIIGuard(PIIPolicy(action="redact")))
    result = policy.inspect_output(
        {"items": ["private.person@example.com", ("safe", "other.person@example.com")]}
    )
    assert result.allowed
    assert result.value == {"items": ["[REDACTED]", ("safe", "[REDACTED]")]}


def test_guard_tool_rejects_non_langchain_objects() -> None:
    with pytest.raises(TypeError, match="BaseTool"):
        guard_tool(object(), policy=ToolGuardPolicy())
