from __future__ import annotations

import asyncio
from typing import Any

import pytest
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import StructuredTool
from langgraph.graph import END, MessagesState, StateGraph
from pydantic import BaseModel

from guardrail_kit.integrations.langchain import ToolGuardPolicy
from guardrail_kit.integrations.langgraph import create_guarded_tool_node
from guardrail_kit.pii import PIIGuard


class ValueArgs(BaseModel):
    value: str


def _tool(name: str, calls: list[tuple[str, str]]) -> StructuredTool:
    def execute(value: str) -> str:
        calls.append((name, value))
        return value

    async def execute_async(value: str) -> str:
        await asyncio.sleep(0)
        return execute(value)

    return StructuredTool.from_function(
        execute,
        coroutine=execute_async,
        name=name,
        description=f"Synthetic {name}",
        args_schema=ValueArgs,
    )


def _state(*calls: dict[str, Any]) -> dict[str, Any]:
    return {"messages": [AIMessage(content="", tool_calls=list(calls))]}


def _graph(node: Any) -> Any:
    builder = StateGraph(MessagesState)
    builder.add_node("tools", node)
    builder.set_entry_point("tools")
    builder.add_edge("tools", END)
    return builder.compile()


def test_tool_node_executes_multiple_guarded_calls() -> None:
    executed: list[tuple[str, str]] = []
    node = create_guarded_tool_node(
        [_tool("first", executed), _tool("second", executed)],
        policies={"first": ToolGuardPolicy(), "second": ToolGuardPolicy()},
    )

    result = _graph(node).invoke(
        _state(
            {"name": "first", "args": {"value": "one"}, "id": "1", "type": "tool_call"},
            {"name": "second", "args": {"value": "two"}, "id": "2", "type": "tool_call"},
        )
    )

    assert sorted(executed) == [("first", "one"), ("second", "two")]
    tool_messages = [message for message in result["messages"] if isinstance(message, ToolMessage)]
    assert len(tool_messages) == 2


@pytest.mark.anyio
async def test_tool_node_async_concurrent_execution_is_guarded() -> None:
    executed: list[tuple[str, str]] = []
    node = create_guarded_tool_node(
        [_tool("echo", executed)], policies={"echo": ToolGuardPolicy()}
    )
    calls = tuple(
        {"name": "echo", "args": {"value": str(index)}, "id": str(index), "type": "tool_call"}
        for index in range(8)
    )

    result = await _graph(node).ainvoke(_state(*calls))

    assert len(executed) == 8
    assert len([item for item in result["messages"] if isinstance(item, ToolMessage)]) == 8


def test_tool_node_policy_failure_returns_safe_error_and_does_not_execute() -> None:
    executed: list[tuple[str, str]] = []
    node = create_guarded_tool_node(
        [_tool("echo", executed)],
        policies={"echo": ToolGuardPolicy(input_guard=PIIGuard())},
    )

    result = _graph(node).invoke(
        _state(
            {
                "name": "echo",
                "args": {"value": "private.person@example.com"},
                "id": "1",
                "type": "tool_call",
            }
        )
    )

    assert executed == []
    message = next(item for item in result["messages"] if isinstance(item, ToolMessage))
    assert message.status == "error"
    assert "private.person" not in str(message.content)


def test_tool_node_requires_policy_for_every_tool() -> None:
    with pytest.raises(ValueError, match="explicit guard policy"):
        create_guarded_tool_node([_tool("echo", [])], policies={})


def test_tool_node_rejects_empty_tool_set() -> None:
    with pytest.raises(ValueError, match="at least one"):
        create_guarded_tool_node([], policies={})


def test_tool_node_rejects_tool_without_string_name() -> None:
    class InvalidTool:
        name = None

    with pytest.raises(TypeError, match="string name"):
        create_guarded_tool_node([InvalidTool()], policies={})
