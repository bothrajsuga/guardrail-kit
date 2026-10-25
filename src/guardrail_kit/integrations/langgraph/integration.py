from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from guardrail_kit.integrations.langchain import ToolGuardPolicy, guard_tool


def create_guarded_tool_node(
    tools: Iterable[Any],
    *,
    policies: Mapping[str, ToolGuardPolicy],
    handle_errors: bool = True,
) -> Any:
    """Create a ToolNode containing only execution-boundary guarded tools."""

    try:
        from langgraph.prebuilt import ToolNode
    except ImportError as exc:
        raise ImportError(
            "LangGraph integration requires: pip install 'guardrail-kit[langgraph]'"
        ) from exc

    guarded = []
    for tool in tools:
        name = getattr(tool, "name", None)
        if not isinstance(name, str):
            raise TypeError("each tool must expose a string name")
        policy = policies.get(name)
        if policy is None:
            raise ValueError("every ToolNode tool must have an explicit guard policy")
        guarded.append(guard_tool(tool, policy=policy))
    if not guarded:
        raise ValueError("tools must contain at least one protected tool")
    return ToolNode(guarded, handle_tool_errors=handle_errors)
