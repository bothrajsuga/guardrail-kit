from __future__ import annotations

from typing import Any

from guardrail_kit.integrations.langchain.exceptions import GuardedToolError
from guardrail_kit.integrations.langchain.policy import ToolGuardPolicy


def guard_tool(tool: Any, *, policy: ToolGuardPolicy) -> Any:
    """Return a LangChain tool protected immediately before execution.

    The optional dependency is imported lazily. The returned StructuredTool
    preserves the protected tool's public schema and common metadata. Direct
    use of the original tool remains outside this security boundary.
    """

    try:
        from langchain_core.tools import BaseTool, StructuredTool
    except ImportError as exc:
        raise ImportError(
            "LangChain integration requires: pip install 'guardrail-kit[langchain]'"
        ) from exc

    if not isinstance(tool, BaseTool):
        raise TypeError("tool must be a LangChain BaseTool or StructuredTool")

    def guarded_sync(*positional: Any, **arguments: Any) -> Any:
        arguments = _arguments_from_call(tool, positional, arguments)
        inspected = policy.inspect_input(arguments)
        if not inspected.allowed or not isinstance(inspected.value, dict):
            raise GuardedToolError(inspected.reason_code)
        failed = False
        try:
            output = tool.invoke(inspected.value)
        except Exception:
            failed = True
            output = None
        if failed:
            raise GuardedToolError("tool_execution_error")
        return _inspect_output(policy, output)

    async def guarded_async(*positional: Any, **arguments: Any) -> Any:
        arguments = _arguments_from_call(tool, positional, arguments)
        inspected = policy.inspect_input(arguments)
        if not inspected.allowed or not isinstance(inspected.value, dict):
            raise GuardedToolError(inspected.reason_code)
        failed = False
        try:
            output = await tool.ainvoke(inspected.value)
        except Exception:
            failed = True
            output = None
        if failed:
            raise GuardedToolError("tool_execution_error")
        return _inspect_output(policy, output)

    return StructuredTool.from_function(
        func=guarded_sync,
        coroutine=guarded_async,
        name=tool.name,
        description=tool.description,
        args_schema=tool.args_schema,
        infer_schema=False,
        return_direct=tool.return_direct,
        response_format=tool.response_format,
        tags=list(tool.tags) if tool.tags is not None else None,
        metadata=dict(tool.metadata) if tool.metadata is not None else None,
        handle_validation_error="Tool input rejected by schema validation.",
    )


def _inspect_output(policy: ToolGuardPolicy, output: Any) -> Any:
    inspected = policy.inspect_output(output)
    if not inspected.allowed:
        raise GuardedToolError(inspected.reason_code)
    return inspected.value


def _arguments_from_call(
    tool: Any, positional: tuple[Any, ...], arguments: dict[str, Any]
) -> dict[str, Any]:
    if not positional:
        return arguments
    fields = getattr(tool.args_schema, "model_fields", {})
    if len(positional) != 1 or arguments or len(fields) != 1:
        raise GuardedToolError("invalid_arguments")
    return {next(iter(fields)): positional[0]}
