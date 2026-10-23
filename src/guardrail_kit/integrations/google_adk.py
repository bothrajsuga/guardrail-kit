from __future__ import annotations

from collections.abc import Mapping
from inspect import signature
from typing import Any

from guardrail_kit.sql import SQLValidator


class GoogleADKSQLGuardrail:
    """Google ADK pre-tool callback for SQL-bearing tools.

    This compatibility callback blocks rejected calls, but an allowed argument
    can still be changed by a later callback. Prefer
    :func:`create_guarded_google_adk_tool` for execution-boundary enforcement.
    """

    def __init__(
        self,
        validator: SQLValidator,
        *,
        tool_names: set[str] | frozenset[str],
        argument_name: str = "query",
    ) -> None:
        if not tool_names:
            raise ValueError("tool_names must contain at least one protected tool")
        if not argument_name:
            raise ValueError("argument_name must not be empty")
        self.validator = validator
        self.tool_names = frozenset(tool_names)
        self.argument_name = argument_name

    async def __call__(
        self, tool: Any, tool_args: Mapping[str, Any], tool_context: Any
    ) -> dict[str, Any] | None:
        """Return None to continue, or a dict to short-circuit tool execution."""
        del tool_context
        if getattr(tool, "name", None) not in self.tool_names:
            return None
        value = tool_args.get(self.argument_name)
        result = self.validator.validate(value)  # type: ignore[arg-type]
        if result.allowed:
            return None
        return {
            "error": "guardrail_blocked",
            "reason_code": result.reason_code,
            "message": result.message,
        }


def create_guarded_google_adk_tool(
    tool: Any,
    validator: SQLValidator,
    *,
    argument_name: str = "query",
) -> Any:
    """Wrap an ADK tool and validate its final arguments inside ``run_async``.

    The wrapped tool receives the same argument dictionary that was validated.
    Validation failures and validation exceptions return a safe tool result and
    never invoke the protected tool.
    """

    if not argument_name:
        raise ValueError("argument_name must not be empty")
    try:
        from google.adk.tools.base_tool import BaseTool
        from google.adk.tools.function_tool import FunctionTool
    except ImportError as exc:
        raise ImportError(
            "Google ADK integration requires: pip install 'guardrail-kit[google-adk]'"
        ) from exc

    required_parameters = {"name", "description"}
    constructor_parameters = signature(BaseTool.__init__).parameters
    if not required_parameters.issubset(constructor_parameters) or not callable(
        getattr(BaseTool, "_get_declaration", None)
    ) or not callable(getattr(BaseTool, "process_llm_request", None)):
        raise RuntimeError(
            "unsupported Google ADK version: guardrail-kit requires the secure "
            "BaseTool registration capabilities provided by google-adk>=2.0.0"
        )

    if isinstance(tool, BaseTool):
        protected_tool = tool
    elif callable(tool):
        protected_tool = FunctionTool(tool)
    else:
        raise TypeError("tool must be a Google ADK BaseTool or a callable")
    if type(protected_tool).process_llm_request is not BaseTool.process_llm_request:
        raise TypeError(
            "tools with custom process_llm_request are not supported by the guarded wrapper"
        )

    class GuardedSQLTool(BaseTool):
        def __init__(self) -> None:
            constructor_values: dict[str, Any] = {
                "name": protected_tool.name,
                "description": protected_tool.description,
            }
            for name in (
                "is_long_running",
                "custom_metadata",
                "behavior",
                "response_scheduling",
            ):
                if name in constructor_parameters and hasattr(protected_tool, name):
                    constructor_values[name] = getattr(protected_tool, name)
            super().__init__(**constructor_values)

        def _get_declaration(self) -> Any:
            # BaseTool.process_llm_request must run on this wrapper so ADK's
            # tools_dict points to guarded run_async, not the protected tool.
            return protected_tool._get_declaration()

        async def run_async(self, *, args: dict[str, Any], tool_context: Any) -> Any:
            value = args.get(argument_name)
            try:
                result = validator.validate(value)  # type: ignore[arg-type]
            except Exception:
                return {
                    "error": "guardrail_blocked",
                    "reason_code": "validation_error",
                    "message": "SQL validation could not be completed safely.",
                }
            if not result.allowed:
                return {
                    "error": "guardrail_blocked",
                    "reason_code": result.reason_code,
                    "message": result.message,
                }
            return await protected_tool.run_async(args=args, tool_context=tool_context)

    return GuardedSQLTool()


def create_google_adk_plugin(
    validator: SQLValidator,
    *,
    tool_names: set[str] | frozenset[str],
    argument_name: str = "query",
    name: str = "guardrail_kit_sql",
) -> Any:
    """Create an ADK pre-tool policy plugin.

    The plugin is useful for application-wide early rejection. It cannot stop
    later callbacks from mutating an allowed argument; protected database tools
    should also be wrapped with :func:`create_guarded_google_adk_tool`.
    """
    try:
        from google.adk.plugins.base_plugin import BasePlugin
    except ImportError as exc:
        raise ImportError(
            "Google ADK integration requires: pip install 'guardrail-kit[google-adk]'"
        ) from exc

    callback = GoogleADKSQLGuardrail(validator, tool_names=tool_names, argument_name=argument_name)

    class SQLGuardrailPlugin(BasePlugin):
        def __init__(self) -> None:
            super().__init__(name=name)

        async def before_tool_callback(
            self, *, tool: Any, tool_args: dict[str, Any], tool_context: Any
        ) -> dict[str, Any] | None:
            return await callback(tool, tool_args, tool_context)

    return SQLGuardrailPlugin()
