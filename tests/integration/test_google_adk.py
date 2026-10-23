import asyncio
from dataclasses import dataclass

import pytest

from guardrail_kit.integrations.google_adk import (
    GoogleADKSQLGuardrail,
    create_google_adk_plugin,
    create_guarded_google_adk_tool,
)
from guardrail_kit.sql import SQLPolicy, SQLValidator


@dataclass
class Tool:
    name: str


def test_allowed_query_does_not_short_circuit() -> None:
    callback = GoogleADKSQLGuardrail(
        SQLValidator(SQLPolicy(allowed_tables={"users"})), tool_names={"run_sql"}
    )
    assert asyncio.run(callback(Tool("run_sql"), {"query": "SELECT id FROM users"}, None)) is None


def test_blocked_query_returns_safe_tool_result() -> None:
    callback = GoogleADKSQLGuardrail(
        SQLValidator(SQLPolicy(allowed_tables={"users"})), tool_names={"run_sql"}
    )
    response = asyncio.run(callback(Tool("run_sql"), {"query": "DELETE FROM users"}, None))
    assert response == {
        "error": "guardrail_blocked",
        "reason_code": "statement_not_allowed",
        "message": "Only SELECT statements are supported.",
    }


def test_unrelated_tool_is_unchanged() -> None:
    callback = GoogleADKSQLGuardrail(
        SQLValidator(SQLPolicy(allowed_tables={"users"})), tool_names={"run_sql"}
    )
    assert asyncio.run(callback(Tool("weather"), {}, None)) is None


def test_compatibility_callback_blocks_unexpected_validator_failure() -> None:
    class BrokenValidator(SQLValidator):
        def _inspect(self, expression: object) -> object:
            del expression
            raise RuntimeError("sensitive internal failure")

    callback = GoogleADKSQLGuardrail(
        BrokenValidator(SQLPolicy(allowed_tables={"users"})), tool_names={"run_sql"}
    )
    response = asyncio.run(callback(Tool("run_sql"), {"query": "SELECT id FROM users"}, None))
    assert response is not None
    assert response["reason_code"] == "validation_error"


def _require_adk() -> None:
    pytest.importorskip("google.adk.tools.function_tool", reason="Google ADK extra not installed")


def test_guarded_tool_blocks_without_invoking_protected_callable() -> None:
    _require_adk()
    calls: list[str] = []

    def run_sql(query: str) -> dict[str, str]:
        calls.append(query)
        return {"status": "executed"}

    guarded = create_guarded_google_adk_tool(
        run_sql,
        SQLValidator(SQLPolicy(allowed_tables={"users"})),
    )
    response = asyncio.run(
        guarded.run_async(args={"query": "DELETE FROM users"}, tool_context=None)
    )
    assert response["reason_code"] == "statement_not_allowed"
    assert calls == []


def test_guarded_tool_executes_the_exact_validated_arguments() -> None:
    _require_adk()
    calls: list[str] = []

    def run_sql(query: str) -> dict[str, str]:
        calls.append(query)
        return {"status": "executed"}

    guarded = create_guarded_google_adk_tool(
        run_sql,
        SQLValidator(SQLPolicy(allowed_tables={"users"})),
    )
    args = {"query": "SELECT id FROM users"}
    response = asyncio.run(guarded.run_async(args=args, tool_context=None))
    assert response == {"status": "executed"}
    assert calls == [args["query"]]


def test_guarded_base_tool_receives_the_same_validated_argument_dictionary() -> None:
    _require_adk()
    from google.adk.tools.base_tool import BaseTool

    received: list[dict[str, object]] = []

    class RecordingTool(BaseTool):
        def __init__(self) -> None:
            super().__init__(name="run_sql", description="SQL tool")

        async def run_async(
            self, *, args: dict[str, object], tool_context: object
        ) -> dict[str, str]:
            del tool_context
            received.append(args)
            return {"status": "executed"}

    guarded = create_guarded_google_adk_tool(
        RecordingTool(), SQLValidator(SQLPolicy(allowed_tables={"users"}))
    )
    args: dict[str, object] = {"query": "SELECT id FROM users"}
    response = asyncio.run(guarded.run_async(args=args, tool_context=None))
    assert response == {"status": "executed"}
    assert received == [args]
    assert received[0] is args


def test_guarded_tool_uses_the_configured_sqlite_dialect() -> None:
    _require_adk()
    calls: list[str] = []

    def run_sql(query: str) -> dict[str, str]:
        calls.append(query)
        return {"status": "executed"}

    guarded = create_guarded_google_adk_tool(
        run_sql,
        SQLValidator(
            SQLPolicy(
                dialect="sqlite",
                allowed_tables={"users"},
                allowed_columns={"users": {"id"}},
            )
        ),
    )
    query = 'SELECT "ID" FROM "USERS"'
    assert asyncio.run(guarded.run_async(args={"query": query}, tool_context=None)) == {
        "status": "executed"
    }
    assert calls == [query]


@pytest.mark.parametrize("args", [{}, {"query": None}, {"query": 42}])
def test_guarded_tool_blocks_missing_or_invalid_sql(args: dict[str, object]) -> None:
    _require_adk()
    calls = 0

    def run_sql(query: str) -> dict[str, str]:
        nonlocal calls
        calls += 1
        return {"status": "executed"}

    guarded = create_guarded_google_adk_tool(
        run_sql,
        SQLValidator(SQLPolicy(allowed_tables={"users"})),
    )
    response = asyncio.run(guarded.run_async(args=args, tool_context=None))
    assert response["reason_code"] == "invalid_input"
    assert calls == 0


def test_guarded_tool_fails_closed_when_validation_raises() -> None:
    _require_adk()
    calls = 0

    def run_sql(query: str) -> dict[str, str]:
        nonlocal calls
        calls += 1
        return {"status": "executed"}

    class BrokenValidator:
        def validate(self, value: object) -> object:
            raise RuntimeError("sensitive internal failure")

    guarded = create_guarded_google_adk_tool(
        run_sql,
        BrokenValidator(),  # type: ignore[arg-type]
    )
    response = asyncio.run(
        guarded.run_async(args={"query": "SELECT id FROM users"}, tool_context=None)
    )
    assert response == {
        "error": "guardrail_blocked",
        "reason_code": "validation_error",
        "message": "SQL validation could not be completed safely.",
    }
    assert calls == 0


def test_guarded_tool_rejects_custom_adk_request_registration() -> None:
    _require_adk()
    from google.adk.tools.base_tool import BaseTool

    class ReplacingTool(BaseTool):
        def __init__(self) -> None:
            super().__init__(name="run_sql", description="SQL tool")

        async def process_llm_request(self, *, tool_context: object, llm_request: object) -> None:
            del tool_context, llm_request

        async def run_async(
            self, *, args: dict[str, object], tool_context: object
        ) -> dict[str, str]:
            del args, tool_context
            return {"status": "executed"}

    with pytest.raises(TypeError, match="custom process_llm_request"):
        create_guarded_google_adk_tool(
            ReplacingTool(), SQLValidator(SQLPolicy(allowed_tables={"users"}))
        )


def test_guarded_tool_revalidates_arguments_mutated_after_plugin_allow() -> None:
    _require_adk()
    calls = 0
    validator = SQLValidator(SQLPolicy(allowed_tables={"users"}))
    callback = GoogleADKSQLGuardrail(validator, tool_names={"run_sql"})

    def run_sql(query: str) -> dict[str, str]:
        nonlocal calls
        calls += 1
        return {"status": "executed"}

    guarded = create_guarded_google_adk_tool(run_sql, validator)
    args = {"query": "SELECT id FROM users"}
    assert asyncio.run(callback(guarded, args, None)) is None
    args["query"] = "DELETE FROM users"
    response = asyncio.run(guarded.run_async(args=args, tool_context=None))
    assert response["reason_code"] == "statement_not_allowed"
    assert calls == 0


def test_plugin_factory_registers_real_adk_plugin() -> None:
    _require_adk()
    from google.adk.agents import LlmAgent
    from google.adk.apps import App

    validator = SQLValidator(SQLPolicy(allowed_tables={"users"}))
    plugin = create_google_adk_plugin(validator, tool_names={"run_sql"})

    def run_sql(query: str) -> dict[str, str]:
        return {"query": query}

    guarded = create_guarded_google_adk_tool(run_sql, validator)
    agent = LlmAgent(name="sql_agent", model="gemini-2.5-flash", tools=[guarded])
    app = App(name="guardrail_test", root_agent=agent, plugins=[plugin])

    assert app.plugins == [plugin]
    assert agent.tools == [guarded]
    response = asyncio.run(
        plugin.before_tool_callback(
            tool=guarded,
            tool_args={"query": "DELETE FROM users"},
            tool_context=None,
        )
    )
    assert response is not None
    assert response["reason_code"] == "statement_not_allowed"


def test_real_adk_runner_blocks_sql_mutated_by_later_agent_callback() -> None:
    _require_adk()
    from collections.abc import AsyncGenerator

    from google.adk.agents import LlmAgent
    from google.adk.models.base_llm import BaseLlm
    from google.adk.models.llm_request import LlmRequest
    from google.adk.models.llm_response import LlmResponse
    from google.adk.runners import InMemoryRunner
    from google.genai import types

    calls: list[str] = []

    def run_sql(query: str) -> dict[str, str]:
        calls.append(query)
        return {"status": "executed"}

    class ToolCallingLlm(BaseLlm):
        turn: int = 0

        async def generate_content_async(
            self, llm_request: LlmRequest, stream: bool = False
        ) -> AsyncGenerator[LlmResponse, None]:
            del llm_request, stream
            self.turn += 1
            if self.turn == 1:
                yield LlmResponse(
                    content=types.Content(
                        role="model",
                        parts=[
                            types.Part(
                                function_call=types.FunctionCall(
                                    id="call-1",
                                    name="run_sql",
                                    args={"query": "SELECT id FROM users"},
                                )
                            )
                        ],
                    )
                )
            else:
                yield LlmResponse(
                    content=types.Content(role="model", parts=[types.Part(text="done")])
                )

    async def run_agent() -> None:
        validator = SQLValidator(SQLPolicy(allowed_tables={"users"}))
        guarded = create_guarded_google_adk_tool(run_sql, validator)

        async def mutate_sql(
            *, tool: object, args: dict[str, object], tool_context: object
        ) -> None:
            del tool, tool_context
            args["query"] = "DELETE FROM users"

        agent = LlmAgent(
            name="sql_agent",
            model=ToolCallingLlm(model="fake"),
            tools=[guarded],
            before_tool_callback=mutate_sql,
        )
        runner = InMemoryRunner(agent=agent, app_name="guardrail_test")
        await runner.session_service.create_session(
            app_name="guardrail_test", user_id="user", session_id="session"
        )
        try:
            events = [
                event
                async for event in runner.run_async(
                    user_id="user",
                    session_id="session",
                    new_message=types.Content(
                        role="user", parts=[types.Part(text="Run the query")]
                    ),
                )
            ]
            assert events
        finally:
            await runner.close()

    asyncio.run(run_agent())
    assert calls == []
