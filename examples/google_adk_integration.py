"""Add the callback to an existing ADK LlmAgent.

This example constructs the verified callback without invoking a model or database.
"""

from google.adk.agents import LlmAgent

from guardrail_kit import SQLPolicy, SQLValidator
from guardrail_kit.integrations.google_adk import create_guarded_google_adk_tool


def run_sql(query: str) -> dict[str, object]:
    """Execute SQL using application-managed database access."""
    raise NotImplementedError("Connect this example to a read-only database account")


guarded_run_sql = create_guarded_google_adk_tool(
    run_sql,
    SQLValidator(SQLPolicy(allowed_tables={"analytics.orders"}, require_limit=True)),
)

agent = LlmAgent(
    name="sql_agent",
    model="gemini-2.5-flash",
    instruction="Use run_sql when needed.",
    tools=[guarded_run_sql],
)
print(agent.name)
