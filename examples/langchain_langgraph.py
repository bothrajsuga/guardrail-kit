from langchain_core.tools import tool

from guardrail_kit import SQLPolicy, SQLValidator
from guardrail_kit.integrations.langchain import ToolGuardPolicy, guard_tool
from guardrail_kit.integrations.langgraph import create_guarded_tool_node
from guardrail_kit.pii import PIIGuard, PIIPolicy


@tool
def run_query(query: str) -> str:
    """Run a query using an application-owned read-only connection."""
    return query  # Replace with a least-privilege database call.


validator = SQLValidator(
    SQLPolicy(dialect="sqlite", allowed_tables={"users"}, require_limit=True)
)
policy = ToolGuardPolicy(
    sql_validator=validator,
    input_guard=PIIGuard(PIIPolicy(action="redact")),
    output_guard=PIIGuard(PIIPolicy(action="redact")),
)

secured_query = guard_tool(run_query, policy=policy)
print(secured_query.invoke({"query": "SELECT id FROM users LIMIT 10"}))

# Add this node to a StateGraph. Every supplied tool requires an explicit policy.
tool_node = create_guarded_tool_node([run_query], policies={"run_query": policy})
assert tool_node is not None
