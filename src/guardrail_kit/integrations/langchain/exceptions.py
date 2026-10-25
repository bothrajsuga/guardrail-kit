try:
    from langchain_core.tools import ToolException
except ImportError as exc:  # pragma: no cover - exercised in a clean optional-dependency smoke test
    raise ImportError(
        "LangChain integration requires: pip install 'guardrail-kit[langchain]'"
    ) from exc


class GuardedToolError(ToolException):
    """Sanitized failure raised when a guarded tool call cannot be allowed."""

    def __init__(self, reason_code: str = "policy_blocked") -> None:
        self.reason_code = reason_code
        super().__init__(f"Tool execution blocked by guardrail policy ({reason_code}).")
