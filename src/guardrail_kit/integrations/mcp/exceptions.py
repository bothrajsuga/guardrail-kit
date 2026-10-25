class MCPGatewayError(Exception):
    """Value-free MCP gateway rejection safe to expose to callers."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"MCP operation blocked by gateway policy ({reason_code}).")
