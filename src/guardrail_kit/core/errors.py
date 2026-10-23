class GuardrailKitError(Exception):
    """Base exception for setup and programming errors."""


class ConfigurationError(GuardrailKitError, ValueError):
    """Raised for an invalid guardrail policy."""
