from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class MCPServerIdentity:
    """Trusted client-side identity binding, never derived from server metadata."""

    identifier: str
    transport: str
    endpoint: str
    verification: str = "configured"

    def __post_init__(self) -> None:
        for field in (self.identifier, self.transport, self.endpoint, self.verification):
            if not field or not field.isascii():
                raise ValueError("server identity fields must be non-empty ASCII strings")
