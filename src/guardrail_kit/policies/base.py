from typing import Protocol


class Policy(Protocol):
    """Marker contract for immutable, validated policy objects."""

    def validate_configuration(self) -> None: ...
