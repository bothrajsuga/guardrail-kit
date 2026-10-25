from __future__ import annotations

from collections.abc import Set
from dataclasses import dataclass, field

from guardrail_kit.core.errors import ConfigurationError
from guardrail_kit.pii.models import SensitiveEntity

_DEFAULT_SECRET_ENTITIES = frozenset(
    {
        SensitiveEntity.AWS_ACCESS_KEY_ID,
        SensitiveEntity.GITHUB_TOKEN,
        SensitiveEntity.API_KEY,
        SensitiveEntity.PEM_PRIVATE_KEY,
        SensitiveEntity.BEARER_TOKEN,
    }
)
_SECRET_ENTITIES = _DEFAULT_SECRET_ENTITIES | {SensitiveEntity.HIGH_ENTROPY}


@dataclass(frozen=True, slots=True)
class SecretPolicy:
    enabled_entities: Set[SensitiveEntity | str] = field(
        default_factory=lambda: _DEFAULT_SECRET_ENTITIES
    )
    enable_high_entropy: bool = False
    minimum_entropy: float = 4.2
    minimum_entropy_length: int = 20

    def __post_init__(self) -> None:
        if not isinstance(self.enabled_entities, Set) or isinstance(
            self.enabled_entities, (str, bytes)
        ):
            raise ConfigurationError("secret enabled_entities must be a set")
        try:
            entities = frozenset(SensitiveEntity(value) for value in self.enabled_entities)
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(
                "secret enabled_entities contains an unknown entity type"
            ) from exc
        if not entities <= _SECRET_ENTITIES:
            raise ConfigurationError("secret policy contains a non-secret entity type")
        if not isinstance(self.enable_high_entropy, bool):
            raise ConfigurationError("enable_high_entropy must be a boolean")
        if not isinstance(self.minimum_entropy, (int, float)) or isinstance(
            self.minimum_entropy, bool
        ):
            raise ConfigurationError("minimum_entropy must be numeric")
        entropy = float(self.minimum_entropy)
        if not 0.0 < entropy <= 8.0:
            raise ConfigurationError("minimum_entropy must be between 0 and 8")
        if (
            not isinstance(self.minimum_entropy_length, int)
            or isinstance(self.minimum_entropy_length, bool)
            or self.minimum_entropy_length < 12
        ):
            raise ConfigurationError("minimum_entropy_length must be at least 12")
        if self.enable_high_entropy:
            entities = entities | {SensitiveEntity.HIGH_ENTROPY}
        else:
            entities = entities - {SensitiveEntity.HIGH_ENTROPY}
        object.__setattr__(self, "enabled_entities", entities)
        object.__setattr__(self, "minimum_entropy", entropy)
