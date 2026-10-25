from __future__ import annotations

import re
from collections.abc import Mapping, Set
from dataclasses import dataclass, field
from types import MappingProxyType

from guardrail_kit.core.errors import ConfigurationError
from guardrail_kit.pii.models import SensitiveAction, SensitiveEntity

_PII_ENTITIES = frozenset(
    {
        SensitiveEntity.EMAIL,
        SensitiveEntity.PHONE,
        SensitiveEntity.IPV4,
        SensitiveEntity.IPV6,
        SensitiveEntity.PAYMENT_CARD,
        SensitiveEntity.INDIAN_PAN,
        SensitiveEntity.INDIAN_AADHAAR,
        SensitiveEntity.CUSTOM_IDENTIFIER,
    }
)
_PHONE_REGIONS = frozenset({"international", "us_ca", "in"})
_UNSAFE_REGEX = re.compile(
    r"\\[1-9]|\\g<|\(\?<[=!]|\(\?P=|\(\?\(|\([^)]*[+*][^)]*\)[+*{]"
)


def validate_configured_pattern(name: str, pattern: str) -> re.Pattern[str]:
    if not isinstance(name, str) or not name or not name.isascii():
        raise ConfigurationError("custom pattern names must be non-empty ASCII strings")
    if not isinstance(pattern, str) or not pattern:
        raise ConfigurationError("custom patterns must be non-empty strings")
    if len(pattern) > 500:
        raise ConfigurationError("custom patterns must not exceed 500 characters")
    if _UNSAFE_REGEX.search(pattern):
        raise ConfigurationError("custom pattern contains a disallowed regex construct")
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise ConfigurationError(f"invalid custom pattern: {name!r}") from exc
    if compiled.groups:
        raise ConfigurationError("custom patterns must not contain capturing groups")
    if compiled.match("") is not None:
        raise ConfigurationError("custom patterns must not match empty text")
    return compiled


def validate_exclusion_pattern(pattern: str) -> re.Pattern[str]:
    return validate_configured_pattern("exclusion", pattern)


@dataclass(frozen=True, slots=True)
class PIIPolicy:
    action: SensitiveAction | str = SensitiveAction.BLOCK
    enabled_entities: Set[SensitiveEntity | str] = field(default_factory=lambda: _PII_ENTITIES)
    phone_regions: Set[str] = field(default_factory=lambda: frozenset({"international"}))
    custom_patterns: Mapping[str, str] = field(default_factory=dict)
    exclusion_patterns: tuple[str, ...] = ()
    include_secrets: bool = True
    max_input_length: int = 100_000
    _compiled_custom_patterns: Mapping[str, re.Pattern[str]] = field(
        init=False, repr=False, compare=False
    )
    _compiled_exclusions: tuple[re.Pattern[str], ...] = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        try:
            action = SensitiveAction(self.action)
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(f"invalid PII action: {self.action!r}") from exc
        if not isinstance(self.enabled_entities, Set) or isinstance(
            self.enabled_entities, (str, bytes)
        ):
            raise ConfigurationError("enabled_entities must be a set")
        try:
            entities = frozenset(SensitiveEntity(value) for value in self.enabled_entities)
        except (TypeError, ValueError) as exc:
            raise ConfigurationError("enabled_entities contains an unknown entity type") from exc
        if not entities <= _PII_ENTITIES:
            raise ConfigurationError("PII policy contains a non-PII entity type")
        if not isinstance(self.phone_regions, Set) or isinstance(self.phone_regions, (str, bytes)):
            raise ConfigurationError("phone_regions must be a set")
        regions = frozenset(self.phone_regions)
        if not all(isinstance(region, str) for region in regions) or not regions <= _PHONE_REGIONS:
            raise ConfigurationError("phone_regions contains an unsupported region")
        if not isinstance(self.custom_patterns, Mapping):
            raise ConfigurationError("custom_patterns must be a mapping")
        compiled_custom = {
            name: validate_configured_pattern(name, pattern)
            for name, pattern in self.custom_patterns.items()
        }
        if not isinstance(self.exclusion_patterns, tuple) or not all(
            isinstance(pattern, str) for pattern in self.exclusion_patterns
        ):
            raise ConfigurationError("exclusion_patterns must be a tuple of strings")
        compiled_exclusions = tuple(
            validate_exclusion_pattern(pattern) for pattern in self.exclusion_patterns
        )
        if not isinstance(self.include_secrets, bool):
            raise ConfigurationError("include_secrets must be a boolean")
        if (
            not isinstance(self.max_input_length, int)
            or isinstance(self.max_input_length, bool)
            or self.max_input_length < 1
        ):
            raise ConfigurationError("max_input_length must be a positive integer")
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "enabled_entities", entities)
        object.__setattr__(self, "phone_regions", regions)
        object.__setattr__(self, "custom_patterns", MappingProxyType(dict(self.custom_patterns)))
        object.__setattr__(self, "_compiled_custom_patterns", MappingProxyType(compiled_custom))
        object.__setattr__(self, "_compiled_exclusions", compiled_exclusions)
