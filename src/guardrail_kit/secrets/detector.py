from __future__ import annotations

import math
import re
from collections import Counter

from guardrail_kit.pii.models import SensitiveEntity, SensitiveMatch
from guardrail_kit.secrets.policy import SecretPolicy

_AWS_ACCESS_KEY = re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])")
_GITHUB_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})"
    r"(?![A-Za-z0-9_])"
)
_API_KEY_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|secret|access[_-]?token|client[_-]?secret)"
    r"\s*[:=]\s*[\"']?([A-Za-z0-9][A-Za-z0-9._~+/=-]{7,255})"
)
_PEM_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
    r"[\s\S]{1,100000}?"
    r"-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
)
_BEARER_TOKEN = re.compile(
    r"(?i)(?<![A-Za-z0-9])Bearer\s+([A-Za-z0-9][A-Za-z0-9._~+/=-]{7,4096})"
)
_ENTROPY_CANDIDATE = re.compile(
    r"(?<![A-Za-z0-9])([A-Za-z0-9_+/-]{12,512}={0,2})(?![A-Za-z0-9])"
)


class SecretDetector:
    def __init__(self, policy: SecretPolicy | None = None) -> None:
        self.policy = policy or SecretPolicy()

    def detect(self, text: str) -> tuple[SensitiveMatch, ...]:
        if not isinstance(text, str):
            raise TypeError("secret detector input must be a string")
        matches: list[SensitiveMatch] = []
        self._append_pattern(
            matches, text, SensitiveEntity.AWS_ACCESS_KEY_ID, _AWS_ACCESS_KEY
        )
        self._append_pattern(matches, text, SensitiveEntity.GITHUB_TOKEN, _GITHUB_TOKEN)
        self._append_pattern(
            matches, text, SensitiveEntity.API_KEY, _API_KEY_ASSIGNMENT, group=1
        )
        self._append_pattern(
            matches, text, SensitiveEntity.PEM_PRIVATE_KEY, _PEM_PRIVATE_KEY
        )
        self._append_pattern(
            matches, text, SensitiveEntity.BEARER_TOKEN, _BEARER_TOKEN, group=1
        )
        if SensitiveEntity.HIGH_ENTROPY in self.policy.enabled_entities:
            for candidate in _ENTROPY_CANDIDATE.finditer(text):
                value = candidate.group(1)
                if (
                    len(value) >= self.policy.minimum_entropy_length
                    and _has_character_variety(value)
                    and _shannon_entropy(value) >= self.policy.minimum_entropy
                ):
                    matches.append(
                        SensitiveMatch(
                            SensitiveEntity.HIGH_ENTROPY,
                            candidate.start(1),
                            candidate.end(1),
                        )
                    )
        return tuple(sorted(set(matches), key=_match_sort_key))

    def _append_pattern(
        self,
        matches: list[SensitiveMatch],
        text: str,
        entity_type: SensitiveEntity,
        pattern: re.Pattern[str],
        *,
        group: int = 0,
    ) -> None:
        if entity_type not in self.policy.enabled_entities:
            return
        matches.extend(
            SensitiveMatch(entity_type, match.start(group), match.end(group))
            for match in pattern.finditer(text)
        )


def _shannon_entropy(value: str) -> float:
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _has_character_variety(value: str) -> bool:
    categories = (
        any(character.islower() for character in value),
        any(character.isupper() for character in value),
        any(character.isdigit() for character in value),
        any(not character.isalnum() for character in value),
    )
    return sum(categories) >= 3


def _match_sort_key(match: SensitiveMatch) -> tuple[int, int, str, str]:
    return (match.start, match.end, match.entity_type.value, match.label or "")
