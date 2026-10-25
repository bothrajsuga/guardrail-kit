from __future__ import annotations

import ipaddress
import re

from guardrail_kit.pii.models import SensitiveEntity, SensitiveMatch
from guardrail_kit.pii.policy import PIIPolicy

_EMAIL = re.compile(
    r"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}(?![A-Za-z0-9-])"
)
_IPV4_CANDIDATE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6_CANDIDATE = re.compile(
    r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){1,7}[0-9A-Fa-f]{0,4}(?![\w:])"
)
_CARD_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_PAN = re.compile(r"(?<![A-Z0-9])[A-Z]{5}[0-9]{4}[A-Z](?![A-Z0-9])")
_AADHAAR = re.compile(r"(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)")
_INTERNATIONAL_PHONE = re.compile(r"(?<!\w)\+[1-9](?:[ .()-]?\d){7,14}(?!\w)")
_US_CA_PHONE = re.compile(
    r"(?<!\d)(?:\+?1[ .-])?(?:\(\d{3}\)[ .-]?|\d{3}[ .-])\d{3}[ .-]\d{4}(?!\d)"
)
_INDIA_PHONE = re.compile(r"(?<!\d)(?:\+91[ .-]?)?[6-9]\d{4}[ .-]\d{5}(?!\d)")

_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


class PIIDetector:
    def __init__(self, policy: PIIPolicy | None = None) -> None:
        self.policy = policy or PIIPolicy()

    def detect(self, text: str) -> tuple[SensitiveMatch, ...]:
        if not isinstance(text, str):
            raise TypeError("PII detector input must be a string")
        matches: list[SensitiveMatch] = []
        self._append_regex(matches, text, SensitiveEntity.EMAIL, _EMAIL)
        self._append_ip_addresses(matches, text)
        self._append_payment_cards(matches, text)
        self._append_regex(matches, text, SensitiveEntity.INDIAN_PAN, _PAN)
        self._append_aadhaar(matches, text)
        self._append_phones(matches, text)
        if SensitiveEntity.CUSTOM_IDENTIFIER in self.policy.enabled_entities:
            for label, pattern in self.policy._compiled_custom_patterns.items():
                matches.extend(
                    SensitiveMatch(
                        SensitiveEntity.CUSTOM_IDENTIFIER,
                        candidate.start(),
                        candidate.end(),
                        label,
                    )
                    for candidate in pattern.finditer(text)
                )
        excluded = [
            (candidate.start(), candidate.end())
            for pattern in self.policy._compiled_exclusions
            for candidate in pattern.finditer(text)
        ]
        unique = set(matches)
        return tuple(
            sorted(
                (
                    match
                    for match in unique
                    if not any(
                        _overlaps(match.start, match.end, start, end)
                        for start, end in excluded
                    )
                ),
                key=_match_sort_key,
            )
        )

    def _append_regex(
        self,
        matches: list[SensitiveMatch],
        text: str,
        entity_type: SensitiveEntity,
        pattern: re.Pattern[str],
    ) -> None:
        if entity_type not in self.policy.enabled_entities:
            return
        matches.extend(
            SensitiveMatch(entity_type, candidate.start(), candidate.end())
            for candidate in pattern.finditer(text)
        )

    def _append_ip_addresses(self, matches: list[SensitiveMatch], text: str) -> None:
        for entity_type, version, pattern in (
            (SensitiveEntity.IPV4, 4, _IPV4_CANDIDATE),
            (SensitiveEntity.IPV6, 6, _IPV6_CANDIDATE),
        ):
            if entity_type not in self.policy.enabled_entities:
                continue
            for candidate in pattern.finditer(text):
                try:
                    address = ipaddress.ip_address(candidate.group())
                except ValueError:
                    continue
                if address.version == version:
                    matches.append(
                        SensitiveMatch(entity_type, candidate.start(), candidate.end())
                    )

    def _append_payment_cards(self, matches: list[SensitiveMatch], text: str) -> None:
        if SensitiveEntity.PAYMENT_CARD not in self.policy.enabled_entities:
            return
        for candidate in _CARD_CANDIDATE.finditer(text):
            digits = _digits(candidate.group())
            if 13 <= len(digits) <= 19 and _luhn_valid(digits):
                matches.append(
                    SensitiveMatch(
                        SensitiveEntity.PAYMENT_CARD,
                        candidate.start(),
                        candidate.end(),
                    )
                )

    def _append_aadhaar(self, matches: list[SensitiveMatch], text: str) -> None:
        if SensitiveEntity.INDIAN_AADHAAR not in self.policy.enabled_entities:
            return
        for candidate in _AADHAAR.finditer(text):
            if _verhoeff_valid(_digits(candidate.group())):
                matches.append(
                    SensitiveMatch(
                        SensitiveEntity.INDIAN_AADHAAR,
                        candidate.start(),
                        candidate.end(),
                    )
                )

    def _append_phones(self, matches: list[SensitiveMatch], text: str) -> None:
        if SensitiveEntity.PHONE not in self.policy.enabled_entities:
            return
        patterns = {
            "international": _INTERNATIONAL_PHONE,
            "us_ca": _US_CA_PHONE,
            "in": _INDIA_PHONE,
        }
        for region in sorted(self.policy.phone_regions):
            matches.extend(
                SensitiveMatch(SensitiveEntity.PHONE, candidate.start(), candidate.end())
                for candidate in patterns[region].finditer(text)
                if 8 <= len(_digits(candidate.group())) <= 15
            )


def _digits(value: str) -> str:
    return "".join(character for character in value if character.isdigit())


def _luhn_valid(value: str) -> bool:
    total = 0
    parity = len(value) % 2
    for index, character in enumerate(value):
        digit = int(character)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _verhoeff_valid(value: str) -> bool:
    checksum = 0
    for index, character in enumerate(reversed(value)):
        checksum = _VERHOEFF_D[checksum][_VERHOEFF_P[index % 8][int(character)]]
    return checksum == 0


def _overlaps(first_start: int, first_end: int, second_start: int, second_end: int) -> bool:
    return first_start < second_end and second_start < first_end


def _match_sort_key(match: SensitiveMatch) -> tuple[int, int, str, str]:
    return (match.start, match.end, match.entity_type.value, match.label or "")
