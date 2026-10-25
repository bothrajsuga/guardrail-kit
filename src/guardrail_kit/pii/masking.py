from __future__ import annotations

from guardrail_kit.pii.models import SensitiveAction, SensitiveEntity, SensitiveMatch

_SECRET_ENTITIES = frozenset(
    {
        SensitiveEntity.AWS_ACCESS_KEY_ID,
        SensitiveEntity.GITHUB_TOKEN,
        SensitiveEntity.API_KEY,
        SensitiveEntity.PEM_PRIVATE_KEY,
        SensitiveEntity.BEARER_TOKEN,
        SensitiveEntity.HIGH_ENTROPY,
    }
)
_PRIORITY = {
    entity: 100 if entity in _SECRET_ENTITIES else 10 for entity in SensitiveEntity
}
_PRIORITY[SensitiveEntity.PAYMENT_CARD] = 30
_PRIORITY[SensitiveEntity.INDIAN_AADHAAR] = 30


def transform_sensitive_text(
    text: str, matches: tuple[SensitiveMatch, ...], action: SensitiveAction
) -> str:
    if action not in {SensitiveAction.MASK, SensitiveAction.REDACT}:
        return text
    spans = _merge_overlapping(matches)
    output: list[str] = []
    cursor = 0
    for match in spans:
        output.append(text[cursor : match.start])
        original = text[match.start : match.end]
        output.append(_replacement(original, match.entity_type, action))
        cursor = match.end
    output.append(text[cursor:])
    return "".join(output)


def _merge_overlapping(matches: tuple[SensitiveMatch, ...]) -> tuple[SensitiveMatch, ...]:
    ordered = sorted(matches, key=lambda item: (item.start, item.end, item.entity_type.value))
    merged: list[SensitiveMatch] = []
    for match in ordered:
        if not merged or match.start >= merged[-1].end:
            merged.append(match)
            continue
        previous = merged[-1]
        entity = max(
            (previous.entity_type, match.entity_type),
            key=lambda item: (_PRIORITY[item], item.value),
        )
        merged[-1] = SensitiveMatch(entity, previous.start, max(previous.end, match.end))
    return tuple(merged)


def _replacement(original: str, entity: SensitiveEntity, action: SensitiveAction) -> str:
    if action is SensitiveAction.REDACT or entity in _SECRET_ENTITIES:
        return "[REDACTED]"
    if entity is SensitiveEntity.EMAIL:
        local, separator, domain = original.partition("@")
        return f"{local[:1]}***{separator}{domain}" if separator else "[MASKED]"
    if entity in {SensitiveEntity.PHONE, SensitiveEntity.PAYMENT_CARD}:
        keep = 4 if entity is SensitiveEntity.PAYMENT_CARD else 2
        remaining = sum(character.isdigit() for character in original) - keep
        output: list[str] = []
        for character in original:
            if character.isdigit() and remaining > 0:
                output.append("*")
                remaining -= 1
            else:
                output.append(character)
        return "".join(output)
    if entity in {SensitiveEntity.INDIAN_PAN, SensitiveEntity.INDIAN_AADHAAR}:
        return "*" * max(0, len(original) - 4) + original[-4:]
    if entity in {SensitiveEntity.IPV4, SensitiveEntity.IPV6}:
        return "[IP]"
    return "[MASKED]"
