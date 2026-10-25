import pytest

from guardrail_kit.pii import PIIDetector, PIIPolicy, SensitiveEntity


def _types(text: str, policy: PIIPolicy | None = None) -> set[SensitiveEntity]:
    return {match.entity_type for match in PIIDetector(policy).detect(text)}


@pytest.mark.parametrize(
    "text,entity",
    [
        ("Contact john@example.com today", SensitiveEntity.EMAIL),
        ("Route 192.0.2.25 is reserved", SensitiveEntity.IPV4),
        ("IPv6 2001:db8::1234 is documentation-only", SensitiveEntity.IPV6),
        ("Card 4242 4242 4242 4242", SensitiveEntity.PAYMENT_CARD),
        ("PAN ABCDE1234F", SensitiveEntity.INDIAN_PAN),
        ("Aadhaar candidate 2222 2222 2227", SensitiveEntity.INDIAN_AADHAAR),
        ("Call +44 20 7946 0958", SensitiveEntity.PHONE),
    ],
)
def test_supported_pii_candidates(text: str, entity: SensitiveEntity) -> None:
    assert entity in _types(text)


@pytest.mark.parametrize(
    "text,entity",
    [
        ("999.2.3.4", SensitiveEntity.IPV4),
        ("not::an::address", SensitiveEntity.IPV6),
        ("4242 4242 4242 4243", SensitiveEntity.PAYMENT_CARD),
        ("abcde1234f", SensitiveEntity.INDIAN_PAN),
        ("2222 2222 2228", SensitiveEntity.INDIAN_AADHAAR),
        ("version 1.2.3", SensitiveEntity.IPV4),
    ],
)
def test_invalid_or_partial_candidates_are_not_detected(
    text: str, entity: SensitiveEntity
) -> None:
    assert entity not in _types(text)


def test_phone_regions_are_explicit() -> None:
    text = "US (415) 555-0132, India 98765-43210"
    default_matches = PIIDetector().detect(text)
    assert not any(match.entity_type is SensitiveEntity.PHONE for match in default_matches)
    policy = PIIPolicy(phone_regions={"us_ca", "in"}, include_secrets=False)
    phones = [
        match
        for match in PIIDetector(policy).detect(text)
        if match.entity_type is SensitiveEntity.PHONE
    ]
    assert len(phones) == 2


def test_custom_identifier_and_configured_exclusion() -> None:
    policy = PIIPolicy(
        custom_patterns={"employee_id": r"EMP-[0-9]{4}"},
        exclusion_patterns=(r"safe@example\.com",),
        include_secrets=False,
    )
    text = "EMP-1234 safe@example.com alert@example.com"
    matches = PIIDetector(policy).detect(text)
    assert [(match.entity_type, match.label) for match in matches] == [
        (SensitiveEntity.CUSTOM_IDENTIFIER, "employee_id"),
        (SensitiveEntity.EMAIL, None),
    ]
    assert text[matches[1].start : matches[1].end] == "alert@example.com"


def test_unicode_and_multiline_input_preserves_original_offsets() -> None:
    text = "வணக்கம் 👋\ncontact: user@example.org\nமுடிவு"
    match = PIIDetector().detect(text)[0]
    assert text[match.start : match.end] == "user@example.org"


def test_detector_rejects_non_string_input() -> None:
    with pytest.raises(TypeError, match="must be a string"):
        PIIDetector().detect(42)  # type: ignore[arg-type]
