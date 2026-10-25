from typing import Any

import pytest

from guardrail_kit.core import Decision
from guardrail_kit.pii import (
    PIIGuard,
    PIIPolicy,
    PIIResult,
    SensitiveAction,
    SensitiveEntity,
    SensitiveMatch,
)
from guardrail_kit.pii.masking import transform_sensitive_text
from guardrail_kit.secrets import SecretPolicy


@pytest.mark.parametrize("action", ["mask", "redact"])
def test_transformation_preserves_text_outside_sensitive_spans(action: str) -> None:
    text = "before john@example.com after"
    result = PIIGuard(PIIPolicy(action=action, include_secrets=False)).inspect(text)
    assert result.output_text is not None
    assert result.output_text.startswith("before ")
    assert result.output_text.endswith(" after")
    assert "john@example.com" not in result.output_text


def test_masking_is_deterministic_for_multiple_entity_types() -> None:
    text = "john@example.com 4242-4242-4242-4242 +44 20 7946 0958"
    guard = PIIGuard(PIIPolicy(action="mask", include_secrets=False))
    first = guard.inspect(text)
    second = guard.inspect(text)
    assert first.output_text == second.output_text
    assert first.output_text == "j***@example.com ****-****-****-4242 +** ** **** **58"


def test_overlapping_secret_matches_are_replaced_once_without_leakage() -> None:
    value = "aB3+/Zx9Qw2_Er7-Ty8Uv4=="
    text = f"API_KEY={value}"
    guard = PIIGuard(
        PIIPolicy(action="mask"),
        secret_policy=SecretPolicy(
            enable_high_entropy=True,
            minimum_entropy=3.5,
            minimum_entropy_length=20,
        ),
    )
    result = guard.inspect(text)
    assert len(result.matches) == 2
    assert result.output_text == "API_KEY=[REDACTED]"
    assert value not in repr(result)
    assert value not in str(result.to_safe_dict())
    assert value not in str(dict(result.metadata))


def test_allow_action_is_explicit_and_reports_detection() -> None:
    text = "john@example.com"
    result = PIIGuard(PIIPolicy(action="allow", include_secrets=False)).inspect(text)
    assert result.decision is Decision.ALLOW
    assert result.reason_code == "sensitive_data_allowed"
    assert result.output_text == text
    assert result.matches


def test_malformed_inputs_and_length_limit_fail_closed() -> None:
    guard = PIIGuard(PIIPolicy(max_input_length=5))
    invalid = guard.inspect(42)  # type: ignore[arg-type]
    oversized = guard.inspect("123456")
    assert invalid.decision is Decision.BLOCK
    assert invalid.reason_code == "invalid_input"
    assert invalid.output_text is None
    assert oversized.decision is Decision.BLOCK
    assert oversized.reason_code == "input_too_long"
    assert oversized.metadata == {"maximum": 5}


def test_unexpected_detector_error_fails_closed_without_exception_details() -> None:
    guard = PIIGuard()

    def broken(_: str) -> tuple[()]:
        raise RuntimeError("synthetic_secret_should_not_escape")

    guard.detector.detect = broken  # type: ignore[method-assign]
    result = guard.inspect("ordinary input")
    assert result.decision is Decision.BLOCK
    assert result.reason_code == "detection_error"
    assert result.output_text is None
    assert "synthetic_secret_should_not_escape" not in repr(result)


def test_safe_serialization_never_includes_output_text() -> None:
    result = PIIResult(
        decision=Decision.ALLOW,
        action=SensitiveAction.ALLOW,
        reason_code="synthetic",
        output_text="sensitive-original",
    )
    assert "sensitive-original" not in repr(result)
    assert "sensitive-original" not in str(result.to_safe_dict())


def test_no_detection_returns_original_unicode_text() -> None:
    text = "வணக்கம் — ordinary text ✅"
    result = PIIGuard(PIIPolicy(action="redact")).inspect(text)
    assert result.reason_code == "no_sensitive_data"
    assert result.output_text == text


def test_result_metadata_contains_only_aggregate_values() -> None:
    secret = "synthetic_secret_value"
    result = PIIGuard(PIIPolicy(action="redact")).inspect(f"API_KEY={secret}")
    metadata: dict[str, Any] = dict(result.metadata)
    assert metadata == {
        "match_count": 1,
        "entity_types": ("api_key",),
        "entity_counts": {"api_key": 1},
    }
    assert secret not in str(metadata)
    with pytest.raises(TypeError):
        result.metadata["entity_counts"]["api_key"] = 2  # type: ignore[index]
    assert result.to_safe_dict()["metadata"] == {
        "match_count": 1,
        "entity_types": ["api_key"],
        "entity_counts": {"api_key": 1},
    }


@pytest.mark.parametrize(
    "entity,value,expected",
    [
        (SensitiveEntity.IPV4, "192.0.2.1", "[IP]"),
        (SensitiveEntity.INDIAN_PAN, "ABCDE1234F", "******234F"),
        (SensitiveEntity.INDIAN_AADHAAR, "2222 2222 2227", "**********2227"),
        (SensitiveEntity.CUSTOM_IDENTIFIER, "EMP-1234", "[MASKED]"),
    ],
)
def test_entity_specific_masking(
    entity: SensitiveEntity, value: str, expected: str
) -> None:
    match = SensitiveMatch(entity, 0, len(value))
    assert transform_sensitive_text(value, (match,), SensitiveAction.MASK) == expected


def test_non_transforming_action_returns_original_text() -> None:
    text = "john@example.com"
    match = SensitiveMatch(SensitiveEntity.EMAIL, 0, len(text))
    assert transform_sensitive_text(text, (match,), SensitiveAction.ALLOW) == text


def test_models_reject_invalid_offsets_and_reason_codes() -> None:
    with pytest.raises(ValueError, match="offsets"):
        SensitiveMatch(SensitiveEntity.EMAIL, 2, 2)
    with pytest.raises(ValueError, match="reason_code"):
        PIIResult(Decision.BLOCK, SensitiveAction.BLOCK, "", None)
