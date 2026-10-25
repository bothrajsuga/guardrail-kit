from guardrail_kit import PIIGuard, PIIPolicy
from guardrail_kit.core import Decision
from guardrail_kit.pii import SensitiveAction, SensitiveEntity
from guardrail_kit.secrets import SecretPolicy


def test_public_api_redacts_pii_and_secrets_in_mixed_content() -> None:
    text = "Contact john@example.com\nAPI_KEY=synthetic_secret_value"
    result = PIIGuard(PIIPolicy(action="redact")).inspect(text)
    assert result.decision is Decision.ALLOW
    assert result.action is SensitiveAction.REDACT
    assert result.output_text == "Contact [REDACTED]\nAPI_KEY=[REDACTED]"
    assert {match.entity_type for match in result.matches} == {
        SensitiveEntity.EMAIL,
        SensitiveEntity.API_KEY,
    }


def test_default_policy_blocks_without_returning_sensitive_text() -> None:
    result = PIIGuard().inspect("Contact john@example.com")
    assert result.decision is Decision.BLOCK
    assert result.reason_code == "sensitive_data_blocked"
    assert result.output_text is None


def test_secret_detection_can_be_disabled_independently() -> None:
    result = PIIGuard(PIIPolicy(action="redact", include_secrets=False)).inspect(
        "API_KEY=synthetic_secret_value"
    )
    assert result.reason_code == "no_sensitive_data"
    assert result.output_text == "API_KEY=synthetic_secret_value"


def test_explicit_exclusion_applies_to_secret_matches() -> None:
    text = "API_KEY=synthetic_secret_value"
    policy = PIIPolicy(
        action="redact",
        exclusion_patterns=(r"API_KEY=synthetic_secret_value",),
    )
    result = PIIGuard(policy).inspect(text)
    assert result.reason_code == "no_sensitive_data"
    assert result.output_text == text


def test_custom_secret_policy_enables_entropy_detection() -> None:
    value = "aB3+/Zx9Qw2_Er7-Ty8Uv4=="
    guard = PIIGuard(
        PIIPolicy(action="redact"),
        secret_policy=SecretPolicy(
            enable_high_entropy=True,
            minimum_entropy=3.5,
            minimum_entropy_length=20,
        ),
    )
    assert guard.inspect(value).output_text == "[REDACTED]"


def test_validate_alias_matches_framework_independent_protocol_shape() -> None:
    guard = PIIGuard(PIIPolicy(action="mask"))
    result = guard.validate("john@example.com")
    assert result.output_text == "j***@example.com"
