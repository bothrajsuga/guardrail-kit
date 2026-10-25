import pytest

from guardrail_kit.core.errors import ConfigurationError
from guardrail_kit.pii import PIIPolicy, SensitiveAction, SensitiveEntity
from guardrail_kit.secrets import SecretPolicy


def test_policy_normalizes_enums_and_freezes_configuration() -> None:
    policy = PIIPolicy(
        action="redact",
        enabled_entities={"email", SensitiveEntity.IPV4},
        phone_regions={"in"},
        custom_patterns={"employee_id": r"EMP-[0-9]{4}"},
        exclusion_patterns=(r"safe@example\.com",),
    )
    assert policy.action is SensitiveAction.REDACT
    assert policy.enabled_entities == {SensitiveEntity.EMAIL, SensitiveEntity.IPV4}
    assert policy.phone_regions == {"in"}
    with pytest.raises(TypeError):
        policy.custom_patterns["other"] = "value"  # type: ignore[index]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"action": "drop"},
        {"enabled_entities": ["email"]},
        {"enabled_entities": {"unknown"}},
        {"enabled_entities": {"api_key"}},
        {"phone_regions": "in"},
        {"phone_regions": {"mars"}},
        {"custom_patterns": {"": r"X+"}},
        {"custom_patterns": {"bad": "("}},
        {"custom_patterns": {"empty": "a*"}},
        {"custom_patterns": {"capture": "(abc)"}},
        {"custom_patterns": {"backref": r"(a)\\1"}},
        {"custom_patterns": {"nested": r"(a+)+"}},
        {"exclusion_patterns": ["safe"]},
        {"include_secrets": 1},
        {"max_input_length": 0},
        {"max_input_length": True},
    ],
)
def test_invalid_pii_policy_fails_closed(kwargs: dict[str, object]) -> None:
    with pytest.raises(ConfigurationError):
        PIIPolicy(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"enabled_entities": ["api_key"]},
        {"enabled_entities": {"email"}},
        {"enabled_entities": {"unknown"}},
        {"enable_high_entropy": 1},
        {"minimum_entropy": 0},
        {"minimum_entropy": 9},
        {"minimum_entropy": True},
        {"minimum_entropy_length": 11},
    ],
)
def test_invalid_secret_policy_fails_closed(kwargs: dict[str, object]) -> None:
    with pytest.raises(ConfigurationError):
        SecretPolicy(**kwargs)  # type: ignore[arg-type]


def test_high_entropy_requires_explicit_opt_in() -> None:
    assert SensitiveEntity.HIGH_ENTROPY not in SecretPolicy().enabled_entities
    assert SensitiveEntity.HIGH_ENTROPY in SecretPolicy(enable_high_entropy=True).enabled_entities
