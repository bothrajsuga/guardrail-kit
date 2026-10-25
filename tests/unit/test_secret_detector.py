import pytest

from guardrail_kit.pii import SensitiveEntity
from guardrail_kit.secrets import SecretDetector, SecretPolicy


@pytest.mark.parametrize(
    "text,entity",
    [
        ("key=AKIAABCDEFGHIJKLMNOP", SensitiveEntity.AWS_ACCESS_KEY_ID),
        ("token ghp_abcdefghijklmnopqrst", SensitiveEntity.GITHUB_TOKEN),
        ("API_KEY=synthetic_secret_value", SensitiveEntity.API_KEY),
        (
            "-----BEGIN PRIVATE KEY-----\nSYNTHETICNOTCREDENTIAL\n"
            "-----END PRIVATE KEY-----",
            SensitiveEntity.PEM_PRIVATE_KEY,
        ),
        ("Authorization: Bearer abcdefghijklmnop", SensitiveEntity.BEARER_TOKEN),
    ],
)
def test_supported_synthetic_secret_formats(text: str, entity: SensitiveEntity) -> None:
    assert entity in {match.entity_type for match in SecretDetector().detect(text)}


@pytest.mark.parametrize(
    "text",
    [
        "AKIA_TOO_SHORT",
        "ghp_short",
        "The quick brown fox jumps over the lazy dog",
        "version=1.2.3",
        "Authorization Bearer short",
        "api_key=short",
    ],
)
def test_ordinary_or_malformed_values_are_not_secrets(text: str) -> None:
    assert SecretDetector().detect(text) == ()


def test_high_entropy_is_advisory_and_opt_in() -> None:
    candidate = "aB3+/Zx9Qw2_Er7-Ty8Uv4=="
    assert SecretDetector().detect(candidate) == ()
    detector = SecretDetector(
        SecretPolicy(enable_high_entropy=True, minimum_entropy=3.5, minimum_entropy_length=20)
    )
    assert SensitiveEntity.HIGH_ENTROPY in {
        match.entity_type for match in detector.detect(candidate)
    }


def test_secret_detector_rejects_non_string_input() -> None:
    with pytest.raises(TypeError, match="must be a string"):
        SecretDetector().detect(None)  # type: ignore[arg-type]
