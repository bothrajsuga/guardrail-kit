import pytest

from guardrail_kit.core import Decision, GuardrailContext, GuardrailResult


def test_result_exposes_allowed_property_and_immutable_metadata() -> None:
    result = GuardrailResult(Decision.ALLOW, "ok", "Allowed", metadata={"count": 1})
    assert result.allowed
    with pytest.raises(TypeError):
        result.metadata["count"] = 2  # type: ignore[index]


def test_context_copies_metadata() -> None:
    source = {"request_id": "safe-id"}
    context = GuardrailContext(metadata=source)
    source["request_id"] = "changed"
    assert context.metadata["request_id"] == "safe-id"


@pytest.mark.parametrize("code,message", [("", "message"), ("ok", "")])
def test_invalid_result_fields(code: str, message: str) -> None:
    with pytest.raises(ValueError):
        GuardrailResult(Decision.BLOCK, code, message)
