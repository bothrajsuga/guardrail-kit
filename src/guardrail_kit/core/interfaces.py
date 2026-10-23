from typing import Generic, Protocol, TypeVar

from guardrail_kit.core.context import GuardrailContext
from guardrail_kit.core.decisions import GuardrailResult

InputT = TypeVar("InputT", contravariant=True)


class Guardrail(Protocol, Generic[InputT]):
    def validate(
        self, value: InputT, context: GuardrailContext | None = None
    ) -> GuardrailResult: ...
