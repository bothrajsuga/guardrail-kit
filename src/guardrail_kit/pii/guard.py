from __future__ import annotations

from collections import Counter

from guardrail_kit.core import Decision, GuardrailContext
from guardrail_kit.pii.detector import PIIDetector
from guardrail_kit.pii.masking import transform_sensitive_text
from guardrail_kit.pii.models import PIIResult, SensitiveAction, SensitiveMatch
from guardrail_kit.pii.policy import PIIPolicy
from guardrail_kit.secrets import SecretDetector, SecretPolicy


class PIIGuard:
    def __init__(
        self,
        policy: PIIPolicy | None = None,
        *,
        secret_policy: SecretPolicy | None = None,
    ) -> None:
        self.policy = policy or PIIPolicy()
        self.detector = PIIDetector(self.policy)
        self.secret_detector = SecretDetector(secret_policy)

    def inspect(self, text: str, context: GuardrailContext | None = None) -> PIIResult:
        del context
        if not isinstance(text, str):
            return self._error("invalid_input")
        if len(text) > self.policy.max_input_length:
            return self._error("input_too_long", {"maximum": self.policy.max_input_length})
        try:
            matches = list(self.detector.detect(text))
            if self.policy.include_secrets:
                matches.extend(self.secret_detector.detect(text))
            excluded = [
                (candidate.start(), candidate.end())
                for pattern in self.policy._compiled_exclusions
                for candidate in pattern.finditer(text)
            ]
            matches = [
                match
                for match in matches
                if not any(
                    match.start < end and start < match.end for start, end in excluded
                )
            ]
            ordered = tuple(sorted(set(matches), key=_match_sort_key))
        except Exception:
            return self._error("detection_error")
        if not ordered:
            return PIIResult(
                decision=Decision.ALLOW,
                action=SensitiveAction.ALLOW,
                reason_code="no_sensitive_data",
                output_text=text,
                metadata={"match_count": 0, "entity_types": ()},
            )
        action = SensitiveAction(self.policy.action)
        counts = Counter(match.entity_type.value for match in ordered)
        metadata = {
            "match_count": len(ordered),
            "entity_types": tuple(sorted(counts)),
            "entity_counts": dict(sorted(counts.items())),
        }
        if action is SensitiveAction.BLOCK:
            return PIIResult(
                decision=Decision.BLOCK,
                action=action,
                reason_code="sensitive_data_blocked",
                output_text=None,
                matches=ordered,
                metadata=metadata,
            )
        if action in {SensitiveAction.MASK, SensitiveAction.REDACT}:
            return PIIResult(
                decision=Decision.ALLOW,
                action=action,
                reason_code=f"sensitive_data_{action.value}ed",
                output_text=transform_sensitive_text(text, ordered, action),
                matches=ordered,
                metadata=metadata,
            )
        return PIIResult(
            decision=Decision.ALLOW,
            action=action,
            reason_code="sensitive_data_allowed",
            output_text=text,
            matches=ordered,
            metadata=metadata,
        )

    def validate(self, text: str, context: GuardrailContext | None = None) -> PIIResult:
        return self.inspect(text, context)

    def _error(self, reason_code: str, metadata: dict[str, int] | None = None) -> PIIResult:
        return PIIResult(
            decision=Decision.BLOCK,
            action=SensitiveAction.BLOCK,
            reason_code=reason_code,
            output_text=None,
            metadata=metadata or {},
        )


def _match_sort_key(match: SensitiveMatch) -> tuple[int, int, str, str]:
    return (match.start, match.end, match.entity_type.value, match.label or "")
