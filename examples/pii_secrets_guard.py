from guardrail_kit.pii import PIIGuard, PIIPolicy

guard = PIIGuard(
    PIIPolicy(
        action="redact",
        phone_regions={"international", "in"},
        custom_patterns={"employee_id": r"EMP-[0-9]{4}"},
    )
)

result = guard.inspect(
    "Contact john@example.com about EMP-1234; API_KEY=synthetic_secret_value"
)
print(result.decision.value, result.reason_code)
print(result.output_text)
print(result.to_safe_dict())
