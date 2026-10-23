from guardrail_kit import SQLPolicy, SQLValidator

validator = SQLValidator(
    SQLPolicy(
        dialect="postgres",
        allowed_tables={"analytics.orders"},
        allowed_columns={"analytics.orders": {"id", "total", "created_at"}},
        require_limit=True,
        max_limit=100,
    )
)

result = validator.validate(
    "SELECT id, total FROM analytics.orders ORDER BY created_at DESC LIMIT 25"
)
print(result.decision.value, result.reason_code, result.message)
