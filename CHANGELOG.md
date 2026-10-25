# Changelog

## 0.1.0 - Unreleased

- Add framework-independent guardrail contracts and privacy-safe audit events.
- Add fail-closed PostgreSQL SELECT validation with table, column, structure, and limit policies.
- Add optional Google ADK 2.12 callback and plugin integrations.
- Add unit, integration, adversarial security, packaging, and CI coverage.
- Reject data-modifying operations anywhere in a SELECT AST, including CTE bodies.
- Preserve PostgreSQL quoted-identifier semantics in table, column, alias, and function policies.
- Add execution-boundary Google ADK guarded tools; callbacks/plugins remain compatibility pre-checks.
- Add `unlisted_table_columns="block"` exhaustive column-policy mode. The default remains `allow` for backward compatibility.
- Validate policy types and dialect names, and make unsupported constructs explicitly fail closed.
- Run and pin the full release quality gate before trusted publishing.
- Add a framework-independent PII and secrets guard with block, allow, mask, and redact actions.
- Detect email, configured phone formats, validated IP addresses, Luhn-valid card candidates, PAN, checksum-valid Aadhaar candidates, and custom identifiers.
- Detect selected AWS/GitHub/API-key/PEM/bearer formats and opt-in advisory high-entropy candidates.
- Keep matched values out of match objects, metadata, safe serialization, and result representations.

