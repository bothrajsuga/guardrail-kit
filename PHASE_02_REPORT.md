# Phase 2 PII and Secrets Guard Report

Date: 2026-10-25

Branch: `feat/phase-02-pii-secrets-guard`

Baseline: Phase 1 commit `06e5b337fae4621c56f0f0c483942ac6fe3b35df`

Scope: Phase 2 only. No Phase 3 work, merge, version change, package publication, or release was performed. The Phase 2 branch was committed and pushed only after separate owner authorization.

## Executive summary

Phase 2 adds a dependency-light, framework-independent PII and secrets guard while preserving the SQL validator and Google ADK integration. It detects deterministic candidate formats, returns value-free original-input spans, and applies explicit allow, block, mask, or redact policy actions. The default action is block. Detector and policy errors fail closed.

The final suite contains 413 passing tests with no failures or skips when Google ADK is required. Total coverage is 90.08%, up from the Phase 1 baseline of 85.29%. Focused PII and secrets module coverage is approximately 97%, exceeding the 90% target.

## Architecture and public API

### Modules

- `guardrail_kit.pii.models`: immutable entity/action enums, value-free matches, and privacy-aware results.
- `guardrail_kit.pii.policy`: action, detector, regional phone, custom-pattern, exclusion, and input-size policy validation.
- `guardrail_kit.pii.detector`: deterministic PII candidate detection and checksum validation.
- `guardrail_kit.pii.masking`: deterministic masking, redaction, and overlap resolution.
- `guardrail_kit.pii.guard`: fail-closed orchestration across PII and secret detectors.
- `guardrail_kit.secrets.policy`: secret detector and opt-in entropy configuration.
- `guardrail_kit.secrets.detector`: selected credential-format and advisory entropy detection.

### Public interfaces

```python
from guardrail_kit.pii import PIIGuard, PIIPolicy

guard = PIIGuard(PIIPolicy(action="redact"))
result = guard.inspect("Contact john@example.com")
assert result.output_text == "Contact [REDACTED]"
```

Public exports include `PIIPolicy`, `PIIDetector`, `PIIGuard`, `PIIResult`, `SensitiveAction`, `SensitiveEntity`, `SensitiveMatch`, `SecretPolicy`, and `SecretDetector`. The main package also re-exports the primary guard, policy, result, and detector classes without changing existing SQL or core names.

`PIIGuard.validate` is an alias for `inspect` and retains the framework-independent guardrail call shape. Matches contain half-open `start:end` offsets into the original input. They do not contain the matched value.

## Security protections implemented

- Safe default `block` action; `allow`, `mask`, and `redact` require explicit configuration.
- Fail-closed results for non-string inputs, excessive input length, detector exceptions, and invalid policy configuration.
- Email candidate detection.
- Explicit regional phone rules for international, US/Canada, and India formats.
- IPv4 and IPv6 parsing through the standard library after candidate extraction.
- Payment-card candidate validation with Luhn checksum.
- Indian PAN format validation only.
- Aadhaar candidate validation using the Verhoeff checksum and a conservative leading-digit rule.
- Configurable custom identifier patterns and exclusions.
- Selected AWS access-key ID, GitHub token, API-key assignment, PEM private-key, and bearer-token format detection.
- Opt-in high-entropy candidates with configurable length and entropy thresholds; disabled by default and documented as advisory rather than proof of a secret.
- Custom-regex constraints: 500-character limit; empty-match, capturing-group, backreference, lookbehind, conditional, and common nested-quantifier rejection.
- Deterministic overlap merging before transformation, prioritizing secret and financial/government identifier spans.
- Secret candidates always redact under the `mask` action rather than partially exposing their value.
- Immutable match tuples and recursively immutable result metadata.
- Aggregate-only metadata; no matched values.
- A custom `repr` and `to_safe_dict()` that omit input and output text.

## Detection and transformation behavior

Detection establishes candidate format only. PAN detection does not verify identity. Aadhaar and card checksums do not prove assignment, ownership, or validity. IP detection does not classify sensitivity. Phone detection is explicitly regional. Secret patterns do not validate credentials against providers.

Masking preserves text outside selected input spans. Email masking retains the first local-part character and domain, phone masking retains two final digits, card masking retains four final digits, and PAN/Aadhaar masking retains four final characters. IP and custom identifiers use fixed placeholders. Redaction uses `[REDACTED]`.

The direct `output_text` field remains sensitive: it contains the original input when no match exists or `allow` is selected, and masking deliberately preserves limited context. Only `to_safe_dict()` is intended as privacy-safe serialization.

## Tests and coverage

### Baseline

Command:

```bash
GUARDRAIL_KIT_REQUIRE_ADK=1 .venv/bin/python -m pytest \
  --cov=guardrail_kit --cov-report=term-missing --cov-fail-under=75
```

Phase 1 baseline result: 335 passed, 0 failed, 0 skipped; 85.29% coverage.

### Final

Same command after Phase 2: 413 passed, 0 failed, 0 skipped in 2.02 seconds; 90.08% total coverage. One upstream Google ADK experimental JSON-schema warning remained non-failing.

Focused command:

```bash
.venv/bin/python -m pytest \
  tests/unit/test_pii_policy.py \
  tests/unit/test_pii_detector.py \
  tests/unit/test_secret_detector.py \
  tests/integration/test_pii_guard.py \
  tests/security/test_pii_adversarial.py \
  --cov=guardrail_kit.pii --cov=guardrail_kit.secrets \
  --cov-report=term-missing -q
```

Focused result before the final metadata immutability regression was added: 78 passed with 97% combined new-module coverage. The subsequent full suite included that additional passing regression.

Coverage observed for security-critical components included 93% for the PII detector, 100% for the guard, 100% for masking, 96% for PII policy, 98% for secret detection, and 100% for secret policy in the focused run.

Tests cover valid and invalid candidates, Unicode and multiline content, regional phones, checksum failures, custom identifiers, exclusions, overlapping matches, deterministic masking, explicit allow behavior, synthetic secret fixtures, opt-in entropy, malformed input, input bounds, fail-closed detector exceptions, aggregate-only metadata, immutable nested metadata, and privacy-safe serialization.

All credential-shaped fixtures are synthetic. No production system or external credential validation endpoint was used.

## Quality gates

- Ruff: passed.
- Strict mypy: passed for 28 source files.
- Package build: wheel and source distribution built successfully.
- Twine: both distributions passed.
- Wheel contents: Phase 2 PII and secrets modules present.
- Fresh normal wheel installation: PII redaction and existing SQL validation smoke tests passed.
- `git diff --check`: passed.

An initial smoke command intentionally used `pip install --no-deps`; importing the package then failed because the existing required SQLGlot dependency was absent. This was an invalid installation mode, not a package regression. A corrected normal wheel installation resolved declared dependencies and passed both PII and SQL smoke tests.

## Files created

- `src/guardrail_kit/pii/__init__.py`
- `src/guardrail_kit/pii/detector.py`
- `src/guardrail_kit/pii/guard.py`
- `src/guardrail_kit/pii/masking.py`
- `src/guardrail_kit/pii/models.py`
- `src/guardrail_kit/pii/policy.py`
- `src/guardrail_kit/secrets/__init__.py`
- `src/guardrail_kit/secrets/detector.py`
- `src/guardrail_kit/secrets/policy.py`
- `examples/pii_secrets_guard.py`
- `tests/unit/test_pii_policy.py`
- `tests/unit/test_pii_detector.py`
- `tests/unit/test_secret_detector.py`
- `tests/integration/test_pii_guard.py`
- `tests/security/test_pii_adversarial.py`
- `PHASE_02_REPORT.md`

## Files modified

- `src/guardrail_kit/__init__.py`
- `README.md`
- `docs/architecture.md`
- `docs/security.md`
- `docs/roadmap.md`
- `CHANGELOG.md`

The package version remains `0.1.0`.

## Remaining security limitations

- Deterministic matching is not comprehensive DLP and has unavoidable false positives and false negatives.
- Obfuscation, encoding, fragmentation, OCR errors, novel secret prefixes, internationalized email, and unconfigured regional identifiers can evade detection.
- Checksum-valid Aadhaar/card candidates are not proof of authenticity, assignment, ownership, or identity.
- Entropy is only a heuristic. Encoded or compressed ordinary data may appear secret-like, while low-entropy secrets may not.
- Regex safety checks reduce obvious risks but do not mathematically prove freedom from regular-expression denial of service. Custom patterns must remain trusted, reviewed configuration.
- `output_text` is intentionally available to callers and can contain sensitive input. Applications must not log it indiscriminately.
- Masking retains limited context by design and may be unsuitable where irreversible removal is required; use redaction and minimize retention.
- Exclusions can suppress true findings and therefore require security review.
- Provider-side secret status, revocation, and live credential validity are not checked.
- No image, document, structured-object, streaming, or framework-specific PII integration is included in Phase 2.

## Backward compatibility

Existing SQL and Google ADK APIs were not changed. Phase 1 SQL and ADK tests pass in the complete suite. New top-level exports are additive. No required dependency was added, no existing policy default was changed, and the Google ADK dependency remains optional.

The new `PIIPolicy` defaults to blocking detected content, but this affects only applications that instantiate the new API. The `allow` action can intentionally return original sensitive text and is documented as an explicit risk decision.

## Phase 3 readiness

Phase 2 is ready for owner review. Phase 3 has not started. Before any Phase 3 work, the owner should review the API, masking semantics, exclusions, regex constraints, documentation, and test evidence. The owner separately authorized committing and pushing this Phase 2 branch after review; no merge or release was authorized or performed.
