# Architecture

The core package defines immutable context, decision, result, and guardrail contracts without importing an agent framework. SQL policy and validation depend only on SQLGlot. Integrations translate framework lifecycle calls into core validation and translate a block into a framework-native response. Audit events contain decisions and non-sensitive metadata, never raw input.

This boundary allows a future PII guardrail to implement the same core protocol without altering `SQLValidator` or importing SQLGlot into the core. Framework dependencies remain optional and isolated under `integrations`.

SQL dialect support is closed and explicit. `guardrail_kit.sql.dialects` resolves each accepted canonical name or documented alias to one immutable `DialectSpec`. The policy stores that resolved specification once, and parsing, identifier handling, function matching, normalization, and validation all consume it. Adding a SQLGlot dialect does not make it supported automatically; it requires an explicit specification, database-specific identifier rules, adversarial tests, and documentation.

