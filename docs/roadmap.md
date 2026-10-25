# Roadmap

## Phase 2 implementation

The development branch implements deterministic PII and secrets inspection for plain strings, configurable regional phone and custom identifier rules, block/mask/redact/allow policies, privacy-aware results, overlap-safe transformation, and adversarial false-positive/false-negative tests. It remains a candidate detector rather than identity verification or comprehensive DLP.

## Phase 3 implementation

The development branch includes optional LangChain and LangGraph adapters for
standard schema-driven tool execution. The boundary combines existing SQL and
PII/secrets guards, immutable custom hooks, sanitized failures, output
inspection, and explicit-policy ToolNode construction. Unsupported dynamic,
remote, custom-invocation, and streaming paths remain documented exclusions.

## Later

More framework integrations based on demand and additional explicitly tested
SQL dialects remain future work. Phase 4 has not started.
