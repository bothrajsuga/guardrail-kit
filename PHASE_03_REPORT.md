# Phase 3 LangChain and LangGraph Security Integration Report

Date: 2026-10-25

Branch: `feat/phase-03-langchain-langgraph`

Baseline: Phase 2 commit `f0917652cf6024dd49674e17ac9df325a50a9703`

Scope: Phase 3 only. No Phase 4 work, merge, version change, publication, tag,
or release was performed. The Phase 3 branch was committed and pushed only
after separate owner authorization and final security review.

## Executive summary

Phase 3 adds optional LangChain and LangGraph integrations around the existing
SQL and PII/secrets guards. The LangChain wrapper enforces configured policies
inside the sync or async callable immediately before the protected tool. A
policy rejection or exception prevents invocation. Output inspection is
available but is explicitly post-execution and cannot undo side effects.

The LangGraph helper requires an explicit policy for every tool and builds a
`ToolNode` from guarded wrappers. Tests exercise compiled `StateGraph` sync,
async, multiple-call, concurrent-call, failure, and safe error-result paths.
The final local suite passed with 90.82% total coverage. Focused coverage for
the new integration modules was 95%.

## Preflight and baseline

- Phase 2 local and remote branch commit: `f0917652cf6024dd49674e17ac9df325a50a9703`.
- Phase 2 GitHub Actions run `40155407916`: completed successfully with all 15
  jobs passing.
- Phase 3 branch was created from that exact clean baseline.
- Baseline command:

  ```bash
  GUARDRAIL_KIT_REQUIRE_ADK=1 .venv/bin/python -m pytest \
    --cov=guardrail_kit --cov-report=term-missing --cov-fail-under=75
  ```

- Baseline result: 413 passed, 0 failed, 0 skipped; 90.08% total coverage.

## Architecture and public API

`ToolGuardPolicy` is immutable configuration containing an optional
`SQLValidator`, named SQL argument, input `PIIGuard`, output `PIIGuard`, and
allow/block custom hooks. Each call receives newly copied JSON-like containers.
PII transformations apply recursively to string values. Custom hooks receive a
recursively immutable view and must return exactly `True` to authorize.

`guard_tool(tool, policy=...)` returns a schema-preserving LangChain
`StructuredTool`. Standard `invoke`, `ainvoke`, `run`, `arun`, `batch`, and
`abatch` paths converge on its guarded callables. Name, description, argument
schema, tags, metadata, `return_direct`, and response format are retained.

`create_guarded_tool_node(tools, policies=...)` rejects missing policies,
guards every tool, and constructs a LangGraph `ToolNode`. Tool errors can be
translated by ToolNode into safe error `ToolMessage` objects.

Example:

```python
from guardrail_kit.integrations.langchain import ToolGuardPolicy, guard_tool

secured = guard_tool(
    original_tool,
    policy=ToolGuardPolicy(
        sql_validator=validator,
        input_guard=redacting_guard,
        output_guard=redacting_guard,
    ),
)
```

## Security boundary analysis

- SQL and sensitive-data policy checks execute immediately before the wrapped
  tool invocation.
- A block, malformed input, hook exception, detector exception, or validator
  exception fails closed and invokes the protected tool zero times.
- Protected-tool exceptions are replaced by `GuardedToolError` with a stable,
  value-free reason and without retaining a raw exception cause or context.
- Input containers are copied before transformation; concurrent calls share no
  mutable decision or argument state.
- Custom hooks cannot mutate nested dictionaries or sequences supplied through
  the supported JSON-like path.
- Output redaction is after execution and is not represented as rollback or
  side-effect protection.

Protection belongs to the returned wrapper, not the original tool or the graph
globally. Direct original-tool use, alternate registration, dynamic tool
replacement, unguarded subgraphs, custom invocation overrides,
remote/distributed executors, and independently implemented streaming paths can
bypass or fall outside this integration. Dictionary keys and arbitrary custom
objects are not recursively inspected. Graph state is inspected only when it
is passed as a declared tool argument.

## Dependency compatibility

Optional dependency ranges:

```text
langchain = langchain-core>=1.0,<2
langgraph = langchain-core>=1.0,<2 and langgraph>=1.0,<2
```

Versions actually tested locally:

```text
Python                 3.12.15
langchain-core         1.7.0
langgraph              1.2.17
langgraph-prebuilt     1.1.1
SQLGlot                30.24.0
Google ADK             2.12.0
pytest                 9.1.1
coverage               7.17.0
Ruff                   0.17.2
mypy                   1.20.2
build                  1.6.1
Twine                  6.2.0
```

The major-version ranges are dependency constraints, not a claim that every
intermediate release was tested. LangChain/LangGraph remain optional for normal
package use.

## Tests and coverage

Final full command:

```bash
GUARDRAIL_KIT_REQUIRE_ADK=1 .venv/bin/python -m pytest \
  --cov=guardrail_kit --cov-report=term-missing --cov-fail-under=75
```

Result: 441 passed, 0 failed, 0 skipped in 1.97 seconds, with one non-failing
upstream Google ADK experimental JSON-schema warning. Total statement coverage
was 90.82% (1,242 statements, 114 missed).

Focused integration command covered the LangChain, LangGraph, and adversarial
tests: 28 passed with 95% combined coverage for the new integration modules.
Individual integration files were 90% or higher except the LangChain tool
module at 94%; the combined target was exceeded.

Coverage includes allowed calls executing exactly once, blocked calls executing
zero times, sync/async parity, concurrent isolation, nested structured input,
input transformation without caller mutation, SQL denial, hook exceptions,
immutable hooks, output redaction/blocking, sanitized tool exceptions, metadata
and schema preservation, batch execution, compiled ToolNode execution, multiple
calls, and safe ToolNode error messages.

## Final security review findings

The pre-commit review found and fixed two issues:

1. LangChain/Pydantic schema-validation errors occur before the guarded
   callable and can include the rejected value. The wrapper now installs a
   fixed, value-free validation-error response. A regression passes a synthetic
   sensitive value of the wrong type and confirms zero tool calls and no value
   exposure.
2. SQL authorization originally ran before optional PII transformation. The
   order now transforms first and validates the exact final SQL mapping passed
   to the tool. Regression tests prove identity between validated and executed
   SQL and prove that a transformation producing invalid SQL blocks with zero
   calls.

No unresolved security or compatibility blocker remained after remediation.

## Quality gates

- Ruff: passed.
- Strict mypy: passed for 34 source files.
- Package build: wheel and source distribution built successfully.
- Twine: wheel and source distribution passed validation.
- Fresh core wheel: installed with ordinary required dependencies; SQL smoke
  passed without installing LangChain or LangGraph.
- Fresh framework wheel: installed with `[langgraph]`; LangChain wrapper and
  guarded ToolNode construction passed using the versions listed above.
- `git diff --check`: passed.
- Package version remains `0.1.0` and Python requirement remains `>=3.11`.

No live external service, production SQL system, network tool, or credential
was used. All sensitive-looking values in tests are synthetic.

## Files created

- `src/guardrail_kit/integrations/langchain/__init__.py`
- `src/guardrail_kit/integrations/langchain/exceptions.py`
- `src/guardrail_kit/integrations/langchain/policy.py`
- `src/guardrail_kit/integrations/langchain/tools.py`
- `src/guardrail_kit/integrations/langgraph/__init__.py`
- `src/guardrail_kit/integrations/langgraph/integration.py`
- `tests/integration/test_langchain.py`
- `tests/integration/test_langgraph.py`
- `tests/security/test_langchain_adversarial.py`
- `examples/langchain_langgraph.py`
- `docs/langchain-langgraph.md`
- `PHASE_03_REPORT.md`

## Files modified

- `pyproject.toml`
- `README.md`
- `docs/architecture.md`
- `docs/security.md`
- `docs/roadmap.md`
- `CHANGELOG.md`

## Remaining risks

- Direct access to the original tool remains an intentional, documented bypass
  boundary; application code must expose only guarded instances.
- Custom BaseTool invocation overrides and nonstandard schemas can route outside
  the verified standard paths and are unsupported.
- Incremental/token streaming, dynamic tool registration, remote executors, and
  universal subgraph protection have not been verified.
- PII/secret detection retains Phase 2 false-positive and false-negative limits.
- Input inspection supports JSON-like containers; custom objects and mapping
  keys require an application-owned policy hook or prior serialization.
- Output blocking cannot reverse side effects already produced by the tool.
- Callback/tracing propagation to the protected inner tool is intentionally not
  preserved; observability should be attached to the guarded wrapper and must
  avoid raw arguments and output.

## Phase 4 readiness

Phase 3 is ready for owner review. Phase 4 has not started. The owner separately
authorized committing and pushing this reviewed Phase 3 branch; no merge,
release, publication, or Phase 4 work was authorized.
