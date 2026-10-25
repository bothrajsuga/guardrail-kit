from __future__ import annotations

from typing import Any

from langchain_core.tools import tool

from guardrail_kit.integrations.langchain import GuardedToolError, ToolGuardPolicy, guard_tool
from guardrail_kit.pii import PIIGuard, PIIPolicy


def test_all_supported_sync_entry_points_reach_the_guard() -> None:
    calls: list[str] = []

    @tool
    def sink(value: str) -> str:
        """Synthetic sensitive-data sink."""
        calls.append(value)
        return value

    guarded = guard_tool(sink, policy=ToolGuardPolicy(input_guard=PIIGuard()))
    blocked = {"value": "private.person@example.com"}

    assert guarded.invoke("safe") == "safe"

    for invoke in (guarded.invoke, guarded.run):
        try:
            invoke(blocked)
        except GuardedToolError as exc:
            assert "private.person" not in str(exc)
        else:  # pragma: no cover - explicit exploit assertion
            raise AssertionError("guarded entry point allowed sensitive input")
    assert calls == ["safe"]


def test_batch_cannot_bypass_policy_and_returned_errors_are_sanitized() -> None:
    calls: list[str] = []

    @tool
    def sink(value: str) -> str:
        """Synthetic batch sink."""
        calls.append(value)
        return value

    guarded = guard_tool(sink, policy=ToolGuardPolicy(input_guard=PIIGuard()))
    results = guarded.batch(
        [{"value": "safe"}, {"value": "private.person@example.com"}],
        return_exceptions=True,
    )

    assert calls == ["safe"]
    assert results[0] == "safe"
    assert isinstance(results[1], GuardedToolError)
    assert "private.person" not in str(results[1])


def test_input_hook_cannot_mutate_a_nested_list() -> None:
    calls: list[dict[str, Any]] = []

    @tool
    def sink(payload: dict[str, Any]) -> str:
        """Synthetic structured sink."""
        calls.append(payload)
        return "ok"

    def hook(arguments: Any) -> bool:
        arguments["payload"]["values"][0] = "changed"
        return True

    guarded = guard_tool(sink, policy=ToolGuardPolicy(input_hooks=(hook,)))
    original = {"payload": {"values": ["original"]}}
    results = guarded.batch([original], return_exceptions=True)

    assert isinstance(results[0], GuardedToolError)
    assert original == {"payload": {"values": ["original"]}}
    assert calls == []


def test_redaction_does_not_mutate_reused_nested_input_between_calls() -> None:
    calls: list[dict[str, Any]] = []

    @tool
    def sink(payload: dict[str, Any]) -> dict[str, Any]:
        """Synthetic structured sink."""
        calls.append(payload)
        return payload

    guarded = guard_tool(
        sink,
        policy=ToolGuardPolicy(input_guard=PIIGuard(PIIPolicy(action="redact"))),
    )
    original = {"payload": {"contact": "private.person@example.com"}}

    guarded.invoke(original)
    guarded.invoke(original)

    assert original["payload"]["contact"] == "private.person@example.com"
    assert [item["contact"] for item in calls] == ["[REDACTED]", "[REDACTED]"]
