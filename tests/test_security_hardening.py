from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from langchain_core.messages import ToolMessage

from langgraph_secure_agents import (
    AuditEvent,
    DecisionReason,
    Effect,
    PolicyBundle,
    PolicyEngine,
    PolicyRegistry,
    PolicyRule,
    Principal,
    SQLiteApprovalStore,
)
from langgraph_secure_agents import middleware as middleware_module
from langgraph_secure_agents.middleware import create_authorization_middleware


def approval_bundle(*, requires_approval: bool) -> PolicyBundle:
    effect = Effect.REQUIRE_APPROVAL if requires_approval else Effect.ALLOW
    return PolicyBundle(
        policy_id="test-policy",
        version="1.0.0",
        rules=(
            PolicyRule(
                rule_id="report-access",
                effect=effect,
                actions=frozenset({"execute"}),
                resources=frozenset({"read_payroll"}),
                roles=frozenset({"analyst"}),
            ),
        ),
    )


def request(*, context: object = None, tool_call_id: str = "call-1") -> SimpleNamespace:
    return SimpleNamespace(
        tool_call={
            "name": "read_payroll",
            "args": {"employee_id": "employee-7"},
            "id": tool_call_id,
        },
        runtime=SimpleNamespace(
            context=context,
            execution_info=SimpleNamespace(
                thread_id="thread-1",
                checkpoint_id="checkpoint-1",
                checkpoint_ns="",
                task_id="task-1",
            ),
        ),
        state={},
        tool=None,
    )


def reviewer_id(context: object) -> str:
    if not isinstance(context, Mapping):
        raise ValueError("trusted reviewer context is missing")
    value = context.get("reviewer_id")
    if not isinstance(value, str):
        raise ValueError("trusted reviewer identity is missing")
    return value


def test_middleware_consumes_approval_grant_once_and_rejects_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = SQLiteApprovalStore(tmp_path / "approval-store.sqlite3")
    retained: dict[str, Any] = {}

    def fake_interrupt(payload: dict[str, Any]) -> dict[str, Any]:
        token = retained.get("token")
        if token is None:
            token = store.issue(payload["request_fingerprint"], "reviewer-1")
            retained["token"] = token
            retained["fingerprint"] = payload["request_fingerprint"]
        return {
            "approved": True,
            "request_fingerprint": payload["request_fingerprint"],
            "approval_token": token,
        }

    monkeypatch.setattr(middleware_module, "interrupt", fake_interrupt)
    middleware = create_authorization_middleware(
        PolicyEngine(approval_bundle(requires_approval=True).rules),
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
        approval_store=store,
        approval_reviewer_resolver=reviewer_id,
    )
    calls: list[str] = []

    def handler(request_value: Any) -> ToolMessage:
        calls.append("executed")
        return ToolMessage(content="executed", tool_call_id="call-1")

    first = middleware.wrap_tool_call(
        request(context={"reviewer_id": "reviewer-1"}),
        handler,
    )
    replay = middleware.wrap_tool_call(
        request(context={"reviewer_id": "reviewer-1"}),
        handler,
    )

    assert isinstance(first, ToolMessage)
    assert first.content == "executed"
    assert isinstance(replay, ToolMessage)
    assert replay.status == "error"
    assert replay.content == "Approval response invalid; tool was not executed."
    assert calls == ["executed"]
    assert store.consume(
        str(retained["token"]),
        str(retained["fingerprint"]),
        "reviewer-1",
    ) is False
    store.close()


def test_middleware_binds_grant_to_trusted_reviewer_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = SQLiteApprovalStore(tmp_path / "reviewer-binding.sqlite3")
    monkeypatch.setattr(
        middleware_module,
        "interrupt",
        lambda payload: {
            "approved": True,
            "request_fingerprint": payload["request_fingerprint"],
            "approval_token": store.issue(payload["request_fingerprint"], "reviewer-1"),
        },
    )
    middleware = create_authorization_middleware(
        PolicyEngine(approval_bundle(requires_approval=True).rules),
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
        approval_store=store,
        approval_reviewer_resolver=reviewer_id,
    )
    calls: list[bool] = []
    response = middleware.wrap_tool_call(
        request(context={"reviewer_id": "reviewer-2"}),
        lambda value: calls.append(True),
    )

    assert isinstance(response, ToolMessage)
    assert response.status == "error"
    assert calls == []
    store.close()


def test_approval_store_and_custom_validator_are_mutually_exclusive(tmp_path: Path) -> None:
    store = SQLiteApprovalStore(tmp_path / "invalid-config.sqlite3")
    with pytest.raises(ValueError, match="not both"):
        create_authorization_middleware(
            PolicyEngine(),
            principal_resolver=lambda context: Principal("alice"),
            approval_store=store,
            approval_reviewer_resolver=reviewer_id,
            approval_validator=lambda approval, access_request, fingerprint: True,
        )
    with pytest.raises(ValueError, match="configured together"):
        create_authorization_middleware(
            PolicyEngine(),
            principal_resolver=lambda context: Principal("alice"),
            approval_store=store,
        )
    store.close()


def test_middleware_uses_one_current_policy_registry_snapshot_for_audit() -> None:
    registry = PolicyRegistry(approval_bundle(requires_approval=False))
    events: list[AuditEvent] = []
    middleware = create_authorization_middleware(
        registry,
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
        audit_event_callback=events.append,
    )
    first = middleware.wrap_tool_call(
        request(context={}),
        lambda value: ToolMessage(content="first", tool_call_id="call-1"),
    )
    assert isinstance(first, ToolMessage)
    assert first.content == "first"

    registry.publish(
        PolicyBundle(policy_id="test-policy", version="1.1.0", rules=())
    )
    second = middleware.wrap_tool_call(
        request(context={}),
        lambda value: ToolMessage(content="must-not-run", tool_call_id="call-1"),
    )
    assert isinstance(second, ToolMessage)
    assert second.status == "error"
    assert [event.policy_version for event in events] == ["1.0.0", "1.1.0"]
    assert events[0].decision_reason is DecisionReason.EXPLICIT_ALLOW
    assert events[1].decision_reason is DecisionReason.DEFAULT_DENY
