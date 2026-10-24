from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from langchain_core.messages import ToolMessage

from langgraph_secure_agents import (
    DecisionReason,
    Effect,
    PolicyEngine,
    PolicyRule,
    Principal,
)
from langgraph_secure_agents import middleware as middleware_module
from langgraph_secure_agents.audit import AuditEvent
from langgraph_secure_agents.guard import AuthorizationDenied, protect_callable
from langgraph_secure_agents.middleware import create_authorization_middleware


def _policy(effect: Effect = Effect.ALLOW) -> PolicyEngine:
    return PolicyEngine(
        [
            PolicyRule(
                rule_id="analysts-read-payroll",
                effect=effect,
                actions=frozenset({"execute"}),
                resources=frozenset({"read_payroll"}),
                roles=frozenset({"analyst"}),
            )
        ]
    )


def _request() -> SimpleNamespace:
    return SimpleNamespace(
        tool_call={"name": "read_payroll", "args": {"employee_id": "employee-7"}, "id": "call-1"},
        runtime=SimpleNamespace(
            context={"user_id": "alice"},
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


def _middleware(
    policy: PolicyEngine,
    events: list[AuditEvent],
    *,
    legacy_decisions: list[object] | None = None,
) -> Any:
    return create_authorization_middleware(
        policy,
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
        audit_event_callback=events.append,
        audit_callback=(
            None
            if legacy_decisions is None
            else lambda request, decision: legacy_decisions.append(decision)
        ),
        policy_id="payroll-access",
        policy_version="1.2.0",
        policy_digest="a" * 64,
    )


def test_callable_emits_structured_event_before_protected_execution() -> None:
    order: list[str] = []
    events: list[AuditEvent] = []

    def read_payroll() -> str:
        order.append("function")
        return "payroll"

    guarded = protect_callable(
        read_payroll,
        policy=_policy(),
        principal_resolver=lambda: Principal("alice", roles=frozenset({"analyst"})),
        audit_event_callback=lambda event: (events.append(event), order.append("audit")),
        request_id_resolver=lambda: "request-123",
        execution_id_resolver=lambda: "run-456",
        policy_id="payroll-access",
        policy_version="1.2.0",
        policy_digest="a" * 64,
    )

    assert guarded() == "payroll"
    assert order == ["audit", "function"]
    assert len(events) == 1
    assert events[0].source == "python_callable"
    assert events[0].allowed is True
    assert events[0].decision_reason is DecisionReason.EXPLICIT_ALLOW
    assert events[0].policy_id == "payroll-access"
    assert events[0].policy_version == "1.2.0"
    assert events[0].policy_digest == "a" * 64
    assert events[0].request_id == "request-123"
    assert events[0].execution_id == "run-456"
    assert events[0].tool_name is None
    assert events[0].duration_ms is not None and events[0].duration_ms >= 0


def test_callable_emits_denial_event_before_raising() -> None:
    events: list[AuditEvent] = []
    calls: list[bool] = []

    def protected_operation() -> None:
        calls.append(True)

    guarded = protect_callable(
        protected_operation,
        policy=PolicyEngine(),
        principal_resolver=lambda: Principal("guest"),
        audit_event_callback=events.append,
    )

    with pytest.raises(AuthorizationDenied):
        guarded()

    assert calls == []
    assert len(events) == 1
    assert events[0].allowed is False
    assert events[0].decision_reason is DecisionReason.DEFAULT_DENY


def test_middleware_emits_structured_event_and_preserves_legacy_callback() -> None:
    events: list[AuditEvent] = []
    legacy_decisions: list[object] = []
    middleware = _middleware(_policy(), events, legacy_decisions=legacy_decisions)
    calls: list[bool] = []

    def handler(request: Any) -> ToolMessage:
        calls.append(True)
        return ToolMessage(content="ok", tool_call_id="call-1")

    response = middleware.wrap_tool_call(_request(), handler)

    assert response.content == "ok"
    assert calls == [True]
    assert len(events) == 1
    assert events[0].source == "langchain_tool"
    assert events[0].action == "execute"
    assert events[0].resource == "read_payroll"
    assert events[0].allowed is True
    assert events[0].request_id == "call-1"
    assert events[0].execution_id == "task-1"
    assert events[0].tool_name == "read_payroll"
    assert events[0].policy_digest == "a" * 64
    assert len(legacy_decisions) == 1
    payload = events[0].to_dict()
    assert "principal_id" not in payload
    assert "resource" not in payload
    assert "matched_rule_ids" not in payload


def test_middleware_emits_denial_event_without_invoking_handler() -> None:
    events: list[AuditEvent] = []
    middleware = _middleware(PolicyEngine(), events)
    calls: list[bool] = []

    response = middleware.wrap_tool_call(
        _request(),
        lambda request: (
            calls.append(True),
            ToolMessage(content="unsafe", tool_call_id="call-1"),
        )[1],
    )

    assert isinstance(response, ToolMessage)
    assert response.status == "error"
    assert calls == []
    assert len(events) == 1
    assert events[0].decision_reason is DecisionReason.DEFAULT_DENY


def test_structured_audit_failure_fails_closed_for_callable_and_middleware() -> None:
    calls: list[bool] = []

    def fail(event: AuditEvent) -> None:
        raise RuntimeError("audit sink unavailable")

    def protected_operation() -> str:
        calls.append(True)
        return "executed"

    guarded = protect_callable(
        protected_operation,
        policy=_policy(),
        principal_resolver=lambda: Principal("alice", roles=frozenset({"analyst"})),
        audit_event_callback=fail,
    )
    with pytest.raises(RuntimeError, match="audit sink unavailable"):
        guarded()

    middleware = create_authorization_middleware(
        _policy(),
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
        audit_event_callback=fail,
    )
    with pytest.raises(RuntimeError, match="audit sink unavailable"):
        middleware.wrap_tool_call(
            _request(),
            lambda request: (
                calls.append(True),
                ToolMessage(content="unsafe", tool_call_id="call-1"),
            )[1],
        )

    assert calls == []


@pytest.mark.parametrize(
    ("resume_outcome", "expected_reason", "expected_allowed", "handler_should_run"),
    [
        ("approved", DecisionReason.HUMAN_APPROVED, True, True),
        ("denied", DecisionReason.APPROVAL_DENIED, False, False),
        ("stale", DecisionReason.APPROVAL_INVALID, False, False),
    ],
)
def test_middleware_audits_policy_and_final_human_approval_outcomes(
    monkeypatch: pytest.MonkeyPatch,
    resume_outcome: str,
    expected_reason: DecisionReason,
    expected_allowed: bool,
    handler_should_run: bool,
) -> None:
    events: list[AuditEvent] = []
    legacy_decisions: list[object] = []
    middleware = _middleware(
        _policy(Effect.REQUIRE_APPROVAL),
        events,
        legacy_decisions=legacy_decisions,
    )

    def resume(payload: dict[str, Any]) -> dict[str, object]:
        return {
            "approved": resume_outcome != "denied",
            "request_fingerprint": (
                "stale-fingerprint" if resume_outcome == "stale" else payload["request_fingerprint"]
            ),
        }

    monkeypatch.setattr(middleware_module, "interrupt", resume)
    calls: list[bool] = []

    response = middleware.wrap_tool_call(
        _request(),
        lambda request: (
            calls.append(True),
            ToolMessage(content="executed", tool_call_id="call-1"),
        )[1],
    )

    assert len(events) == 2
    assert events[0].decision_reason is DecisionReason.APPROVAL_REQUIRED
    assert events[0].requires_approval is True
    assert events[1].decision_reason is expected_reason
    assert events[1].allowed is expected_allowed
    assert calls == ([True] if handler_should_run else [])
    assert len(legacy_decisions) == 1
    if handler_should_run:
        assert response.content == "executed"
    else:
        assert isinstance(response, ToolMessage)
        assert response.status == "error"


def test_failed_audit_of_pending_approval_prevents_interrupt_and_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    interrupt_calls: list[bool] = []
    handler_calls: list[bool] = []

    def fail(event: AuditEvent) -> None:
        raise RuntimeError("audit sink unavailable")

    def unexpected_interrupt(payload: dict[str, Any]) -> object:
        interrupt_calls.append(True)
        return {"approved": True, "request_fingerprint": payload["request_fingerprint"]}

    monkeypatch.setattr(middleware_module, "interrupt", unexpected_interrupt)
    middleware = create_authorization_middleware(
        _policy(Effect.REQUIRE_APPROVAL),
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
        audit_event_callback=fail,
    )

    with pytest.raises(RuntimeError, match="audit sink unavailable"):
        middleware.wrap_tool_call(
            _request(),
            lambda request: (
                handler_calls.append(True),
                ToolMessage(content="unsafe", tool_call_id="call-1"),
            )[1],
        )

    assert interrupt_calls == []
    assert handler_calls == []
