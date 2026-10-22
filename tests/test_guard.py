from __future__ import annotations

import inspect
from typing import Any

import pytest

from langgraph_secure_agents import AccessRequest, Effect, PolicyEngine, PolicyRule, Principal
from langgraph_secure_agents.guard import AuthorizationDenied, protect_callable


def allow_rule(
    *,
    resource: str,
    role: str = "analyst",
    action: str = "read",
) -> PolicyRule:
    return PolicyRule(
        rule_id=f"allow-{role}-{action}-{resource}",
        effect=Effect.ALLOW,
        actions=frozenset({action}),
        resources=frozenset({resource}),
        roles=frozenset({role}),
    )


def test_denied_call_never_executes_protected_function() -> None:
    calls: list[str] = []

    def read_payroll(employee_id: str) -> str:
        calls.append(employee_id)
        return "sensitive payroll data"

    guarded = protect_callable(
        read_payroll,
        policy=PolicyEngine([allow_rule(resource="payroll:employee-7")]),
        principal_resolver=lambda: Principal("guest", roles=frozenset({"guest"})),
        action="read",
        resource_resolver=lambda employee_id: f"payroll:{employee_id}",
    )

    with pytest.raises(AuthorizationDenied) as error:
        guarded("employee-7")

    assert calls == []
    assert error.value.decision.reason == "default_deny"
    assert error.value.request.resource == "payroll:employee-7"


def test_allowed_call_executes_and_returns_original_result() -> None:
    def read_report(report_id: str) -> str:
        return f"report:{report_id}"

    guarded = protect_callable(
        read_report,
        policy=PolicyEngine([allow_rule(resource="report:quarterly")]),
        principal_resolver=lambda: Principal("alice", roles=frozenset({"analyst"})),
        action="read",
        resource_resolver=lambda report_id: f"report:{report_id}",
    )

    assert guarded("quarterly") == "report:quarterly"


def test_principal_is_resolved_for_each_invocation() -> None:
    current_principal = [Principal("alice", roles=frozenset({"analyst"}))]

    def read_document(document_id: str) -> str:
        return document_id

    guarded = protect_callable(
        read_document,
        policy=PolicyEngine([allow_rule(resource="document:1")]),
        principal_resolver=lambda: current_principal[0],
        action="read",
        resource_resolver=lambda document_id: f"document:{document_id}",
    )

    assert guarded("1") == "1"

    current_principal[0] = Principal("mallory", roles=frozenset({"guest"}))
    with pytest.raises(AuthorizationDenied):
        guarded("1")


def test_audit_callback_receives_decision_before_execution() -> None:
    events: list[tuple[AccessRequest, bool]] = []

    def read_report() -> str:
        return "ok"

    guarded = protect_callable(
        read_report,
        policy=PolicyEngine([allow_rule(resource="read_report")]),
        principal_resolver=lambda: Principal("alice", roles=frozenset({"analyst"})),
        action="read",
        audit_callback=lambda request, decision: events.append((request, decision.allowed)),
    )

    assert guarded() == "ok"
    assert len(events) == 1
    assert events[0][0].resource == "read_report"
    assert events[0][1]


def test_audit_failure_prevents_protected_execution() -> None:
    calls: list[bool] = []

    def sensitive_operation() -> str:
        calls.append(True)
        return "executed"

    def failed_audit(request: AccessRequest, decision: object) -> None:
        raise RuntimeError("audit backend unavailable")

    guarded = protect_callable(
        sensitive_operation,
        policy=PolicyEngine(
            [
                PolicyRule(
                    rule_id="allow",
                    effect=Effect.ALLOW,
                    actions=frozenset({"execute"}),
                    resources=frozenset({"sensitive_operation"}),
                    roles=frozenset({"operator"}),
                )
            ]
        ),
        principal_resolver=lambda: Principal("alice", roles=frozenset({"operator"})),
        audit_callback=failed_audit,
    )

    with pytest.raises(RuntimeError, match="audit backend unavailable"):
        guarded()

    assert calls == []


def test_guard_preserves_wrapped_function_name_and_signature() -> None:
    def lookup_record(record_id: str, include_history: bool = False) -> str:
        return f"{record_id}:{include_history}"

    guarded = protect_callable(
        lookup_record,
        policy=PolicyEngine([allow_rule(resource="lookup_record", action="execute")]),
        principal_resolver=lambda: Principal("alice", roles=frozenset({"analyst"})),
    )

    assert guarded.__name__ == "lookup_record"
    assert inspect.signature(guarded) == inspect.signature(lookup_record)
    assert guarded("item-1", include_history=True) == "item-1:True"


def test_invalid_principal_resolver_result_fails_closed() -> None:
    calls: list[bool] = []

    def operation() -> None:
        calls.append(True)

    guarded = protect_callable(
        operation,
        policy=PolicyEngine(),
        principal_resolver=lambda: "alice",  # type: ignore[return-value]
    )

    with pytest.raises(TypeError, match="Principal instance"):
        guarded()

    assert calls == []


def test_mutating_resource_resolver_fails_closed_before_callable_execution() -> None:
    calls: list[str] = []
    payload = {"employee_id": "employee-8"}

    def read_payroll(request_payload: dict[str, str]) -> str:
        calls.append(request_payload["employee_id"])
        return request_payload["employee_id"]

    def mutating_resolver(request_payload: dict[str, str]) -> str:
        request_payload["employee_id"] = "employee-7"
        return f"payroll:{request_payload['employee_id']}"

    guarded = protect_callable(
        read_payroll,
        policy=PolicyEngine([allow_rule(resource="payroll:employee-7")]),
        principal_resolver=lambda: Principal("alice", roles=frozenset({"analyst"})),
        action="read",
        resource_resolver=mutating_resolver,
    )

    with pytest.raises(ValueError, match="must not mutate"):
        guarded(payload)

    assert payload == {"employee_id": "employee-8"}
    assert calls == []


def test_protect_callable_rejects_invalid_configuration() -> None:
    def operation() -> None:
        return None

    valid_options: dict[str, Any] = {
        "policy": PolicyEngine(),
        "principal_resolver": lambda: Principal("alice"),
    }
    cases: list[tuple[Any, dict[str, Any], type[Exception], str]] = [
        (object(), {}, TypeError, "function must be callable"),
        (operation, {"policy": object()}, TypeError, "PolicyEngine instance"),
        (operation, {"principal_resolver": None}, TypeError, "principal_resolver must be callable"),
        (
            operation,
            {"resource_resolver": object()},
            TypeError,
            "resource_resolver must be callable",
        ),
        (operation, {"audit_callback": object()}, TypeError, "audit_callback must be callable"),
        (operation, {"action": ""}, ValueError, "concrete action"),
        (operation, {"action": "*"}, ValueError, "concrete action"),
        (operation, {"action": None}, ValueError, "concrete action"),
    ]

    for function, overrides, exception, message in cases:
        options = {**valid_options, **overrides}
        with pytest.raises(exception, match=message):
            protect_callable(function, **options)  # type: ignore[arg-type]
