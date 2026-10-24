from __future__ import annotations

import inspect
from typing import Any

import pytest

from langgraph_secure_agents import (
    AccessRequest,
    AttributeCondition,
    AttributeReference,
    ConditionOperator,
    Effect,
    PolicyEngine,
    PolicyRule,
    Principal,
)
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
        (
            operation,
            {"resource_attributes_resolver": object()},
            TypeError,
            "resource_attributes_resolver must be callable",
        ),
        (
            operation,
            {"context_resolver": object()},
            TypeError,
            "context_resolver must be callable",
        ),
        (operation, {"audit_callback": object()}, TypeError, "audit_callback must be callable"),
        (
            operation,
            {"audit_event_callback": object()},
            TypeError,
            "audit_event_callback must be callable",
        ),
        (
            operation,
            {"request_id_resolver": object()},
            TypeError,
            "request_id_resolver must be callable",
        ),
        (
            operation,
            {"execution_id_resolver": object()},
            TypeError,
            "execution_id_resolver must be callable",
        ),
        (operation, {"action": ""}, ValueError, "concrete action"),
        (operation, {"action": "*"}, ValueError, "concrete action"),
        (operation, {"action": None}, ValueError, "concrete action"),
    ]

    for function, overrides, exception, message in cases:
        options = {**valid_options, **overrides}
        with pytest.raises(exception, match=message):
            protect_callable(function, **options)  # type: ignore[arg-type]


def test_async_callable_authorizes_when_awaited_not_when_coroutine_is_created() -> None:
    import asyncio
    from collections.abc import Awaitable

    current_principal = [Principal("alice", roles=frozenset({"analyst"}))]
    resolver_calls: list[str] = []
    handler_calls: list[str] = []

    async def read_payroll(employee_id: str) -> str:
        handler_calls.append(employee_id)
        return f"payroll:{employee_id}"

    def resolve_principal() -> Principal:
        resolver_calls.append(current_principal[0].principal_id)
        return current_principal[0]

    guarded = protect_callable(
        read_payroll,
        policy=PolicyEngine([allow_rule(resource="payroll:employee-7")]),
        principal_resolver=resolve_principal,
        action="read",
        resource_resolver=lambda employee_id: f"payroll:{employee_id}",
    )

    async def scenario() -> None:
        pending = guarded("employee-7")
        assert isinstance(pending, Awaitable)
        assert resolver_calls == []
        assert handler_calls == []

        current_principal[0] = Principal("mallory", roles=frozenset({"guest"}))
        with pytest.raises(AuthorizationDenied):
            await pending

        assert resolver_calls == ["mallory"]
        assert handler_calls == []

    asyncio.run(scenario())


def test_callable_guard_enforces_tenant_abac_before_function_execution() -> None:
    records = {
        "document:42": {"tenant_id": "tenant-a"},
        "document:99": {"tenant_id": "tenant-b"},
    }
    policy = PolicyEngine(
        [
            PolicyRule(
                rule_id="read-own-tenant-document",
                effect=Effect.ALLOW,
                actions=frozenset({"read"}),
                resources=frozenset({"*"}),
                roles=frozenset({"analyst"}),
                conditions=(
                    AttributeCondition(
                        "principal.attributes.tenant_id",
                        ConditionOperator.EQ,
                        AttributeReference("resource.attributes.tenant_id"),
                    ),
                    AttributeCondition("context.environment", ConditionOperator.EQ, "prod"),
                ),
            )
        ]
    )
    calls: list[str] = []

    def read_document(document_id: str) -> str:
        calls.append(document_id)
        return f"document:{document_id}"

    guarded = protect_callable(
        read_document,
        policy=policy,
        principal_resolver=lambda: Principal(
            "alice",
            roles=frozenset({"analyst"}),
            attributes={"tenant_id": "tenant-a"},
        ),
        action="read",
        resource_resolver=lambda document_id: f"document:{document_id}",
        resource_attributes_resolver=lambda resource: records[resource],
        context_resolver=lambda: {"environment": "prod"},
    )

    assert guarded("42") == "document:42"
    with pytest.raises(AuthorizationDenied):
        guarded("99")

    assert calls == ["42"]


def test_callable_guard_fails_closed_when_attribute_resolvers_return_non_mappings() -> None:
    def operation(document_id: str) -> str:
        return document_id

    guarded = protect_callable(
        operation,
        policy=PolicyEngine([allow_rule(resource="document:42")]),
        principal_resolver=lambda: Principal("alice", roles=frozenset({"analyst"})),
        action="read",
        resource_resolver=lambda document_id: f"document:{document_id}",
        resource_attributes_resolver=lambda resource: "not-metadata",  # type: ignore[return-value]
    )

    with pytest.raises(TypeError, match="resource_attributes_resolver must return a mapping"):
        guarded("42")


def test_callable_guard_fails_closed_when_context_resolver_returns_non_mapping() -> None:
    calls: list[bool] = []

    def operation() -> str:
        calls.append(True)
        return "executed"

    guarded = protect_callable(
        operation,
        policy=PolicyEngine([allow_rule(resource="operation")]),
        principal_resolver=lambda: Principal("alice", roles=frozenset({"analyst"})),
        context_resolver=lambda: "untrusted-context",  # type: ignore[return-value]
    )

    with pytest.raises(TypeError, match="context_resolver must return a mapping"):
        guarded()

    assert calls == []


def test_async_callable_executes_when_authorization_succeeds() -> None:
    import asyncio

    async def operation() -> str:
        return "approved"

    guarded = protect_callable(
        operation,
        policy=PolicyEngine([allow_rule(resource="operation", action="execute")]),
        principal_resolver=lambda: Principal("alice", roles=frozenset({"analyst"})),
    )

    assert asyncio.run(guarded()) == "approved"

def test_resource_attributes_resolver_receives_normalized_resource_id() -> None:
    resolved_resources: list[str] = []

    def resource_attributes(resource: str) -> dict[str, str]:
        resolved_resources.append(resource)
        if resource == "customer:101":
            return {"tenant_id": "tenant-a"}
        return {}

    policy = PolicyEngine(
        [
            PolicyRule(
                rule_id="read-own-tenant-customer",
                effect=Effect.ALLOW,
                actions=frozenset({"read"}),
                resources=frozenset({"customer:101"}),
                roles=frozenset({"analyst"}),
                conditions=(
                    AttributeCondition(
                        attribute="principal.attributes.tenant_id",
                        operator=ConditionOperator.EQ,
                        value=AttributeReference("resource.attributes.tenant_id"),
                    ),
                ),
            )
        ]
    )
    guarded = protect_callable(
        lambda customer_id: f"Customer {customer_id}",
        policy=policy,
        principal_resolver=lambda: Principal(
            "analyst-7",
            roles=frozenset({"analyst"}),
            attributes={"tenant_id": "tenant-a"},
        ),
        action="read",
        resource_resolver=lambda _customer_id: " customer:101 ",
        resource_attributes_resolver=resource_attributes,
    )

    assert guarded("101") == "Customer 101"
    assert resolved_resources == ["customer:101"]


@pytest.mark.parametrize("invalid_resource", ["", "   ", "*", None, 7])
def test_invalid_resolved_resource_fails_before_metadata_lookup(
    invalid_resource: object,
) -> None:
    metadata_calls: list[str] = []
    handler_calls: list[str] = []

    def read_customer(customer_id: str) -> str:
        handler_calls.append(customer_id)
        return customer_id

    guarded = protect_callable(
        read_customer,
        policy=PolicyEngine([allow_rule(resource="customer:101")]),
        principal_resolver=lambda: Principal("analyst-7", roles=frozenset({"analyst"})),
        action="read",
        resource_resolver=lambda _customer_id: invalid_resource,
        resource_attributes_resolver=lambda resource: metadata_calls.append(resource) or {},
    )

    with pytest.raises(ValueError):
        guarded("101")

    assert metadata_calls == []
    assert handler_calls == []
