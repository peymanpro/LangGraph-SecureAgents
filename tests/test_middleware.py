from __future__ import annotations

from collections.abc import Mapping
from types import SimpleNamespace
from typing import Any

import pytest
from langchain_core.messages import ToolMessage

from langgraph_secure_agents import (
    AttributeCondition,
    AttributeReference,
    ConditionOperator,
    Decision,
    DecisionReason,
    Effect,
    PolicyEngine,
    PolicyRule,
    Principal,
)
from langgraph_secure_agents import middleware as middleware_module
from langgraph_secure_agents.middleware import create_authorization_middleware


def allow_rule(
    *,
    rule_id: str = "allow-analyst",
    action: str = "execute",
    resource: str = "read_payroll",
    role: str = "analyst",
) -> PolicyRule:
    return PolicyRule(
        rule_id=rule_id,
        effect=Effect.ALLOW,
        actions=frozenset({action}),
        resources=frozenset({resource}),
        roles=frozenset({role}),
    )


def middleware_request(
    *,
    name: str = "read_payroll",
    args: dict[str, Any] | None = None,
    tool_call_id: str = "call-1",
    context: object = None,
    thread_id: str = "test-thread",
    checkpoint_id: str = "test-checkpoint",
    checkpoint_ns: str = "",
    task_id: str = "test-task",
) -> SimpleNamespace:
    return SimpleNamespace(
        tool_call={"name": name, "args": args or {}, "id": tool_call_id},
        runtime=SimpleNamespace(
            context=context,
            execution_info=SimpleNamespace(
                thread_id=thread_id,
                checkpoint_id=checkpoint_id,
                checkpoint_ns=checkpoint_ns,
                task_id=task_id,
            ),
        ),
        state={},
        tool=None,
    )


def test_denied_tool_call_returns_error_without_running_handler() -> None:
    handler_calls: list[bool] = []
    middleware = create_authorization_middleware(
        PolicyEngine(),
        principal_resolver=lambda context: Principal("guest", roles=frozenset({"guest"})),
    )

    def handler(request: Any) -> ToolMessage:
        handler_calls.append(True)
        return ToolMessage(content="sensitive output", tool_call_id="call-1")

    response = middleware.wrap_tool_call(
        middleware_request(context={"user_id": "guest"}),
        handler,
    )

    assert isinstance(response, ToolMessage)
    assert response.status == "error"
    assert response.tool_call_id == "call-1"
    assert response.content == "Authorization denied."
    assert handler_calls == []


def test_allowed_tool_call_delegates_to_handler() -> None:
    middleware = create_authorization_middleware(
        PolicyEngine([allow_rule()]),
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
    )
    handler_calls: list[bool] = []

    def handler(request: Any) -> ToolMessage:
        handler_calls.append(True)
        return ToolMessage(content="allowed output", tool_call_id="call-2")

    response = middleware.wrap_tool_call(
        middleware_request(tool_call_id="call-2", context={"user_id": "alice"}),
        handler,
    )

    assert isinstance(response, ToolMessage)
    assert response.content == "allowed output"
    assert handler_calls == [True]


def test_identity_is_resolved_from_runtime_context_not_tool_arguments() -> None:
    middleware = create_authorization_middleware(
        PolicyEngine([allow_rule()]),
        principal_resolver=lambda context: Principal(
            str(context["user_id"]),  # type: ignore[index]
            roles=frozenset({str(context["role"])}),  # type: ignore[index]
        ),
    )
    handler_calls: list[bool] = []

    def handler(request: Any) -> ToolMessage:
        handler_calls.append(True)
        return ToolMessage(content="should not run", tool_call_id="call-3")

    response = middleware.wrap_tool_call(
        middleware_request(
            args={"principal_id": "alice"},
            tool_call_id="call-3",
            context={"user_id": "mallory", "role": "guest"},
        ),
        handler,
    )

    assert isinstance(response, ToolMessage)
    assert response.status == "error"
    assert handler_calls == []


def test_resolvers_can_map_tool_arguments_to_domain_action_and_resource() -> None:
    policy = PolicyEngine(
        [
            allow_rule(
                action="read",
                resource="payroll:employee-7",
            )
        ]
    )
    middleware = create_authorization_middleware(
        policy,
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
        action_resolver=lambda tool_name, args: "read",
        resource_resolver=lambda tool_name, args: f"payroll:{args['employee_id']}",
    )

    response = middleware.wrap_tool_call(
        middleware_request(
            args={"employee_id": "employee-7"},
            context={"user_id": "alice"},
        ),
        lambda request: ToolMessage(content="report", tool_call_id="call-4"),
    )

    assert isinstance(response, ToolMessage)
    assert response.content == "report"


def test_audit_failure_prevents_tool_handler_execution() -> None:
    middleware = create_authorization_middleware(
        PolicyEngine([allow_rule()]),
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
        audit_callback=lambda request, decision: (_ for _ in ()).throw(
            RuntimeError("audit unavailable")
        ),
    )
    handler_calls: list[bool] = []

    def handler(request: Any) -> ToolMessage:
        handler_calls.append(True)
        return ToolMessage(content="should not run", tool_call_id="call-5")

    with pytest.raises(RuntimeError, match="audit unavailable"):
        middleware.wrap_tool_call(
            middleware_request(context={"user_id": "alice"}),
            handler,
        )

    assert handler_calls == []


def test_principal_resolver_must_return_a_principal() -> None:
    middleware = create_authorization_middleware(
        PolicyEngine([allow_rule()]),
        principal_resolver=lambda context: "alice",  # type: ignore[return-value]
    )

    with pytest.raises(TypeError, match="Principal instance"):
        middleware.wrap_tool_call(
            middleware_request(context={"user_id": "alice"}),
            lambda request: ToolMessage(content="should not run", tool_call_id="call-6"),
        )


def approval_rule() -> PolicyRule:
    return PolicyRule(
        rule_id="requires-human-approval",
        effect=Effect.REQUIRE_APPROVAL,
        actions=frozenset({"execute"}),
        resources=frozenset({"read_payroll"}),
        roles=frozenset({"analyst"}),
    )


def test_human_approval_resumes_and_then_executes_tool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    interrupt_payloads: list[dict[str, Any]] = []
    audit_events: list[tuple[str, bool]] = []
    handler_calls: list[bool] = []

    def fake_interrupt(payload: dict[str, Any]) -> dict[str, Any]:
        interrupt_payloads.append(payload)
        return {"approved": True, "request_fingerprint": payload["request_fingerprint"]}

    monkeypatch.setattr(middleware_module, "interrupt", fake_interrupt)
    middleware = create_authorization_middleware(
        PolicyEngine([approval_rule()]),
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
        audit_callback=lambda request, decision: audit_events.append(
            (decision.reason, decision.allowed)
        ),
    )

    def handler(request: Any) -> ToolMessage:
        handler_calls.append(True)
        return ToolMessage(content="approved output", tool_call_id="call-approval")

    response = middleware.wrap_tool_call(
        middleware_request(tool_call_id="call-approval", context={"user_id": "alice"}),
        handler,
    )

    assert isinstance(response, ToolMessage)
    assert response.content == "approved output"
    assert handler_calls == [True]
    assert len(interrupt_payloads) == 1
    assert interrupt_payloads[0]["type"] == "authorization_approval"
    assert interrupt_payloads[0]["principal_id"] == "alice"
    assert interrupt_payloads[0]["request_fingerprint"]
    assert audit_events == [("human_approved", True)]


def test_human_rejection_never_executes_tool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handler_calls: list[bool] = []
    audit_reasons: list[str] = []

    def fake_interrupt(payload: dict[str, Any]) -> dict[str, Any]:
        return {"approved": False, "request_fingerprint": payload["request_fingerprint"]}

    monkeypatch.setattr(middleware_module, "interrupt", fake_interrupt)
    middleware = create_authorization_middleware(
        PolicyEngine([approval_rule()]),
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
        audit_callback=lambda request, decision: audit_reasons.append(decision.reason),
    )

    response = middleware.wrap_tool_call(
        middleware_request(tool_call_id="call-rejected"),
        lambda request: handler_calls.append(True),
    )

    assert isinstance(response, ToolMessage)
    assert response.status == "error"
    assert response.content == "Human approval denied."
    assert handler_calls == []
    assert audit_reasons == ["approval_denied"]


def test_mismatched_approval_fingerprint_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handler_calls: list[bool] = []
    audit_reasons: list[str] = []

    def fake_interrupt(payload: dict[str, Any]) -> dict[str, Any]:
        return {"approved": True, "request_fingerprint": "not-the-request-fingerprint"}

    monkeypatch.setattr(middleware_module, "interrupt", fake_interrupt)
    middleware = create_authorization_middleware(
        PolicyEngine([approval_rule()]),
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
        audit_callback=lambda request, decision: audit_reasons.append(decision.reason),
    )

    response = middleware.wrap_tool_call(
        middleware_request(tool_call_id="call-tampered"),
        lambda request: handler_calls.append(True),
    )

    assert isinstance(response, ToolMessage)
    assert response.status == "error"
    assert response.content == "Approval response invalid; tool was not executed."
    assert handler_calls == []
    assert audit_reasons == ["approval_invalid"]


def test_approval_fingerprint_binds_tool_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    received: list[dict[str, Any]] = []

    def fake_interrupt(payload: dict[str, Any]) -> dict[str, Any]:
        received.append(payload)
        return {"approved": True, "request_fingerprint": payload["request_fingerprint"]}

    monkeypatch.setattr(middleware_module, "interrupt", fake_interrupt)
    middleware = create_authorization_middleware(
        PolicyEngine([approval_rule()]),
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
    )

    middleware.wrap_tool_call(
        middleware_request(args={"employee_id": "employee-7"}, tool_call_id="call-args"),
        lambda request: ToolMessage(content="ok", tool_call_id="call-args"),
    )
    first_fingerprint = received[-1]["request_fingerprint"]

    middleware.wrap_tool_call(
        middleware_request(args={"employee_id": "employee-8"}, tool_call_id="call-args"),
        lambda request: ToolMessage(content="ok", tool_call_id="call-args"),
    )
    second_fingerprint = received[-1]["request_fingerprint"]

    assert first_fingerprint != second_fingerprint


@pytest.mark.parametrize("mutating_resolver", ["action", "resource"])
def test_mutating_scope_resolver_fails_closed_without_changing_tool_args(
    mutating_resolver: str,
) -> None:
    tool_args = {"employee_id": "employee-8"}
    handler_calls: list[bool] = []

    def mutate_and_resolve(tool_name: str, args: Mapping[str, Any]) -> str:
        args["employee_id"] = "employee-7"  # type: ignore[index]
        return "read" if mutating_resolver == "action" else "payroll:employee-7"

    middleware = create_authorization_middleware(
        PolicyEngine(),
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
        action_resolver=mutate_and_resolve if mutating_resolver == "action" else None,
        resource_resolver=mutate_and_resolve if mutating_resolver == "resource" else None,
    )

    with pytest.raises(ValueError, match="must not mutate"):
        middleware.wrap_tool_call(
            middleware_request(args=tool_args, context={"user_id": "alice"}),
            lambda request: handler_calls.append(True),
        )

    assert tool_args == {"employee_id": "employee-8"}
    assert handler_calls == []


def test_middleware_rejects_invalid_configuration() -> None:
    valid_options: dict[str, Any] = {
        "policy": PolicyEngine(),
        "principal_resolver": lambda context: Principal("alice"),
    }
    cases: list[tuple[dict[str, Any], type[Exception], str]] = [
        ({"policy": object()}, TypeError, "PolicyEngine instance"),
        ({"principal_resolver": None}, TypeError, "principal_resolver must be callable"),
        ({"action_resolver": object()}, TypeError, "action_resolver must be callable"),
        ({"resource_resolver": object()}, TypeError, "resource_resolver must be callable"),
        ({"audit_callback": object()}, TypeError, "audit_callback must be callable"),
        ({"approval_validator": object()}, TypeError, "approval_validator must be callable"),
    ]

    for overrides, exception, message in cases:
        with pytest.raises(exception, match=message):
            create_authorization_middleware(
                **{**valid_options, **overrides}  # type: ignore[arg-type]
            )


def test_middleware_rejects_malformed_tool_call_requests() -> None:
    middleware = create_authorization_middleware(
        PolicyEngine(),
        principal_resolver=lambda context: Principal("alice"),
    )

    def handler(request: Any) -> ToolMessage:
        return ToolMessage(content="should not run", tool_call_id="call-1")

    with pytest.raises(TypeError, match="tool_call mapping"):
        middleware.wrap_tool_call(SimpleNamespace(runtime=SimpleNamespace(context=None)), handler)

    with pytest.raises(ValueError, match="non-empty name"):
        middleware.wrap_tool_call(
            middleware_request(name="   "),
            handler,
        )

    malformed_args_request = SimpleNamespace(
        tool_call={"name": "read_payroll", "args": "not-a-mapping", "id": "call-args"},
        runtime=SimpleNamespace(context=None),
        state={},
        tool=None,
    )
    with pytest.raises(TypeError, match="args must be a mapping"):
        middleware.wrap_tool_call(malformed_args_request, handler)


def test_denied_tool_call_without_id_fails_closed() -> None:
    middleware = create_authorization_middleware(
        PolicyEngine(),
        principal_resolver=lambda context: Principal("guest"),
    )
    request = SimpleNamespace(
        tool_call={"name": "read_payroll", "args": {}},
        runtime=SimpleNamespace(context=None),
        state={},
        tool=None,
    )

    with pytest.raises(ValueError, match="must include a tool-call id"):
        middleware.wrap_tool_call(
            request,
            lambda tool_request: ToolMessage(content="should not run", tool_call_id="call-no-id"),
        )


def test_approval_required_call_without_id_fails_closed() -> None:
    middleware = create_authorization_middleware(
        PolicyEngine([approval_rule()]),
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
    )
    request = SimpleNamespace(
        tool_call={"name": "read_payroll", "args": {}},
        runtime=SimpleNamespace(context=None),
        state={},
        tool=None,
    )

    with pytest.raises(ValueError, match="must include a tool-call id"):
        middleware.wrap_tool_call(
            request,
            lambda tool_request: ToolMessage(content="should not run", tool_call_id="call-no-id"),
        )


def test_approval_with_non_json_arguments_fails_closed() -> None:
    middleware = create_authorization_middleware(
        PolicyEngine([approval_rule()]),
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
    )

    with pytest.raises(ValueError, match="JSON-serializable"):
        middleware.wrap_tool_call(
            middleware_request(args={"payload": object()}),
            lambda request: ToolMessage(content="should not run", tool_call_id="call-1"),
        )


def test_approval_fingerprint_binds_the_matched_policy_definition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fingerprints: list[str] = []

    def fake_interrupt(payload: dict[str, Any]) -> dict[str, Any]:
        fingerprints.append(payload["request_fingerprint"])
        return {"approved": True, "request_fingerprint": payload["request_fingerprint"]}

    monkeypatch.setattr(middleware_module, "interrupt", fake_interrupt)
    policies = [
        PolicyEngine([approval_rule()]),
        PolicyEngine(
            [
                PolicyRule(
                    rule_id="requires-human-approval",
                    effect=Effect.REQUIRE_APPROVAL,
                    actions=frozenset({"execute"}),
                    resources=frozenset({"read_payroll"}),
                    roles=frozenset({"analyst", "hr"}),
                )
            ]
        ),
    ]

    for policy in policies:
        middleware = create_authorization_middleware(
            policy,
            principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
        )
        response = middleware.wrap_tool_call(
            middleware_request(args={"employee_id": "employee-7"}, tool_call_id="call-policy"),
            lambda request: ToolMessage(content="approved", tool_call_id="call-policy"),
        )
        assert isinstance(response, ToolMessage)
        assert response.content == "approved"

    assert fingerprints[0] != fingerprints[1]


def test_approval_fingerprint_accepts_standard_json_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_interrupt(payload: dict[str, Any]) -> dict[str, Any]:
        return {"approved": True, "request_fingerprint": payload["request_fingerprint"]}

    monkeypatch.setattr(middleware_module, "interrupt", fake_interrupt)
    middleware = create_authorization_middleware(
        PolicyEngine([approval_rule()]),
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
    )
    args = {
        "none": None,
        "boolean": True,
        "integer": 7,
        "float": 2.5,
        "tuple": (1, "two"),
        "nested": {"values": [False, None, "text"]},
    }

    response = middleware.wrap_tool_call(
        middleware_request(args=args, tool_call_id="call-json"),
        lambda request: ToolMessage(content="approved", tool_call_id="call-json"),
    )

    assert isinstance(response, ToolMessage)
    assert response.content == "approved"


@pytest.mark.parametrize(
    "args",
    [
        {"payload": {1: "non-string-key"}},
        {"payload": float("nan")},
        {"payload": float("inf")},
    ],
)
def test_approval_fingerprint_rejects_ambiguous_or_nonfinite_json_values(
    monkeypatch: pytest.MonkeyPatch,
    args: dict[str, Any],
) -> None:
    middleware = create_authorization_middleware(
        PolicyEngine([approval_rule()]),
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
    )

    with pytest.raises(ValueError, match="JSON-serializable"):
        middleware.wrap_tool_call(
            middleware_request(args=args, tool_call_id="call-invalid-json"),
            lambda request: ToolMessage(content="should not run", tool_call_id="call-invalid-json"),
        )


def test_approval_fingerprint_rejects_cyclic_arguments() -> None:
    middleware = create_authorization_middleware(
        PolicyEngine([approval_rule()]),
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
    )
    cyclic_values: list[Any] = []
    cyclic_values.append(cyclic_values)

    with pytest.raises(ValueError, match="JSON-serializable"):
        middleware.wrap_tool_call(
            middleware_request(args={"cycle": cyclic_values}, tool_call_id="call-cycle"),
            lambda request: ToolMessage(content="should not run", tool_call_id="call-cycle"),
        )


def test_unknown_matched_policy_rule_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def inconsistent_evaluate(self: PolicyEngine, request: Any) -> Decision:
        return Decision(
            allowed=False,
            reason=DecisionReason.APPROVAL_REQUIRED,
            matched_rule_ids=("missing-rule",),
            requires_approval=True,
        )

    monkeypatch.setattr(PolicyEngine, "evaluate", inconsistent_evaluate)
    middleware = create_authorization_middleware(
        PolicyEngine(),
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
    )

    with pytest.raises(RuntimeError, match="unknown policy rule"):
        middleware.wrap_tool_call(
            middleware_request(context={"user_id": "alice"}),
            lambda request: ToolMessage(content="should not run", tool_call_id="call-unknown-rule"),
        )


def test_approval_fingerprint_binds_checkpoint_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fingerprints: list[str] = []

    def fake_interrupt(payload: dict[str, Any]) -> dict[str, Any]:
        fingerprints.append(payload["request_fingerprint"])
        return {"approved": True, "request_fingerprint": payload["request_fingerprint"]}

    monkeypatch.setattr(middleware_module, "interrupt", fake_interrupt)
    middleware = create_authorization_middleware(
        PolicyEngine([approval_rule()]),
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
    )

    for checkpoint_id in ("checkpoint-one", "checkpoint-two"):
        response = middleware.wrap_tool_call(
            middleware_request(
                args={"employee_id": "employee-7"},
                tool_call_id="call-same",
                context={"user_id": "alice"},
                checkpoint_id=checkpoint_id,
            ),
            lambda request: ToolMessage(content="approved", tool_call_id="call-same"),
        )
        assert isinstance(response, ToolMessage)

    assert len(fingerprints) == 2
    assert fingerprints[0] != fingerprints[1]


def test_approval_fails_closed_without_checkpoint_execution_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    interrupt_called: list[bool] = []
    validator_called: list[bool] = []

    def fake_interrupt(payload: dict[str, Any]) -> dict[str, Any]:
        interrupt_called.append(True)
        return {"approved": True, "request_fingerprint": payload["request_fingerprint"]}

    def validator(
        approval: Mapping[str, Any],
        access_request: Any,
        fingerprint: str,
    ) -> bool:
        validator_called.append(True)
        return True

    monkeypatch.setattr(middleware_module, "interrupt", fake_interrupt)
    middleware = create_authorization_middleware(
        PolicyEngine([approval_rule()]),
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
        approval_validator=validator,
    )
    request = middleware_request(context={"user_id": "alice"})
    request.runtime.execution_info = None

    with pytest.raises(RuntimeError, match="execution metadata"):
        middleware.wrap_tool_call(
            request,
            lambda tool_request: ToolMessage(content="should not run", tool_call_id="call-1"),
        )

    assert interrupt_called == []
    assert validator_called == []


def test_approval_validator_consumes_identical_request_only_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handler_calls: list[str] = []
    audit_reasons: list[str] = []
    fingerprints: list[str] = []
    consumed_fingerprints: set[str] = set()

    def fake_interrupt(payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "approved": True,
            "request_fingerprint": payload["request_fingerprint"],
            "reviewer_id": "reviewer-17",
        }

    def validate_and_consume(
        approval: Mapping[str, Any],
        access_request: Any,
        fingerprint: str,
    ) -> bool:
        assert approval["reviewer_id"] == "reviewer-17"
        assert access_request.principal.principal_id == "alice"
        fingerprints.append(fingerprint)
        if fingerprint in consumed_fingerprints:
            return False
        consumed_fingerprints.add(fingerprint)
        return True

    monkeypatch.setattr(middleware_module, "interrupt", fake_interrupt)
    middleware = create_authorization_middleware(
        PolicyEngine([approval_rule()]),
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
        audit_callback=lambda request, decision: audit_reasons.append(decision.reason),
        approval_validator=validate_and_consume,
    )

    def handler(request: Any) -> ToolMessage:
        handler_calls.append(request.tool_call["id"])
        return ToolMessage(content="approved", tool_call_id=request.tool_call["id"])

    def same_request() -> Any:
        return middleware_request(
            args={"employee_id": "employee-7"},
            tool_call_id="same-idempotency-key",
            context={"user_id": "alice"},
        )

    first = middleware.wrap_tool_call(same_request(), handler)
    second = middleware.wrap_tool_call(same_request(), handler)

    assert isinstance(first, ToolMessage)
    assert first.content == "approved"
    assert isinstance(second, ToolMessage)
    assert second.status == "error"
    assert second.content == "Approval response invalid; tool was not executed."
    assert fingerprints[0] == fingerprints[1]
    assert handler_calls == ["same-idempotency-key"]
    assert audit_reasons == ["human_approved", "approval_invalid"]


@pytest.mark.parametrize("validator_result", [False, None, 1, "yes"])
def test_approval_validator_requires_literal_true(
    monkeypatch: pytest.MonkeyPatch,
    validator_result: object,
) -> None:
    handler_calls: list[bool] = []

    def fake_interrupt(payload: dict[str, Any]) -> dict[str, Any]:
        return {"approved": True, "request_fingerprint": payload["request_fingerprint"]}

    monkeypatch.setattr(middleware_module, "interrupt", fake_interrupt)
    middleware = create_authorization_middleware(
        PolicyEngine([approval_rule()]),
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
        approval_validator=lambda approval, request, fingerprint: validator_result,  # type: ignore[return-value]
    )

    response = middleware.wrap_tool_call(
        middleware_request(tool_call_id="call-validator-result"),
        lambda request: handler_calls.append(True),
    )

    assert isinstance(response, ToolMessage)
    assert response.status == "error"
    assert response.content == "Approval response invalid; tool was not executed."
    assert handler_calls == []


def test_approval_validator_exception_fails_closed_before_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handler_calls: list[bool] = []

    def fake_interrupt(payload: dict[str, Any]) -> dict[str, Any]:
        return {"approved": True, "request_fingerprint": payload["request_fingerprint"]}

    def unavailable_validator(
        approval: Mapping[str, Any],
        access_request: Any,
        fingerprint: str,
    ) -> bool:
        raise RuntimeError("approval store unavailable")

    monkeypatch.setattr(middleware_module, "interrupt", fake_interrupt)
    middleware = create_authorization_middleware(
        PolicyEngine([approval_rule()]),
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
        approval_validator=unavailable_validator,
    )

    with pytest.raises(RuntimeError, match="approval store unavailable"):
        middleware.wrap_tool_call(
            middleware_request(tool_call_id="call-validator-error"),
            lambda request: handler_calls.append(True),
        )

    assert handler_calls == []


def test_approval_validator_is_not_called_for_mismatched_fingerprint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validator_calls: list[bool] = []
    handler_calls: list[bool] = []

    def fake_interrupt(payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "approved": True,
            "request_fingerprint": "fingerprint-from-another-request",
            "reviewer_id": "reviewer-17",
        }

    def validator(
        approval: Mapping[str, Any],
        access_request: Any,
        fingerprint: str,
    ) -> bool:
        validator_calls.append(True)
        return True

    monkeypatch.setattr(middleware_module, "interrupt", fake_interrupt)
    middleware = create_authorization_middleware(
        PolicyEngine([approval_rule()]),
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
        approval_validator=validator,
    )

    response = middleware.wrap_tool_call(
        middleware_request(tool_call_id="call-unbound-approval"),
        lambda request: handler_calls.append(True),
    )

    assert isinstance(response, ToolMessage)
    assert response.status == "error"
    assert response.content == "Approval response invalid; tool was not executed."
    assert validator_calls == []
    assert handler_calls == []


def test_middleware_enforces_tenant_abac_using_trusted_resource_metadata() -> None:
    resources = {
        "document:42": {"tenant_id": "tenant-a"},
        "document:99": {"tenant_id": "tenant-b"},
    }
    policy = PolicyEngine(
        [
            PolicyRule(
                rule_id="analysts-read-own-tenant-documents",
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

    def resolve_principal(context: object) -> Principal:
        assert isinstance(context, Mapping)
        return Principal(
            str(context["user_id"]),
            roles=frozenset({"analyst"}),
            attributes={"tenant_id": str(context["tenant_id"])},
        )

    middleware = create_authorization_middleware(
        policy,
        principal_resolver=resolve_principal,
        action_resolver=lambda tool_name, args: "read",
        resource_resolver=lambda tool_name, args: f"document:{args['document_id']}",
        resource_attributes_resolver=lambda resource: resources[resource],
        context_resolver=lambda context: {"environment": context["environment"]},  # type: ignore[index]
    )
    handler_calls: list[str] = []

    def handler(request: Any) -> ToolMessage:
        handler_calls.append(request.tool_call["args"]["document_id"])
        return ToolMessage(content="document read", tool_call_id=request.tool_call["id"])

    same_tenant = middleware.wrap_tool_call(
        middleware_request(
            args={"document_id": "42"},
            tool_call_id="tenant-match",
            context={"user_id": "alice", "tenant_id": "tenant-a", "environment": "prod"},
        ),
        handler,
    )
    cross_tenant = middleware.wrap_tool_call(
        middleware_request(
            args={"document_id": "99"},
            tool_call_id="tenant-mismatch",
            context={"user_id": "alice", "tenant_id": "tenant-a", "environment": "prod"},
        ),
        handler,
    )

    assert isinstance(same_tenant, ToolMessage)
    assert same_tenant.content == "document read"
    assert isinstance(cross_tenant, ToolMessage)
    assert cross_tenant.status == "error"
    assert cross_tenant.content == "Authorization denied."
    assert handler_calls == ["42"]


def test_abac_condition_definitions_are_bound_into_approval_fingerprint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fingerprints: list[str] = []

    def fake_interrupt(payload: dict[str, Any]) -> dict[str, Any]:
        fingerprints.append(payload["request_fingerprint"])
        return {"approved": True, "request_fingerprint": payload["request_fingerprint"]}

    monkeypatch.setattr(middleware_module, "interrupt", fake_interrupt)
    rules = [
        PolicyRule(
            rule_id="approval-rule",
            effect=Effect.REQUIRE_APPROVAL,
            actions=frozenset({"execute"}),
            resources=frozenset({"read_payroll"}),
            roles=frozenset({"analyst"}),
            conditions=(condition,),
        )
        for condition in (
            AttributeCondition("principal.attributes.clearance", ConditionOperator.EQ, "high"),
            AttributeCondition(
                "principal.attributes.clearance",
                ConditionOperator.IN,
                ["high", "restricted"],
            ),
        )
    ]

    for policy_rule in rules:
        middleware = create_authorization_middleware(
            PolicyEngine([policy_rule]),
            principal_resolver=lambda context: Principal(
                "alice",
                roles=frozenset({"analyst"}),
                attributes={"clearance": "high"},
            ),
        )
        response = middleware.wrap_tool_call(
            middleware_request(
                tool_call_id="same-approval-call",
                context={"user_id": "alice"},
            ),
            lambda request: ToolMessage(content="approved", tool_call_id="same-approval-call"),
        )
        assert isinstance(response, ToolMessage)
        assert response.content == "approved"

    assert len(fingerprints) == 2
    assert fingerprints[0] != fingerprints[1]
