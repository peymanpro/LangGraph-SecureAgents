from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from langchain_core.messages import ToolMessage

from langgraph_secure_agents import Effect, PolicyEngine, PolicyRule, Principal
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
) -> SimpleNamespace:
    return SimpleNamespace(
        tool_call={"name": name, "args": args or {}, "id": tool_call_id},
        runtime=SimpleNamespace(context=context),
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
