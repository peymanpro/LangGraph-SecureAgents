from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any, TypedDict

import pytest
from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.runtime import Runtime
from langgraph.types import Command, interrupt

from langgraph_secure_agents import (
    AuthorizationDenied,
    DecisionReason,
    Effect,
    PolicyBundle,
    PolicyEngine,
    PolicyRegistry,
    PolicyRule,
    Principal,
)
from langgraph_secure_agents.audit import AuditEvent
from langgraph_secure_agents.langgraph import protect_node


class GraphState(TypedDict):
    resource_id: str
    completed: bool
    claimed_roles: list[str]


class AuthContext(TypedDict):
    user_id: str
    roles: list[str]
    tenant_id: str


def _principal(context: object) -> Principal:
    if not isinstance(context, Mapping):
        raise TypeError("trusted context must be a mapping")
    return Principal(str(context["user_id"]), roles=frozenset(context["roles"]))


def _policy(effect: Effect = Effect.ALLOW) -> PolicyEngine:
    return PolicyEngine(
        [
            PolicyRule(
                rule_id=f"{effect.value}-refund",
                effect=effect,
                actions=frozenset({"refund"}),
                resources=frozenset({"order:42"}),
                roles=frozenset({"operator"}),
            )
        ]
    )


def _graph(
    node: Any,
    policy: PolicyEngine | PolicyRegistry,
    **guard_options: Any,
) -> Any:
    guard_options.setdefault("resource_resolver", lambda state: state["resource_id"])
    guard_options.setdefault("principal_resolver", _principal)
    protected = protect_node(
        node,
        policy=policy,
        action="refund",
        **guard_options,
    )
    builder = StateGraph(GraphState, context_schema=AuthContext)
    builder.add_node("sensitive_operation", protected)
    builder.add_edge(START, "sensitive_operation")
    builder.add_edge("sensitive_operation", END)
    return builder.compile()


def _initial_state(resource_id: str = "order:42") -> GraphState:
    return {"resource_id": resource_id, "completed": False, "claimed_roles": []}


def _context(roles: list[str] | None = None) -> AuthContext:
    return {
        "user_id": "alice",
        "roles": ["operator"] if roles is None else roles,
        "tenant_id": "tenant-a",
    }


def test_allowed_node_executes_once_and_emits_audit_events() -> None:
    side_effects: list[str] = []
    events: list[AuditEvent] = []
    callback_requests: list[str] = []

    def refund_node(state: GraphState, runtime: Runtime[AuthContext]) -> dict[str, bool]:
        side_effects.append(state["resource_id"])
        assert runtime.context["user_id"] == "alice"
        return {"completed": True}

    graph = _graph(
        refund_node,
        _policy(),
        resource_attributes_resolver=lambda resource: {"tenant_id": "tenant-a"},
        context_resolver=lambda context: {"tenant_id": context["tenant_id"]},
        audit_callback=lambda request, decision: callback_requests.append(request.resource),
        audit_event_callback=events.append,
        policy_id="orders",
        policy_version="1.0",
        policy_digest="abc123",
    )

    result = graph.invoke(_initial_state(), context=_context())

    assert result["completed"] is True
    assert side_effects == ["order:42"]
    assert callback_requests == ["order:42"]
    assert len(events) == 1
    assert events[0].source == "langgraph_node"
    assert events[0].resource == "order:42"
    assert events[0].policy_id == "orders"
    assert events[0].policy_version == "1.0"
    assert events[0].policy_digest == "abc123"


def test_explicit_deny_overrides_allow_before_node_side_effect() -> None:
    side_effects: list[str] = []
    policy = PolicyEngine(
        [
            PolicyRule(
                rule_id="allow-refund",
                effect=Effect.ALLOW,
                actions=frozenset({"refund"}),
                resources=frozenset({"order:42"}),
                roles=frozenset({"operator"}),
            ),
            PolicyRule(
                rule_id="deny-refund",
                effect=Effect.DENY,
                actions=frozenset({"refund"}),
                resources=frozenset({"order:42"}),
                roles=frozenset({"operator"}),
            ),
        ]
    )

    def refund_node(state: GraphState, runtime: Runtime[AuthContext]) -> dict[str, bool]:
        side_effects.append(state["resource_id"])
        return {"completed": True}

    with pytest.raises(AuthorizationDenied) as raised:
        _graph(refund_node, policy).invoke(_initial_state(), context=_context())

    assert raised.value.decision.reason is DecisionReason.EXPLICIT_DENY
    assert side_effects == []


def test_default_deny_and_changed_resource_prevent_execution() -> None:
    side_effects: list[str] = []

    def refund_node(state: GraphState, runtime: Runtime[AuthContext]) -> dict[str, bool]:
        side_effects.append(state["resource_id"])
        return {"completed": True}

    graph = _graph(refund_node, PolicyEngine())
    with pytest.raises(AuthorizationDenied) as missing_policy:
        graph.invoke(_initial_state(), context=_context())
    assert missing_policy.value.decision.reason is DecisionReason.DEFAULT_DENY

    with pytest.raises(AuthorizationDenied) as other_resource:
        _graph(refund_node, _policy()).invoke(
            _initial_state("order:43"),
            context=_context(),
        )
    assert other_resource.value.request.resource == "order:43"
    assert other_resource.value.decision.reason is DecisionReason.DEFAULT_DENY
    assert side_effects == []


def test_approval_required_node_fails_closed_without_running() -> None:
    side_effects: list[str] = []

    def refund_node(state: GraphState, runtime: Runtime[AuthContext]) -> dict[str, bool]:
        side_effects.append(state["resource_id"])
        return {"completed": True}

    with pytest.raises(AuthorizationDenied) as raised:
        _graph(refund_node, _policy(Effect.REQUIRE_APPROVAL)).invoke(
            _initial_state(),
            context=_context(),
        )

    assert raised.value.decision.requires_approval is True
    assert raised.value.decision.reason is DecisionReason.APPROVAL_REQUIRED
    assert side_effects == []


def test_policy_registry_snapshot_metadata_is_audited() -> None:
    registry = PolicyRegistry(
        PolicyBundle(
            policy_id="orders",
            version="2.1.0",
            description="Order operations",
            rules=(
                PolicyRule(
                    rule_id="allow-refund",
                    effect=Effect.ALLOW,
                    actions=frozenset({"refund"}),
                    resources=frozenset({"order:42"}),
                    roles=frozenset({"operator"}),
                ),
            ),
        )
    )
    events: list[AuditEvent] = []

    def refund_node(state: GraphState, runtime: Runtime[AuthContext]) -> dict[str, bool]:
        return {"completed": True}

    result = _graph(refund_node, registry, audit_event_callback=events.append).invoke(
        _initial_state(),
        context=_context(),
    )

    assert result["completed"] is True
    assert events[0].policy_id == "orders"
    assert events[0].policy_version == "2.1.0"
    assert events[0].policy_digest == registry.snapshot().digest


def test_async_node_is_authorized_before_its_body_runs() -> None:
    side_effects: list[str] = []

    async def refund_node(state: GraphState, runtime: Runtime[AuthContext]) -> dict[str, bool]:
        await asyncio.sleep(0)
        side_effects.append(state["resource_id"])
        return {"completed": True}

    result = asyncio.run(
        _graph(refund_node, _policy()).ainvoke(_initial_state(), context=_context())
    )
    assert result["completed"] is True
    assert side_effects == ["order:42"]


def test_resolver_exception_or_mutation_fails_closed() -> None:
    side_effects: list[str] = []

    def refund_node(state: GraphState, runtime: Runtime[AuthContext]) -> dict[str, bool]:
        side_effects.append(state["resource_id"])
        return {"completed": True}

    def broken_principal(_context: object) -> Principal:
        raise RuntimeError("identity service unavailable")

    with pytest.raises(RuntimeError, match="identity service unavailable"):
        _graph(refund_node, _policy(), principal_resolver=broken_principal).invoke(
            _initial_state(),
            context=_context(),
        )

    def mutating_resource(state: object) -> str:
        assert isinstance(state, dict)
        state["resource_id"] = "order:other"
        return "order:42"

    with pytest.raises(ValueError, match="must not mutate"):
        _graph(refund_node, _policy(), resource_resolver=mutating_resource).invoke(
            _initial_state(),
            context=_context(),
        )
    assert side_effects == []


def test_audit_failure_stops_execution() -> None:
    side_effects: list[str] = []

    def refund_node(state: GraphState, runtime: Runtime[AuthContext]) -> dict[str, bool]:
        side_effects.append(state["resource_id"])
        return {"completed": True}

    def broken_audit(_request: object, _decision: object) -> None:
        raise RuntimeError("audit storage unavailable")

    with pytest.raises(RuntimeError, match="audit storage unavailable"):
        _graph(refund_node, _policy(), audit_callback=broken_audit).invoke(
            _initial_state(),
            context=_context(),
        )
    assert side_effects == []


def test_node_defaults_to_its_name_as_resource() -> None:
    side_effects: list[str] = []
    policy = PolicyEngine(
        [
            PolicyRule(
                rule_id="allow-node",
                effect=Effect.ALLOW,
                actions=frozenset({"refund"}),
                resources=frozenset({"refund_node"}),
                roles=frozenset({"operator"}),
            )
        ]
    )

    def refund_node(state: GraphState, runtime: Runtime[AuthContext]) -> dict[str, bool]:
        side_effects.append(state["resource_id"])
        return {"completed": True}

    result = _graph(refund_node, policy, resource_resolver=None).invoke(
        _initial_state(),
        context=_context(),
    )
    assert result["completed"] is True
    assert side_effects == ["order:42"]


def test_protected_node_requires_graph_state_and_runtime() -> None:
    def refund_node(state: GraphState, runtime: Runtime[AuthContext]) -> dict[str, bool]:
        return {"completed": True}

    protected = protect_node(refund_node, policy=_policy(), principal_resolver=_principal)
    with pytest.raises(TypeError, match="must receive graph state"):
        protected()
    with pytest.raises(RuntimeError, match="must declare and receive a Runtime"):
        protected(_initial_state())


@pytest.mark.parametrize(
    ("overrides", "error", "message"),
    [
        ({"policy": object()}, TypeError, "policy must be a PolicyEngine"),
        ({"principal_resolver": object()}, TypeError, "principal_resolver must be callable"),
        ({"resource_resolver": object()}, TypeError, "resource_resolver must be callable"),
        (
            {"resource_attributes_resolver": object()},
            TypeError,
            "resource_attributes_resolver must be callable",
        ),
        ({"context_resolver": object()}, TypeError, "context_resolver must be callable"),
        ({"audit_callback": object()}, TypeError, "audit_callback must be callable"),
        ({"audit_event_callback": object()}, TypeError, "audit_event_callback must be callable"),
        ({"action": ""}, ValueError, "action must be a non-empty"),
        ({"action": "*"}, ValueError, "action must be a non-empty"),
    ],
)
def test_invalid_configuration_is_rejected(
    overrides: dict[str, Any],
    error: type[Exception],
    message: str,
) -> None:
    def refund_node(state: GraphState, runtime: Runtime[AuthContext]) -> dict[str, bool]:
        return {"completed": True}

    options: dict[str, Any] = {"policy": _policy(), "principal_resolver": _principal}
    options.update(overrides)
    with pytest.raises(error, match=message):
        protect_node(refund_node, **options)


def test_non_callable_node_and_node_without_state_parameter_are_rejected() -> None:
    with pytest.raises(TypeError, match="node must be callable"):
        protect_node(None, policy=_policy(), principal_resolver=_principal)  # type: ignore[arg-type]

    def no_state() -> dict[str, bool]:
        return {"completed": True}

    with pytest.raises(TypeError, match="first positional parameter"):
        protect_node(no_state, policy=_policy(), principal_resolver=_principal)


@pytest.mark.parametrize(
    ("resource_attributes_resolver", "context_resolver", "message"),
    [
        (lambda _resource: None, None, "resource_attributes_resolver must return a mapping"),
        (None, lambda _context: None, "context_resolver must return a mapping"),
    ],
)
def test_non_mapping_resolver_results_are_rejected(
    resource_attributes_resolver: Any,
    context_resolver: Any,
    message: str,
) -> None:
    def refund_node(state: GraphState, runtime: Runtime[AuthContext]) -> dict[str, bool]:
        return {"completed": True}

    with pytest.raises(TypeError, match=message):
        _graph(
            refund_node,
            _policy(),
            resource_attributes_resolver=resource_attributes_resolver,
            context_resolver=context_resolver,
        ).invoke(_initial_state(), context=_context())


def test_non_principal_resolver_result_is_rejected_before_execution() -> None:
    side_effects: list[str] = []

    def refund_node(state: GraphState, runtime: Runtime[AuthContext]) -> dict[str, bool]:
        side_effects.append(state["resource_id"])
        return {"completed": True}

    with pytest.raises(TypeError, match="must return a Principal"):
        _graph(
            refund_node,
            _policy(),
            principal_resolver=lambda _context: "alice",
        ).invoke(_initial_state(), context=_context())
    assert side_effects == []

def test_untrusted_graph_state_cannot_escalate_principal_roles() -> None:
    side_effects: list[str] = []

    def refund_node(state: GraphState, runtime: Runtime[AuthContext]) -> dict[str, bool]:
        side_effects.append(state["resource_id"])
        return {"completed": True}

    spoofed_state = _initial_state()
    spoofed_state["claimed_roles"] = ["operator"]
    with pytest.raises(AuthorizationDenied) as raised:
        _graph(refund_node, _policy()).invoke(
            spoofed_state,
            context=_context(roles=["viewer"]),
        )

    assert raised.value.request.principal.roles == frozenset({"viewer"})
    assert side_effects == [], "model-controlled state must not grant an operator role"


def test_protected_node_preserves_command_routing_and_runtime_config() -> None:
    visited: list[str] = []

    def route_to_finish(
        state: GraphState,
        config: RunnableConfig,
        runtime: Runtime[AuthContext],
    ) -> Command:
        assert config.get("tags") == ["node-guard-test"]
        assert runtime.context["user_id"] == "alice"
        return Command(goto="finish", update={"completed": True})

    def finish_node(state: GraphState, runtime: Runtime[AuthContext]) -> dict[str, bool]:
        visited.append("finish")
        return {"completed": True}

    protected = protect_node(
        route_to_finish,
        policy=_policy(),
        principal_resolver=_principal,
        action="refund",
        resource_resolver=lambda state: state["resource_id"],
    )
    builder = StateGraph(GraphState, context_schema=AuthContext)
    builder.add_node("refund", protected)
    builder.add_node("finish", finish_node)
    builder.add_edge(START, "refund")
    builder.add_edge("refund", "finish")
    builder.add_edge("finish", END)
    graph = builder.compile()

    result = graph.invoke(
        _initial_state(),
        config={"configurable": {"thread_id": "command-preservation"}, "tags": ["node-guard-test"]},
        context=_context(),
    )

    assert result["completed"] is True
    assert visited == ["finish"]


def test_protected_node_preserves_interrupt_and_resume() -> None:
    resumed_values: list[str] = []

    def interruptible_node(
        state: GraphState, runtime: Runtime[AuthContext]
    ) -> dict[str, bool]:
        decision = interrupt({"operation": "refund", "resource": state["resource_id"]})
        resumed_values.append(str(decision))
        return {"completed": True}

    protected = protect_node(
        interruptible_node,
        policy=_policy(),
        principal_resolver=_principal,
        action="refund",
        resource_resolver=lambda state: state["resource_id"],
    )
    builder = StateGraph(GraphState, context_schema=AuthContext)
    builder.add_node("refund", protected)
    builder.add_edge(START, "refund")
    builder.add_edge("refund", END)
    graph = builder.compile(checkpointer=InMemorySaver())
    config = {"configurable": {"thread_id": "interrupt-preservation"}}

    paused = graph.invoke(_initial_state(), config=config, context=_context())
    assert paused["__interrupt__"][0].value == {
        "operation": "refund",
        "resource": "order:42",
    }
    assert resumed_values == []

    resumed = graph.invoke(Command(resume="approved-by-test"), config=config, context=_context())
    assert resumed["completed"] is True
    assert resumed_values == ["approved-by-test"]
