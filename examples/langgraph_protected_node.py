"""Model-free demonstration of authorization on a sensitive LangGraph node."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.runtime import Runtime

from langgraph_secure_agents import (
    AuthorizationDenied,
    Effect,
    PolicyEngine,
    PolicyRule,
    Principal,
)
from langgraph_secure_agents.langgraph import protect_node


class OrderState(TypedDict):
    order_id: str
    completed: bool


class RequestContext(TypedDict):
    user_id: str
    roles: list[str]


def resolve_principal(context: object) -> Principal:
    """Build a principal only from host-supplied runtime context."""
    if not isinstance(context, Mapping):
        raise TypeError("expected trusted runtime context")
    return Principal(str(context["user_id"]), roles=frozenset(context["roles"]))


refund_policy = PolicyEngine(
    [
        PolicyRule(
            rule_id="operators-refund-order-42",
            effect=Effect.ALLOW,
            roles=frozenset({"operator"}),
            actions=frozenset({"refund"}),
            resources=frozenset({"order:42"}),
        )
    ]
)
executed: list[str] = []


def issue_refund(state: OrderState, runtime: Runtime[RequestContext]) -> dict[str, bool]:
    """Stand-in for a real side-effecting refund service call."""
    executed.append(state["order_id"])
    print(f"Refund executed for {state['order_id']} on behalf of {runtime.context['user_id']}")
    return {"completed": True}


protected_refund = protect_node(
    issue_refund,
    policy=refund_policy,
    principal_resolver=resolve_principal,
    action="refund",
    resource_resolver=lambda state: f"order:{state['order_id']}",
)
builder = StateGraph(OrderState, context_schema=RequestContext)
builder.add_node("refund", protected_refund)
builder.add_edge(START, "refund")
builder.add_edge("refund", END)
graph = builder.compile()

initial_state: OrderState = {"order_id": "42", "completed": False}

print("1. Authorized request")
allowed = graph.invoke(
    initial_state,
    context={"user_id": "alice", "roles": ["operator"]},
)
assert allowed["completed"] is True
assert executed == ["42"]

print("2. Unauthorized request")
try:
    graph.invoke(
        initial_state,
        context={"user_id": "bob", "roles": ["viewer"]},
    )
except AuthorizationDenied as exc:
    print(f"Denied before the node ran: {exc.decision.reason.value}")
else:
    raise AssertionError("an unauthorized refund unexpectedly executed")

assert executed == ["42"], "the denied request must not trigger the side effect"
print("Security check passed: denied operation caused no side effect.")
