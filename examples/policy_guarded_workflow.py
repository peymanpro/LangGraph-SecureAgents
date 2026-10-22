"""Runnable, model-free LangGraph example for guarded business tools.

Run after installing development dependencies:
    python examples/policy_guarded_workflow.py

The runtime context in this example represents data supplied by a trusted
authentication layer. Never accept principal IDs or roles directly from the
user's natural-language request or LLM-generated tool arguments.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.runtime import Runtime

from langgraph_secure_agents import (
    AuthorizationDenied,
    Effect,
    PolicyEngine,
    PolicyRule,
    Principal,
    protect_callable,
)

# Fake data only; no external service or credential is used.
_PAYROLL: dict[str, str] = {
    "employee-7": "Employee 7: salary band P4",
    "employee-8": "Employee 8: salary band P2",
}


@dataclass(frozen=True, slots=True)
class PayrollContext:
    """Trusted, per-run identity context provided by the host application."""

    principal_id: str
    roles: tuple[str, ...]


class PayrollState(TypedDict):
    employee_id: str
    report: str | None
    error: str | None


def _read_payroll(employee_id: str) -> str:
    """Read a mock payroll record; this is the protected operation."""

    return _PAYROLL[employee_id]


def build_payroll_workflow():
    """Build a workflow whose payroll node guards access before reading data."""

    policy = PolicyEngine(
        [
            PolicyRule(
                rule_id="hr-read-employee-7",
                effect=Effect.ALLOW,
                actions=frozenset({"read"}),
                resources=frozenset({"payroll:employee-7"}),
                roles=frozenset({"hr"}),
            )
        ]
    )

    def read_payroll_node(
        state: PayrollState,
        runtime: Runtime[PayrollContext],
    ) -> dict[str, str | None]:
        # The context is passed separately from the ordinary graph state.
        # The caller must build it from verified server-side authentication.
        principal = Principal(
            principal_id=runtime.context.principal_id,
            roles=frozenset(runtime.context.roles),
        )
        secured_read = protect_callable(
            _read_payroll,
            policy=policy,
            principal_resolver=lambda: principal,
            action="read",
            resource_resolver=lambda employee_id: f"payroll:{employee_id}",
        )

        try:
            report = secured_read(state["employee_id"])
        except AuthorizationDenied as exc:
            return {"report": None, "error": str(exc)}

        return {"report": report, "error": None}

    builder = StateGraph(PayrollState, context_schema=PayrollContext)
    builder.add_node("read_payroll", read_payroll_node)
    builder.add_edge(START, "read_payroll")
    builder.add_edge("read_payroll", END)
    return builder.compile()


def run_request(
    graph: Any,
    *,
    employee_id: str,
    context: PayrollContext,
) -> PayrollState:
    """Run the graph with explicit trusted context and a requested resource."""

    # Keep the request boundary visible in one place.
    return graph.invoke(
        {"employee_id": employee_id, "report": None, "error": None},
        context=context,
    )


def main() -> None:
    graph = build_payroll_workflow()

    cases = [
        (
            "HR reads an explicitly allowed record",
            "employee-7",
            PayrollContext(principal_id="alice", roles=("hr",)),
        ),
        (
            "HR requests a different record",
            "employee-8",
            PayrollContext(principal_id="alice", roles=("hr",)),
        ),
        (
            "A guest requests an allowed record",
            "employee-7",
            PayrollContext(principal_id="mallory", roles=("guest",)),
        ),
    ]

    for description, employee_id, context in cases:
        result = run_request(graph, employee_id=employee_id, context=context)
        print(f"\n{description}")
        if result["report"] is not None:
            print(f"ALLOW: {result['report']}")
        else:
            print(f"DENY: {result['error']}")


if __name__ == "__main__":
    main()
