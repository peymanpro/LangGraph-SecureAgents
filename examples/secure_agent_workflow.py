"""Model-free end-to-end demo for guarded customer access and human-approved refunds.

Run with development dependencies:
    python examples/secure_agent_workflow.py

Pass --data-dir PATH to retain the SQLite databases after the demo. The default
uses a temporary directory so the repository stays clean.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from contextvars import ContextVar, Token
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Any, TypedDict

from langchain_core.messages import ToolMessage
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.runtime import Runtime
from langgraph.types import Command

from langgraph_secure_agents import (
    AttributeCondition,
    AttributeReference,
    ConditionOperator,
    Effect,
    PolicyEngine,
    PolicyRule,
    Principal,
    SQLiteApprovalStore,
    SQLiteAuditSink,
)
from langgraph_secure_agents.middleware import create_authorization_middleware

# Fake records only. The tenant metadata is resolved independently of tool arguments.
_CUSTOMERS: dict[str, dict[str, str]] = {
    "customer-101": {
        "tenant_id": "tenant-a",
        "summary": "Customer 101 profile: standard account",
    },
    "customer-202": {
        "tenant_id": "tenant-b",
        "summary": "Customer 202 profile: confidential account",
    },
}

# In a web service, this would be established by the authenticated resume endpoint.
# Never read reviewer identity from the approval payload or model-generated arguments.
_AUTHENTICATED_REVIEWER: ContextVar[str | None] = ContextVar(
    "secure_demo_authenticated_reviewer",
    default=None,
)


@dataclass(frozen=True, slots=True)
class DemoContext:
    """Trusted identity context created by the host application for each run."""

    principal_id: str
    roles: tuple[str, ...]
    tenant_id: str


class SecureDemoState(TypedDict):
    tool_name: str
    tool_args: dict[str, str]
    tool_call_id: str
    result: str


@dataclass(frozen=True, slots=True)
class DemoReport:
    own_tenant_result: str
    cross_tenant_result: str
    approved_refund_result: str
    replay_result: str
    executed_operations: tuple[str, ...]
    audit_reasons: tuple[str, ...]
    audit_integrity_valid: bool


@dataclass(slots=True)
class DemoEnvironment:
    graph: Any
    approval_store: SQLiteApprovalStore
    audit_sink: SQLiteAuditSink
    executed_operations: list[str]


def _resolve_principal(context: object) -> Principal:
    if not isinstance(context, DemoContext):
        raise TypeError("DemoContext must come from the trusted host application")
    return Principal(
        principal_id=context.principal_id,
        roles=frozenset(context.roles),
        attributes={"tenant_id": context.tenant_id},
    )


def _resolve_reviewer(_context: object) -> str:
    reviewer_id = _AUTHENTICATED_REVIEWER.get()
    if not reviewer_id:
        raise RuntimeError("the resume endpoint has not authenticated a reviewer")
    return reviewer_id


def build_secure_workflow(
    approval_database: str | Path,
    audit_database: str | Path,
) -> DemoEnvironment:
    """Build the secured workflow with real policy, middleware, and SQLite stores."""

    policy = PolicyEngine(
        [
            PolicyRule(
                rule_id="read-customers-in-own-tenant",
                effect=Effect.ALLOW,
                actions=frozenset({"read"}),
                resources=frozenset({"*"}),
                roles=frozenset({"analyst", "finance"}),
                conditions=(
                    AttributeCondition(
                        attribute="principal.attributes.tenant_id",
                        operator=ConditionOperator.EQ,
                        value=AttributeReference("resource.attributes.tenant_id"),
                    ),
                ),
            ),
            PolicyRule(
                rule_id="refunds-require-human-approval",
                effect=Effect.REQUIRE_APPROVAL,
                actions=frozenset({"execute"}),
                resources=frozenset({"issue_refund"}),
                roles=frozenset({"finance"}),
            ),
        ]
    )
    approval_store = SQLiteApprovalStore(approval_database)
    audit_sink = SQLiteAuditSink(audit_database)
    executed_operations: list[str] = []

    def resolve_resource(tool_name: str, args: Mapping[str, Any]) -> str:
        if tool_name == "read_customer":
            return f"customer:{args.get('customer_id', '')}"
        return tool_name

    def resolve_resource_attributes(resource: str) -> dict[str, str]:
        if not resource.startswith("customer:"):
            return {}
        customer_id = resource.removeprefix("customer:")
        record = _CUSTOMERS.get(customer_id)
        # Missing records have no tenant metadata and therefore cannot pass ABAC.
        return {} if record is None else {"tenant_id": record["tenant_id"]}

    authorization = create_authorization_middleware(
        policy,
        principal_resolver=_resolve_principal,
        action_resolver=lambda tool_name, _args: (
            "read" if tool_name == "read_customer" else "execute"
        ),
        resource_resolver=resolve_resource,
        resource_attributes_resolver=resolve_resource_attributes,
        audit_event_callback=audit_sink,
        approval_store=approval_store,
        approval_reviewer_resolver=_resolve_reviewer,
    )

    def execute_demo_tool(request: Any) -> ToolMessage:
        call = request.tool_call
        name = str(call["name"])
        args = call["args"]
        call_id = str(call["id"])

        if name == "read_customer":
            customer_id = str(args["customer_id"])
            record = _CUSTOMERS[customer_id]
            executed_operations.append(f"read_customer:{customer_id}")
            content = record["summary"]
        elif name == "issue_refund":
            invoice_id = str(args["invoice_id"])
            executed_operations.append(f"issue_refund:{invoice_id}")
            content = f"Refund issued for {invoice_id}."
        else:
            raise ValueError(f"Unknown demo tool: {name}")

        return ToolMessage(content=content, tool_call_id=call_id)

    def protected_tool_node(
        state: SecureDemoState,
        runtime: Runtime[DemoContext],
    ) -> dict[str, str]:
        request = SimpleNamespace(
            tool_call={
                "name": state["tool_name"],
                "args": state["tool_args"],
                "id": state["tool_call_id"],
            },
            runtime=runtime,
            state=state,
            tool=None,
        )
        response = authorization.wrap_tool_call(request, execute_demo_tool)
        if not isinstance(response, ToolMessage):
            raise TypeError("authorization middleware must return a ToolMessage")
        result = response.content if isinstance(response.content, str) else str(response.content)
        return {"result": result}

    builder = StateGraph(SecureDemoState, context_schema=DemoContext)
    builder.add_node("protected_tool", protected_tool_node)
    builder.add_edge(START, "protected_tool")
    builder.add_edge("protected_tool", END)
    graph = builder.compile(checkpointer=InMemorySaver())

    return DemoEnvironment(
        graph=graph,
        approval_store=approval_store,
        audit_sink=audit_sink,
        executed_operations=executed_operations,
    )


def _invoke_tool(
    environment: DemoEnvironment,
    *,
    thread_id: str,
    tool_name: str,
    tool_args: dict[str, str],
    tool_call_id: str,
    context: DemoContext,
) -> dict[str, Any]:
    return environment.graph.invoke(
        {
            "tool_name": tool_name,
            "tool_args": tool_args,
            "tool_call_id": tool_call_id,
            "result": "",
        },
        {"configurable": {"thread_id": thread_id}},
        context=context,
    )


def run_demo(data_dir: str | Path) -> DemoReport:
    """Run own-tenant, cross-tenant, approval, and replay scenarios."""

    data_path = Path(data_dir)
    data_path.mkdir(parents=True, exist_ok=True)
    environment = build_secure_workflow(
        data_path / "approvals.sqlite3",
        data_path / "authorization-audit.sqlite3",
    )
    # Keep the report scoped to this run even when the operator retains old records.
    starting_audit_sequence = environment.audit_sink.count

    analyst = DemoContext(principal_id="analyst-7", roles=("analyst",), tenant_id="tenant-a")
    finance = DemoContext(principal_id="finance-4", roles=("finance",), tenant_id="tenant-a")
    reviewer_id = "finance-reviewer-2"

    try:
        own_tenant = _invoke_tool(
            environment,
            thread_id="demo-own-tenant",
            tool_name="read_customer",
            tool_args={"customer_id": "customer-101"},
            tool_call_id="read-own-tenant",
            context=analyst,
        )
        cross_tenant = _invoke_tool(
            environment,
            thread_id="demo-cross-tenant",
            tool_name="read_customer",
            tool_args={"customer_id": "customer-202"},
            tool_call_id="read-cross-tenant",
            context=analyst,
        )

        refund_config = {"configurable": {"thread_id": "demo-refund-1"}}
        pending = _invoke_tool(
            environment,
            thread_id="demo-refund-1",
            tool_name="issue_refund",
            tool_args={"invoice_id": "invoice-9001"},
            tool_call_id="refund-call-1",
            context=finance,
        )
        if "__interrupt__" not in pending:
            raise AssertionError("the refund should pause for human approval")
        interrupt_payload = pending["__interrupt__"][0].value
        fingerprint = str(interrupt_payload["request_fingerprint"])

        # This is the trusted host-side approval step in the demo. A real service
        # must authenticate the reviewer and authorize this exact pending action first.
        token = environment.approval_store.issue(
            fingerprint,
            reviewer_id=reviewer_id,
            ttl=timedelta(minutes=3),
        )
        reviewer_context_token: Token[str | None] = _AUTHENTICATED_REVIEWER.set(reviewer_id)
        try:
            approved = environment.graph.invoke(
                Command(
                    resume={
                        "approved": True,
                        "request_fingerprint": fingerprint,
                        "approval_token": token,
                    }
                ),
                refund_config,
                context=finance,
            )
        finally:
            _AUTHENTICATED_REVIEWER.reset(reviewer_context_token)

        # Try to reuse the same approval for a separate paused execution. The new
        # checkpoint produces a different fingerprint, so the old grant cannot run it.
        replay_config = {"configurable": {"thread_id": "demo-refund-replay"}}
        replay_pending = _invoke_tool(
            environment,
            thread_id="demo-refund-replay",
            tool_name="issue_refund",
            tool_args={"invoice_id": "invoice-9001"},
            tool_call_id="refund-call-replay",
            context=finance,
        )
        if "__interrupt__" not in replay_pending:
            raise AssertionError("the separate refund should also require approval")

        replay_reviewer_token: Token[str | None] = _AUTHENTICATED_REVIEWER.set(reviewer_id)
        try:
            replay = environment.graph.invoke(
                Command(
                    resume={
                        "approved": True,
                        "request_fingerprint": fingerprint,
                        "approval_token": token,
                    }
                ),
                replay_config,
                context=finance,
            )
        finally:
            _AUTHENTICATED_REVIEWER.reset(replay_reviewer_token)

        records = environment.audit_sink.records(after_sequence=starting_audit_sequence, limit=100)
        audit_reasons = tuple(str(record.payload["decision_reason"]) for record in records)
        return DemoReport(
            own_tenant_result=str(own_tenant["result"]),
            cross_tenant_result=str(cross_tenant["result"]),
            approved_refund_result=str(approved["result"]),
            replay_result=str(replay["result"]),
            executed_operations=tuple(environment.executed_operations),
            audit_reasons=audit_reasons,
            audit_integrity_valid=environment.audit_sink.verify_integrity(),
        )
    finally:
        environment.approval_store.close()
        environment.audit_sink.close()


def _print_report(report: DemoReport) -> None:
    print(f"Own-tenant read: {report.own_tenant_result}")
    print(f"Cross-tenant read: {report.cross_tenant_result}")
    print(f"Human-approved refund: {report.approved_refund_result}")
    print(f"Replay attempt: {report.replay_result}")
    print(f"Executed operations: {list(report.executed_operations)}")
    print(f"Audit reasons: {list(report.audit_reasons)}")
    print(f"Audit hash chain valid: {report.audit_integrity_valid}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-dir",
        type=Path,
        help="directory for SQLite databases (omit to use and remove a temporary directory)",
    )
    args = parser.parse_args()

    if args.data_dir is not None:
        _print_report(run_demo(args.data_dir))
        return

    with TemporaryDirectory(prefix="langgraph-secure-agents-") as temporary_directory:
        _print_report(run_demo(temporary_directory))


if __name__ == "__main__":
    main()
