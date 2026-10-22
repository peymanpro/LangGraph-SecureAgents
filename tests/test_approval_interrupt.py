from __future__ import annotations

from typing import TypedDict

from langchain_core.messages import ToolMessage
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.runtime import Runtime
from langgraph.types import Command

from langgraph_secure_agents import Effect, PolicyEngine, PolicyRule, Principal
from langgraph_secure_agents.middleware import create_authorization_middleware


class ApprovalState(TypedDict):
    result: str | None


class ApprovalContext(TypedDict):
    principal_id: str
    roles: list[str]


def test_graph_interrupts_before_tool_and_resumes_after_bound_approval() -> None:
    handler_calls: list[bool] = []
    policy = PolicyEngine(
        [
            PolicyRule(
                rule_id="approve-payroll-read",
                effect=Effect.REQUIRE_APPROVAL,
                actions=frozenset({"read"}),
                resources=frozenset({"payroll:employee-7"}),
                roles=frozenset({"hr"}),
            )
        ]
    )
    middleware = create_authorization_middleware(
        policy,
        principal_resolver=lambda context: Principal(
            context["principal_id"],  # type: ignore[index]
            roles=frozenset(context["roles"]),  # type: ignore[index]
        ),
        action_resolver=lambda tool_name, args: "read",
        resource_resolver=lambda tool_name, args: f"payroll:{args['employee_id']}",
    )

    def read_payroll_node(
        state: ApprovalState,
        runtime: Runtime[ApprovalContext],
    ) -> dict[str, str | None]:
        request = type(
            "ToolRequest",
            (),
            {
                "tool_call": {
                    "name": "read_payroll",
                    "args": {"employee_id": "employee-7"},
                    "id": "call-approval-integration",
                },
                "runtime": runtime,
                "state": {},
                "tool": None,
            },
        )()

        def handler(tool_request: object) -> ToolMessage:
            handler_calls.append(True)
            return ToolMessage(
                content="Sensitive payroll read executed.",
                tool_call_id="call-approval-integration",
            )

        response = middleware.wrap_tool_call(request, handler)
        return {"result": response.content}

    builder = StateGraph(ApprovalState, context_schema=ApprovalContext)
    builder.add_node("read_payroll", read_payroll_node)
    builder.add_edge(START, "read_payroll")
    builder.add_edge("read_payroll", END)
    graph = builder.compile(checkpointer=InMemorySaver())

    config = {"configurable": {"thread_id": "approval-integration-test"}}
    context: ApprovalContext = {"principal_id": "alice", "roles": ["hr"]}

    paused = graph.invoke({"result": None}, config=config, context=context)

    assert handler_calls == []
    interrupts = paused.get("__interrupt__", [])
    assert len(interrupts) == 1
    payload = interrupts[0].value
    assert payload["type"] == "authorization_approval"
    assert payload["resource"] == "payroll:employee-7"

    resumed = graph.invoke(
        Command(
            resume={
                "approved": True,
                "request_fingerprint": payload["request_fingerprint"],
            }
        ),
        config=config,
        context=context,
    )

    assert resumed["result"] == "Sensitive payroll read executed."
    assert handler_calls == [True]
