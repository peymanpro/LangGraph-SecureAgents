from __future__ import annotations

from types import SimpleNamespace
from typing import Any, TypedDict

import pytest
from langchain_core.messages import ToolMessage
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.runtime import Runtime
from langgraph.types import Command

from langgraph_secure_agents import Effect, PolicyEngine, PolicyRule, Principal
from langgraph_secure_agents.middleware import create_authorization_middleware


class ApprovalGraphState(TypedDict):
    result: str


@pytest.mark.parametrize(
    ("approved", "expected_result", "expected_audit_reason"),
    [
        (True, "Payroll record returned", "human_approved"),
        (False, "Human approval denied.", "approval_denied"),
    ],
)
def test_checkpointed_graph_pauses_before_tool_and_resumes_with_bound_approval(
    approved: bool,
    expected_result: str,
    expected_audit_reason: str,
) -> None:
    handler_calls: list[str] = []
    audit_reasons: list[str] = []
    execution_observations: list[tuple[str | None, ...]] = []
    call_id = "approval-integration-call"

    policy = PolicyEngine(
        [
            PolicyRule(
                rule_id="approval-required-payroll-read",
                effect=Effect.REQUIRE_APPROVAL,
                actions=frozenset({"execute"}),
                resources=frozenset({"read_payroll"}),
                roles=frozenset({"analyst"}),
            )
        ]
    )
    middleware = create_authorization_middleware(
        policy,
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
        audit_callback=lambda request, decision: audit_reasons.append(decision.reason),
    )

    def protected_handler(request: Any) -> ToolMessage:
        handler_calls.append(call_id)
        return ToolMessage(content="Payroll record returned", tool_call_id=call_id)

    def protected_tool_node(
        state: ApprovalGraphState,
        runtime: Runtime,
    ) -> dict[str, str]:
        info = getattr(runtime, "execution_info", None)
        execution_observations.append(
            (
                getattr(info, "thread_id", None),
                getattr(info, "checkpoint_id", None),
                getattr(info, "checkpoint_ns", None),
                getattr(info, "task_id", None),
                getattr(info, "run_id", None),
            )
        )
        request = SimpleNamespace(
            tool_call={
                "name": "read_payroll",
                "args": {"employee_id": "employee-7"},
                "id": call_id,
            },
            runtime=runtime,
            state={},
            tool=None,
        )
        response = middleware.wrap_tool_call(request, protected_handler)
        assert isinstance(response, ToolMessage)
        return {"result": response.content}

    builder = StateGraph(ApprovalGraphState)
    builder.add_node("protected_tool", protected_tool_node)
    builder.add_edge(START, "protected_tool")
    builder.add_edge("protected_tool", END)
    graph = builder.compile(checkpointer=InMemorySaver())
    config = {
        "configurable": {
            "thread_id": f"approval-integration-{approved}",
        }
    }

    initial = graph.invoke({"result": ""}, config)

    assert "__interrupt__" in initial
    interrupts = initial["__interrupt__"]
    assert len(interrupts) == 1
    payload = interrupts[0].value
    assert payload["type"] == "authorization_approval"
    assert payload["tool_call_id"] == call_id
    assert payload["principal_id"] == "alice"
    assert handler_calls == []
    assert audit_reasons == []

    resumed = graph.invoke(
        Command(
            resume={
                "approved": approved,
                "request_fingerprint": payload["request_fingerprint"],
            }
        ),
        config,
    )

    assert resumed["result"] == expected_result
    assert audit_reasons == [expected_audit_reason]
    assert handler_calls == ([call_id] if approved else [])
    assert len(execution_observations) == 2
    first_execution, resumed_execution = execution_observations
    assert first_execution[0] is not None
    assert first_execution[0] == resumed_execution[0]  # thread_id
    assert first_execution[1] == resumed_execution[1]  # checkpoint_id
    assert first_execution[2] == resumed_execution[2]  # checkpoint namespace
    assert first_execution[3] == resumed_execution[3]  # task ID

def test_checkpointed_graph_rejects_approval_when_host_validator_denies(
) -> None:
    handler_calls: list[str] = []
    validator_calls: list[tuple[str, str, str]] = []
    call_id = "host-validator-rejection-call"

    policy = PolicyEngine(
        [
            PolicyRule(
                rule_id="approval-required-payroll-read",
                effect=Effect.REQUIRE_APPROVAL,
                actions=frozenset({"execute"}),
                resources=frozenset({"read_payroll"}),
                roles=frozenset({"analyst"}),
            )
        ]
    )

    def reject_untrusted_reviewer(
        approval: Any,
        access_request: Any,
        fingerprint: str,
    ) -> bool:
        validator_calls.append(
            (
                str(approval.get("reviewer_id")),
                access_request.principal.principal_id,
                fingerprint,
            )
        )
        return False

    middleware = create_authorization_middleware(
        policy,
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
        approval_validator=reject_untrusted_reviewer,
    )

    def protected_handler(request: Any) -> ToolMessage:
        handler_calls.append(call_id)
        return ToolMessage(content="sensitive operation executed", tool_call_id=call_id)

    def protected_tool_node(
        state: ApprovalGraphState,
        runtime: Runtime,
    ) -> dict[str, str]:
        request = SimpleNamespace(
            tool_call={
                "name": "read_payroll",
                "args": {"employee_id": "employee-7"},
                "id": call_id,
            },
            runtime=runtime,
            state={},
            tool=None,
        )
        response = middleware.wrap_tool_call(request, protected_handler)
        assert isinstance(response, ToolMessage)
        return {"result": response.content}

    builder = StateGraph(ApprovalGraphState)
    builder.add_node("protected_tool", protected_tool_node)
    builder.add_edge(START, "protected_tool")
    builder.add_edge("protected_tool", END)
    graph = builder.compile(checkpointer=InMemorySaver())
    config = {"configurable": {"thread_id": "host-validator-rejection"}}

    paused = graph.invoke({"result": ""}, config)
    assert "__interrupt__" in paused
    assert handler_calls == []
    payload = paused["__interrupt__"][0].value

    resumed = graph.invoke(
        Command(
            resume={
                "approved": True,
                "request_fingerprint": payload["request_fingerprint"],
                "reviewer_id": "untrusted-reviewer",
            }
        ),
        config,
    )

    assert resumed["result"] == "Approval response invalid; tool was not executed."
    assert validator_calls == [
        ("untrusted-reviewer", "alice", payload["request_fingerprint"])
    ]
    assert handler_calls == []

