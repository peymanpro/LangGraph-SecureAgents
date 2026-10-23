from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest

from langchain_core.messages import ToolMessage

from langgraph_secure_agents import Effect, PolicyEngine, PolicyRule, Principal
from langgraph_secure_agents import middleware as middleware_module
from langgraph_secure_agents.middleware import create_authorization_middleware


def request_for(
    *,
    resource: str = "read_payroll",
    args: dict[str, Any] | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        tool_call={"name": resource, "args": args or {}, "id": "async-call-1"},
        runtime=SimpleNamespace(
            context={"trusted_user": "alice"},
            execution_info=SimpleNamespace(
                thread_id="async-thread",
                checkpoint_id="async-checkpoint",
                checkpoint_ns="",
                task_id="async-task",
            ),
        ),
        state={},
        tool=None,
    )


def allow_policy() -> PolicyEngine:
    return PolicyEngine(
        [
            PolicyRule(
                rule_id="allow-analyst",
                effect=Effect.ALLOW,
                actions=frozenset({"execute"}),
                resources=frozenset({"read_payroll"}),
                roles=frozenset({"analyst"}),
            )
        ]
    )


def test_async_middleware_awaits_allowed_handler() -> None:
    handler_calls: list[str] = []
    middleware = create_authorization_middleware(
        allow_policy(),
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
    )

    async def handler(request: Any) -> ToolMessage:
        await asyncio.sleep(0)
        handler_calls.append(request.tool_call["id"])
        return ToolMessage(content="async result", tool_call_id=request.tool_call["id"])

    response = asyncio.run(middleware.awrap_tool_call(request_for(), handler))

    assert isinstance(response, ToolMessage)
    assert response.content == "async result"
    assert handler_calls == ["async-call-1"]


def test_async_middleware_denies_without_awaiting_handler() -> None:
    handler_calls: list[bool] = []
    middleware = create_authorization_middleware(
        PolicyEngine(),
        principal_resolver=lambda context: Principal("guest", roles=frozenset({"guest"})),
    )

    async def handler(request: Any) -> ToolMessage:
        handler_calls.append(True)
        return ToolMessage(content="sensitive result", tool_call_id=request.tool_call["id"])

    response = asyncio.run(middleware.awrap_tool_call(request_for(), handler))

    assert isinstance(response, ToolMessage)
    assert response.status == "error"
    assert response.content == "Authorization denied."
    assert handler_calls == []


def test_async_middleware_requires_matching_approval_before_awaiting_handler(
    monkeypatch: Any,
) -> None:
    handler_calls: list[str] = []

    def approve_interrupt(payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "approved": True,
            "request_fingerprint": payload["request_fingerprint"],
        }

    monkeypatch.setattr(middleware_module, "interrupt", approve_interrupt)
    policy = PolicyEngine(
        [
            PolicyRule(
                rule_id="approval-required-payroll",
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
    )

    async def handler(request: Any) -> ToolMessage:
        await asyncio.sleep(0)
        handler_calls.append(request.tool_call["id"])
        return ToolMessage(content="approved async result", tool_call_id=request.tool_call["id"])

    response = asyncio.run(middleware.awrap_tool_call(request_for(), handler))

    assert isinstance(response, ToolMessage)
    assert response.content == "approved async result"
    assert handler_calls == ["async-call-1"]



def test_async_middleware_propagates_handler_exception() -> None:
    handler_calls: list[bool] = []
    middleware = create_authorization_middleware(
        allow_policy(),
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
    )

    async def handler(request: Any) -> ToolMessage:
        handler_calls.append(True)
        raise RuntimeError("tool backend failed")

    with pytest.raises(RuntimeError, match="tool backend failed"):
        asyncio.run(middleware.awrap_tool_call(request_for(), handler))

    assert handler_calls == [True]


def test_async_middleware_propagates_handler_cancellation() -> None:
    handler_calls: list[bool] = []
    middleware = create_authorization_middleware(
        allow_policy(),
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
    )

    async def handler(request: Any) -> ToolMessage:
        handler_calls.append(True)
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(middleware.awrap_tool_call(request_for(), handler))

    assert handler_calls == [True]


def test_async_middleware_fails_closed_when_audit_callback_raises() -> None:
    handler_calls: list[bool] = []

    def fail_audit(request: Any, decision: Any) -> None:
        raise RuntimeError("audit storage unavailable")

    middleware = create_authorization_middleware(
        allow_policy(),
        principal_resolver=lambda context: Principal("alice", roles=frozenset({"analyst"})),
        audit_callback=fail_audit,
    )

    async def handler(request: Any) -> ToolMessage:
        handler_calls.append(True)
        return ToolMessage(content="sensitive result", tool_call_id=request.tool_call["id"])

    with pytest.raises(RuntimeError, match="audit storage unavailable"):
        asyncio.run(middleware.awrap_tool_call(request_for(), handler))

    assert handler_calls == []
