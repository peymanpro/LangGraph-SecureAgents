from __future__ import annotations

from collections.abc import Mapping
from types import SimpleNamespace
from typing import cast

import pytest
from mcp import Client
from mcp.server import MCPServer
from mcp.server.mcpserver import Context

from langgraph_secure_agents import (
    AttributeCondition,
    AttributeReference,
    AuditEvent,
    AuthorizationDenied,
    ConditionOperator,
    Effect,
    PolicyEngine,
    PolicyRule,
    Principal,
)
from langgraph_secure_agents.mcp_adapter import protect_mcp_tool

_CUSTOMERS = {
    "customer-101": {"tenant_id": "tenant-a", "summary": "Customer 101"},
    "customer-202": {"tenant_id": "tenant-b", "summary": "Customer 202"},
}

_MISSING_CONTEXT = cast(Context, None)


def _policy() -> PolicyEngine:
    return PolicyEngine(
        [
            PolicyRule(
                rule_id="read-own-tenant",
                effect=Effect.ALLOW,
                actions=frozenset({"read"}),
                resources=frozenset({"*"}),
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


def _resource_attributes(resource: str) -> Mapping[str, str]:
    customer_id = resource.removeprefix("customer:")
    customer = _CUSTOMERS.get(customer_id)
    return {} if customer is None else {"tenant_id": customer["tenant_id"]}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_mcp_server_enforces_tenant_policy_before_tool_handler() -> None:
    server = MCPServer("SecureCustomerTest")
    handler_calls: list[str] = []
    events: list[AuditEvent] = []
    policy = _policy()

    @server.tool()
    @protect_mcp_tool(
        policy=policy,
        principal_resolver=lambda _ctx: Principal(
            "analyst-7",
            roles=frozenset({"analyst"}),
            attributes={"tenant_id": "tenant-a"},
        ),
        action="read",
        resource_resolver=lambda args: f"customer:{args['customer_id']}",
        resource_attributes_resolver=_resource_attributes,
        audit_event_callback=events.append,
        policy_id="customer-access",
        policy_version="1.0.0",
    )
    def read_customer(customer_id: str, ctx: Context) -> str:
        """Read a customer record after authorization."""

        handler_calls.append(customer_id)
        return _CUSTOMERS[customer_id]["summary"]

    async with Client(server) as client:
        tools = await client.list_tools()
        tool = next(item for item in tools.tools if item.name == "read_customer")
        assert "ctx" not in tool.input_schema.get("properties", {})

        same_tenant = await client.call_tool("read_customer", {"customer_id": "customer-101"})
        cross_tenant = await client.call_tool("read_customer", {"customer_id": "customer-202"})

    assert same_tenant.is_error is not True
    assert same_tenant.content[0].text == "Customer 101"
    assert cross_tenant.is_error is True
    assert handler_calls == ["customer-101"]
    assert [event.decision_reason.value for event in events] == ["explicit_allow", "default_deny"]
    assert all(event.source == "mcp_tool" for event in events)
    assert events[0].request_id
    assert events[0].tool_name == "read_customer"
    assert events[0].policy_id == "customer-access"
    assert events[0].policy_version == "1.0.0"


def test_missing_or_untrusted_resource_metadata_fails_closed() -> None:
    handler_calls: list[str] = []
    tool_context = cast(Context, SimpleNamespace(request_id="test-request"))

    @protect_mcp_tool(
        policy=_policy(),
        principal_resolver=lambda _ctx: Principal(
            "analyst-7",
            roles=frozenset({"analyst"}),
            attributes={"tenant_id": "tenant-a"},
        ),
        action="read",
        resource_resolver=lambda args: f"customer:{args['customer_id']}",
        resource_attributes_resolver=lambda _resource: {},
    )
    def read_customer(customer_id: str, ctx: Context) -> str:
        handler_calls.append(customer_id)
        return "sensitive data"

    with pytest.raises(AuthorizationDenied):
        read_customer("customer-101", tool_context)

    assert handler_calls == []


def test_audit_failure_prevents_mcp_tool_execution() -> None:
    handler_calls: list[str] = []
    tool_context = cast(Context, SimpleNamespace(request_id="audit-failure"))
    principal = Principal("analyst-7", roles=frozenset({"analyst"}))

    def broken_audit(_event: AuditEvent) -> None:
        raise RuntimeError("audit sink unavailable")

    @protect_mcp_tool(
        policy=PolicyEngine(
            [
                PolicyRule(
                    rule_id="allow-read",
                    effect=Effect.ALLOW,
                    actions=frozenset({"read"}),
                    resources=frozenset({"*"}),
                    roles=frozenset({"analyst"}),
                )
            ]
        ),
        principal_resolver=lambda _ctx: principal,
        action="read",
        audit_event_callback=broken_audit,
    )
    def read_report(report_id: str, ctx: Context) -> str:
        handler_calls.append(report_id)
        return "report"

    with pytest.raises(RuntimeError, match="audit sink unavailable"):
        read_report("report-42", tool_context)

    assert handler_calls == []


def test_async_mcp_handler_is_authorized_when_awaited() -> None:
    import asyncio

    handler_calls: list[str] = []
    tool_context = cast(Context, SimpleNamespace(request_id="async-mcp"))
    policy = PolicyEngine(
        [
            PolicyRule(
                rule_id="allow-report-read",
                effect=Effect.ALLOW,
                actions=frozenset({"read"}),
                resources=frozenset({"report:42"}),
            )
        ]
    )

    @protect_mcp_tool(
        policy=policy,
        principal_resolver=lambda _ctx: Principal("service-account"),
        action="read",
        resource_resolver=lambda args: f"report:{args['report_id']}",
    )
    async def read_report(report_id: str, ctx: Context) -> str:
        handler_calls.append(report_id)
        return "report contents"

    assert asyncio.run(read_report("42", tool_context)) == "report contents"
    assert handler_calls == ["42"]


def test_adapter_rejects_handlers_without_exactly_one_required_context() -> None:
    protector = protect_mcp_tool(
        policy=PolicyEngine(),
        principal_resolver=lambda _ctx: Principal("service-account"),
    )

    with pytest.raises(TypeError, match="exactly one parameter annotated as Context"):

        @protector
        def missing_context(customer_id: str) -> str:
            return customer_id

    with pytest.raises(TypeError, match="Context parameter must be required"):

        @protector
        def optional_context(customer_id: str, ctx: Context = _MISSING_CONTEXT) -> str:
            return customer_id
