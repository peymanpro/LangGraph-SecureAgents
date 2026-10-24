"""MCP server example with handler-level authorization.

Install and run:
    python -m pip install -e ".[mcp]"
    python examples/mcp_secure_server.py

This demonstration intentionally uses one fixed, trusted local identity. A
multi-user deployment must integrate the principal resolver with its real
authentication layer; never derive identity from MCP tool arguments or headers.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from mcp.server import MCPServer
from mcp.server.mcpserver import Context

from langgraph_secure_agents import (
    AttributeCondition,
    AttributeReference,
    ConditionOperator,
    Effect,
    PolicyEngine,
    PolicyRule,
    Principal,
)
from langgraph_secure_agents.mcp_adapter import protect_mcp_tool

CUSTOMERS = {
    "customer-101": {"tenant_id": "tenant-a", "summary": "Customer 101: standard account"},
    "customer-202": {"tenant_id": "tenant-b", "summary": "Customer 202: confidential account"},
}

policy = PolicyEngine(
    [
        PolicyRule(
            rule_id="read-customer-in-own-tenant",
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

server = MCPServer("LangGraph-SecureAgents demo")


def trusted_demo_principal(_ctx: Context) -> Principal:
    """Represent a single local identity; replace this with host authentication."""

    return Principal(
        "local-analyst",
        roles=frozenset({"analyst"}),
        attributes={"tenant_id": "tenant-a"},
    )


def resolve_customer_resource(arguments: Mapping[str, Any]) -> str:
    return f"customer:{arguments['customer_id']}"


def resolve_customer_attributes(resource: str) -> Mapping[str, str]:
    customer_id = resource.removeprefix("customer:")
    customer = CUSTOMERS.get(customer_id)
    return {} if customer is None else {"tenant_id": customer["tenant_id"]}


@server.tool()
@protect_mcp_tool(
    policy=policy,
    principal_resolver=trusted_demo_principal,
    action="read",
    resource_resolver=resolve_customer_resource,
    resource_attributes_resolver=resolve_customer_attributes,
)
def read_customer(customer_id: str, ctx: Context) -> str:
    """Read a customer record only if it belongs to the caller's tenant."""

    return CUSTOMERS[customer_id]["summary"]


if __name__ == "__main__":
    server.run()
