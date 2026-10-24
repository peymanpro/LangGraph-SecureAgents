# MCP tool authorization

LangGraph-SecureAgents provides an optional handler-level adapter for servers built with MCP Python SDK v2. It evaluates the existing policy engine immediately before a registered MCP tool handler runs and can emit the same structured audit events as the callable guard and LangChain middleware.

## Install

Python 3.11 or newer is required.

```bash
python -m pip install "langgraph-secure-agents[mcp]"
```

The adapter uses MCP Python SDK v2 and declares the optional dependency as `mcp>=2.0,<3.0`. The core package remains usable without installing MCP.

## Protect a tool handler

```python
from collections.abc import Mapping
from typing import Any

from mcp.server import MCPServer
from mcp.server.mcpserver import Context

from langgraph_secure_agents import PolicyEngine, Principal
from langgraph_secure_agents.mcp_adapter import protect_mcp_tool

server = MCPServer("Customer service")
policy = PolicyEngine(...)  # Load reviewed rules for this application.


def principal_from_trusted_auth(ctx: Context) -> Principal:
    # Integrate with the host's verified authentication state.
    # Do not trust model arguments or caller-controlled request headers as identity.
    return authenticated_principal_for(ctx)


def customer_resource(arguments: Mapping[str, Any]) -> str:
    return f"customer:{arguments['customer_id']}"


@server.tool()
@protect_mcp_tool(
    policy=policy,
    principal_resolver=principal_from_trusted_auth,
    action="read",
    resource_resolver=customer_resource,
    resource_attributes_resolver=load_trusted_customer_attributes,
)
def read_customer(customer_id: str, ctx: Context) -> str:
    # The resolver must target the same record that this function reads.
    return customer_store.read(customer_id)


if __name__ == "__main__":
    server.run()
```

Apply `protect_mcp_tool` inside the MCP server's `@server.tool()` decorator. The original signature is preserved so the SDK can inject its `Context` object. The Context parameter is handled by the SDK and should not be presented as a model-supplied input.

The adapter has no built-in identity provider. The `principal_resolver` must construct a `Principal` from trusted host authentication state, and `resource_attributes_resolver` must load metadata for the exact resource being accessed. MCP request headers are client-supplied and are not proof of identity. Keep downstream API and database authorization enabled.

## What is enforced

- Policy evaluation happens before the original handler executes.
- Default-deny, deny-overrides, RBAC/ABAC conditions, and `PolicyRegistry` snapshots use the existing policy engine.
- The resource resolver receives the tool's bound arguments (excluding the injected Context). The adapter calls it with detached inputs and rejects detected mutation.
- A configured audit callback receives a structured event with source `mcp_tool`, tool name, request ID where available, and policy metadata. If the callback raises, the handler does not execute.
- An authorization denial raises `AuthorizationDenied`; the MCP SDK represents a tool-body exception as an error result. The adapter does not return the protected result on a denial.

## Human approval

This adapter does not implement human approval interrupts by itself. If a policy returns `Effect.REQUIRE_APPROVAL`, the standalone MCP handler is denied and the original function is not called. For tools that should pause a LangGraph execution for reviewer approval, use the LangGraph middleware with a checkpointer and the configured approval-store or validator flow.

## Test the server example

The repository includes a model-free MCP server using fake customer records:

```bash
python -m pip install -e ".[mcp]"
python examples/mcp_secure_server.py
```

The example uses a fixed local identity to illustrate tenant-aware enforcement; it is not a multi-user authentication implementation. The automated integration test creates an in-memory MCP client/server pair and verifies that an own-tenant read succeeds while a cross-tenant attempt returns an error without invoking the handler.

For the MCP SDK's Context injection and tool signature behavior, see the [official Context guide](https://py.sdk.modelcontextprotocol.io/handlers/context/). The SDK currently marks its general-purpose server middleware surface as provisional; this adapter instead enforces authorization in the individual registered handler, rather than relying on that middleware hook ([official middleware note](https://py.sdk.modelcontextprotocol.io/advanced/middleware/)).
