# LangGraph node authorization

`protect_node` adds an explicit authorization boundary around a sensitive LangGraph node. It complements the existing `protect_callable` guard and the LangChain agent middleware; it does not secure every node or every path through a graph automatically.

## Install

The core policy engine does not require LangGraph. Install the optional integration extra:

```bash
python -m pip install "langgraph-secure-agents[langgraph]"
```

## Protect a node

```python
from collections.abc import Mapping
from typing import TypedDict

from langgraph.runtime import Runtime
from langgraph_secure_agents import PolicyEngine, Principal
from langgraph_secure_agents.langgraph import protect_node

class RequestContext(TypedDict):
    user_id: str
    roles: list[str]

def resolve_principal(context: object) -> Principal:
    # The host must populate this context from authenticated server-side data.
    if not isinstance(context, Mapping):
        raise TypeError("expected trusted runtime context")
    return Principal(str(context["user_id"]), roles=frozenset(context["roles"]))

def refund_node(state: dict[str, str], runtime: Runtime[RequestContext]) -> dict[str, bool]:
    # Call the actual domain operation here.
    return {"completed": True}

protected_node = protect_node(
    refund_node,
    policy=policy,
    principal_resolver=resolve_principal,
    action="refund",
    resource_resolver=lambda state: f"order:{state['order_id']}",
)
builder.add_node("refund", protected_node)
```

The wrapped node must declare a LangGraph `Runtime` parameter (normally `runtime: Runtime[Context]`) so the guard can read `runtime.context`. Pass trusted, request-scoped context to `graph.invoke(..., context=...)`. The first node parameter is treated as graph state. `resource_resolver` must identify the exact resource that the node will actually affect; if omitted, the node's function name is used as the resource identifier.

`protect_node` checks authorization immediately before calling the original node. It preserves the original function signature and accepts synchronous or asynchronous nodes. On a deny, a resolver error, a malformed resolver result, or an audit callback failure, the original node body is not called. The guard uses the same `PolicyEngine` or `PolicyRegistry`, request model, audit callbacks, and `AuthorizationDenied` exception as the callable guard.

## Run the model-free example

From the repository root, install the project with the development extras, then run:

```bash
python -m pip install -e ".[dev]"
python examples/langgraph_protected_node.py
```

The example builds a small graph and compares an authorized operator with a viewer. It does not need an LLM API key or an external service. Its side-effect list demonstrates that a denied request does not execute the protected node.

## Human approval

A node policy with `Effect.REQUIRE_APPROVAL` is not treated as an allow decision: `protect_node` raises `AuthorizationDenied` before the node executes. It does not create an interrupt or approve the operation itself. For the checkpointed human-approval flow currently implemented in this project, use `create_authorization_middleware` for protected agent tool calls and configure a trusted reviewer flow plus the one-time approval store or an equivalent validator. See the [approval store guide](approval-store.md).

## Security responsibilities and limits

- **The host authenticates.** `protect_node` does not authenticate a user. The host must construct context from authenticated, validated server-side identity data; arbitrary client-provided `context` is not trustworthy merely because LangGraph calls it runtime context.
- **Protect every sensitive path.** Only nodes explicitly wrapped with `protect_node` are covered by this boundary. An unwrapped node, direct callable invocation, separate tool entry point, or downstream service path can bypass it.
- **Do not trust model-controlled state.** Graph state can include values generated or influenced by an LLM. Use a resource resolver and verify the real resource and tenant against trusted server-side data before side effects.
- **Do not replace downstream authorization.** APIs, databases, and services must enforce their own permissions and tenant checks.
- **Resolvers must be trusted and side-effect-free.** Resolver inputs are detached and checked for mutation. They must be safely copyable; resolver exceptions or unsafe inputs fail closed.
- **Audit is synchronous.** When configured, an audit callback runs before the protected node. If it fails, node execution is stopped. Configure durable sinks and retention according to the host's needs.
- **Human approval is a separate workflow.** This node guard does not itself implement interrupt/resume or consume approval tokens. Do not interpret an `approved` value from graph state or model output as proof of human approval.
- **Interrupts and graph commands.** The wrapper returns the original node's result unchanged when access is allowed; it does not transform return values. Keep node-specific routing, `Command`, and interrupt behavior in the node itself and verify those flows with integration tests for the LangGraph version you deploy.

See also the [threat model](threat-model.md), [audit guide](audit-events.md), and [project README](../README.md).
