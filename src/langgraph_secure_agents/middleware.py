"""Optional middleware that enforces policies before agent tools execute."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from langchain.agents.middleware import wrap_tool_call
from langchain_core.messages import ToolMessage

from .models import AccessRequest, Decision, Principal
from .policy import PolicyEngine

PrincipalResolver = Callable[[object], Principal]
ActionResolver = Callable[[str, Mapping[str, Any]], str]
ResourceResolver = Callable[[str, Mapping[str, Any]], str]
AuditCallback = Callable[[AccessRequest, Decision], None]


def create_authorization_middleware(
    policy: PolicyEngine,
    principal_resolver: PrincipalResolver,
    *,
    action_resolver: ActionResolver | None = None,
    resource_resolver: ResourceResolver | None = None,
    audit_callback: AuditCallback | None = None,
) -> Any:
    """Create middleware that authorizes every tool call before execution.

    The principal resolver receives the agent runtime's context. It must derive
    identity from trusted application data, never from tool arguments or LLM
    output. By default, the requested action is execute and the resource is
    the tool name. Custom resolvers can map tool calls to domain actions and
    resources. A denied call returns an error ToolMessage without invoking the
    tool handler.

    If configured auditing raises, the tool handler is not invoked (fail closed).
    """

    if not isinstance(policy, PolicyEngine):
        raise TypeError("policy must be a PolicyEngine instance")
    if not callable(principal_resolver):
        raise TypeError("principal_resolver must be callable")
    if action_resolver is not None and not callable(action_resolver):
        raise TypeError("action_resolver must be callable")
    if resource_resolver is not None and not callable(resource_resolver):
        raise TypeError("resource_resolver must be callable")
    if audit_callback is not None and not callable(audit_callback):
        raise TypeError("audit_callback must be callable")

    def default_action_resolver(
        tool_name: str,
        tool_args: Mapping[str, Any],
    ) -> str:
        return "execute"

    def default_resource_resolver(
        tool_name: str,
        tool_args: Mapping[str, Any],
    ) -> str:
        return tool_name

    resolve_action = action_resolver or default_action_resolver
    resolve_resource = resource_resolver or default_resource_resolver

    @wrap_tool_call(name="secure_agent_authorization")
    def enforce_authorization(request: Any, handler: Callable[[Any], Any]) -> Any:
        tool_call = getattr(request, "tool_call", None)
        if not isinstance(tool_call, Mapping):
            raise TypeError("middleware request must contain a tool_call mapping")

        tool_name = tool_call.get("name")
        tool_args = tool_call.get("args", {})
        tool_call_id = tool_call.get("id")

        if not isinstance(tool_name, str) or not tool_name.strip():
            raise ValueError("tool call must include a non-empty name")
        if not isinstance(tool_args, Mapping):
            raise TypeError("tool call args must be a mapping")

        runtime = getattr(request, "runtime", None)
        runtime_context = getattr(runtime, "context", None)
        principal = principal_resolver(runtime_context)
        if not isinstance(principal, Principal):
            raise TypeError("principal_resolver must return a Principal instance")

        access_request = AccessRequest(
            principal=principal,
            action=resolve_action(tool_name, tool_args),
            resource=resolve_resource(tool_name, tool_args),
        )
        decision = policy.evaluate(access_request)

        if audit_callback is not None:
            audit_callback(access_request, decision)

        if not decision.allowed:
            if not isinstance(tool_call_id, str) or not tool_call_id:
                raise ValueError("denied tool calls must include a tool-call id")
            return ToolMessage(
                content="Authorization denied.",
                tool_call_id=tool_call_id,
                status="error",
            )

        return handler(request)

    return enforce_authorization
