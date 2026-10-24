"""Optional authorization decorator for MCP Python SDK v2 tool handlers.

Import this module only when the optional mcp extra is installed.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from functools import wraps
from inspect import Parameter, isasyncgenfunction, iscoroutinefunction, signature
from time import perf_counter
from typing import Any, cast, get_type_hints

from mcp.server.mcpserver import Context

from ._resolver_safety import call_resolver_without_mutation
from .audit import AuditEvent, AuditEventCallback
from .guard import AuditCallback, AuthorizationDenied
from .models import AccessRequest, JSONValue, Principal
from .policy import PolicyEngine
from .policy_registry import PolicyRegistry

PrincipalResolver = Callable[[Context], Principal]
ResourceResolver = Callable[[Mapping[str, Any]], str]
ResourceAttributesResolver = Callable[[str], Mapping[str, JSONValue]]
ContextResolver = Callable[[Context], Mapping[str, JSONValue]]


def _is_context_annotation(annotation: Any) -> bool:
    """Recognize only the actual MCP SDK Context class."""

    return annotation is Context


def protect_mcp_tool(
    *,
    policy: PolicyEngine | PolicyRegistry,
    principal_resolver: PrincipalResolver,
    action: str = "execute",
    tool_name: str | None = None,
    resource_resolver: ResourceResolver | None = None,
    resource_attributes_resolver: ResourceAttributesResolver | None = None,
    context_resolver: ContextResolver | None = None,
    audit_callback: AuditCallback | None = None,
    audit_event_callback: AuditEventCallback | None = None,
    policy_id: str | None = None,
    policy_version: str | None = None,
    policy_digest: str | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorate an MCP SDK v2 handler with authorization enforcement.

    Apply this decorator inside the MCP server's tool decorator, so the SDK sees
    the original function signature and its injected Context parameter.

    The principal resolver must derive identity from trusted authentication state
    available to the host application. MCP Context headers are caller-controlled
    and must not be treated as proof of identity. Resource attributes must
    describe the exact resource the handler will access.

    A denial, including a REQUIRE_APPROVAL policy result, raises
    AuthorizationDenied before the handler executes. This adapter does not
    implement human-approval interrupts; use the LangGraph middleware and its
    checkpointed approval flow when a tool needs that interaction. If a
    configured audit callback raises, the handler is not executed.

    The Context parameter must be annotated with its real SDK Context type. It is
    hidden from the tool's JSON input schema by the SDK and is never taken from
    model-supplied arguments.
    """

    if not isinstance(policy, (PolicyEngine, PolicyRegistry)):
        raise TypeError("policy must be a PolicyEngine instance or a PolicyRegistry instance")
    if not callable(principal_resolver):
        raise TypeError("principal_resolver must be callable")
    if resource_resolver is not None and not callable(resource_resolver):
        raise TypeError("resource_resolver must be callable")
    if resource_attributes_resolver is not None and not callable(resource_attributes_resolver):
        raise TypeError("resource_attributes_resolver must be callable")
    if context_resolver is not None and not callable(context_resolver):
        raise TypeError("context_resolver must be callable")
    if audit_callback is not None and not callable(audit_callback):
        raise TypeError("audit_callback must be callable")
    if audit_event_callback is not None and not callable(audit_event_callback):
        raise TypeError("audit_event_callback must be callable")
    if not isinstance(action, str) or not action.strip() or action.strip() == "*":
        raise ValueError("action must be a non-empty concrete action")
    normalized_action = action.strip()

    if tool_name is None:
        normalized_tool_name = None
    elif not isinstance(tool_name, str) or not tool_name.strip():
        raise ValueError("tool_name must be a non-empty string or None")
    else:
        normalized_tool_name = tool_name.strip()

    def decorate(function: Callable[..., Any]) -> Callable[..., Any]:
        if not callable(function):
            raise TypeError("function must be callable")
        if isasyncgenfunction(function):
            raise TypeError("async generator MCP tools are not supported")

        function_signature = signature(function)
        try:
            resolved_annotations = get_type_hints(function, include_extras=True)
        except Exception as exc:
            raise TypeError(
                "MCP tool handler annotations must be resolvable before authorization"
            ) from exc
        context_parameters = [
            parameter
            for parameter in function_signature.parameters.values()
            if _is_context_annotation(
                resolved_annotations.get(parameter.name, parameter.annotation)
            )
        ]
        if len(context_parameters) != 1:
            raise TypeError(
                "MCP tool handler must declare exactly one parameter annotated as Context"
            )
        context_parameter = context_parameters[0]
        if context_parameter.kind in {
            Parameter.POSITIONAL_ONLY,
            Parameter.VAR_POSITIONAL,
            Parameter.VAR_KEYWORD,
        }:
            raise TypeError(
                "Context must be a named positional-or-keyword or keyword-only parameter"
            )
        if context_parameter.default is not Parameter.empty:
            raise TypeError(
                "Context parameter must be required so authorization cannot run without it"
            )

        effective_tool_name = normalized_tool_name or getattr(
            function, "__name__", type(function).__name__
        )
        if not isinstance(effective_tool_name, str) or not effective_tool_name.strip():
            raise ValueError("MCP tool name must be non-empty")
        effective_tool_name = effective_tool_name.strip()

        def authorize(args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
            started = perf_counter()
            bound = function_signature.bind(*args, **kwargs)
            bound.apply_defaults()
            mcp_context = bound.arguments[context_parameter.name]
            tool_arguments = {
                name: value
                for name, value in bound.arguments.items()
                if name != context_parameter.name
            }

            if isinstance(policy, PolicyRegistry):
                policy_snapshot = policy.snapshot()
                active_policy = policy_snapshot.engine
            else:
                policy_snapshot = None
                active_policy = policy

            principal = principal_resolver(cast(Context, mcp_context))
            if not isinstance(principal, Principal):
                raise TypeError("principal_resolver must return a Principal instance")

            resource = (
                effective_tool_name
                if resource_resolver is None
                else call_resolver_without_mutation(resource_resolver, tool_arguments)
            )
            resource_attributes = (
                {}
                if resource_attributes_resolver is None
                else call_resolver_without_mutation(resource_attributes_resolver, resource)
            )
            if not isinstance(resource_attributes, Mapping):
                raise TypeError("resource_attributes_resolver must return a mapping")

            context_attributes = (
                {} if context_resolver is None else context_resolver(cast(Context, mcp_context))
            )
            if not isinstance(context_attributes, Mapping):
                raise TypeError("context_resolver must return a mapping")

            request = AccessRequest(
                principal=principal,
                action=normalized_action,
                resource=resource,
                resource_attributes=resource_attributes,
                context=context_attributes,
            )
            decision = active_policy.evaluate(request)
            duration_ms = (perf_counter() - started) * 1000.0
            request_id = getattr(mcp_context, "request_id", None)
            if not isinstance(request_id, str) or not request_id.strip():
                request_id = None

            if audit_event_callback is not None:
                audit_event_callback(
                    AuditEvent.from_decision(
                        request,
                        decision,
                        source="mcp_tool",
                        duration_ms=duration_ms,
                        request_id=request_id,
                        tool_name=effective_tool_name,
                        policy_id=(
                            policy_snapshot.policy_id if policy_snapshot is not None else policy_id
                        ),
                        policy_version=(
                            policy_snapshot.version
                            if policy_snapshot is not None
                            else policy_version
                        ),
                        policy_digest=(
                            policy_snapshot.digest if policy_snapshot is not None else policy_digest
                        ),
                    )
                )
            if audit_callback is not None:
                audit_callback(request, decision)

            if not decision.allowed:
                raise AuthorizationDenied(request, decision)

        if iscoroutinefunction(function):

            @wraps(function)
            async def guarded_async(*args: Any, **kwargs: Any) -> Any:
                authorize(args, kwargs)
                return await cast(Awaitable[Any], function(*args, **kwargs))

            return guarded_async

        @wraps(function)
        def guarded(*args: Any, **kwargs: Any) -> Any:
            authorize(args, kwargs)
            return function(*args, **kwargs)

        return guarded

    return decorate
