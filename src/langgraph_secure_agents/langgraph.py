"""Optional LangGraph-native authorization for sensitive graph nodes.

This module is separate so the core policy engine does not require LangGraph.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from functools import wraps
from inspect import Parameter, iscoroutinefunction, signature
from time import perf_counter
from typing import Any, TypeVar, cast

from langgraph.runtime import Runtime

from ._resolver_safety import call_resolver_without_mutation
from .audit import AuditEvent, AuditEventCallback
from .guard import AuditCallback, AuthorizationDenied
from .models import AccessRequest, JSONValue, Principal, normalize_resource_id
from .policy import PolicyEngine
from .policy_registry import PolicyRegistry

NodeFunction = TypeVar("NodeFunction", bound=Callable[..., Any])
PrincipalResolver = Callable[[object], Principal]
ResourceResolver = Callable[[object], str]
ResourceAttributesResolver = Callable[[str], Mapping[str, JSONValue]]
ContextResolver = Callable[[object], Mapping[str, JSONValue]]


def protect_node(
    node: NodeFunction,
    *,
    policy: PolicyEngine | PolicyRegistry,
    principal_resolver: PrincipalResolver,
    action: str = "execute",
    resource_resolver: ResourceResolver | None = None,
    resource_attributes_resolver: ResourceAttributesResolver | None = None,
    context_resolver: ContextResolver | None = None,
    audit_callback: AuditCallback | None = None,
    audit_event_callback: AuditEventCallback | None = None,
    policy_id: str | None = None,
    policy_version: str | None = None,
    policy_digest: str | None = None,
) -> NodeFunction:
    """Wrap a LangGraph node with authorization before its execution.

    The node must declare a LangGraph Runtime parameter, normally annotated as
    Runtime[Context]. Its first parameter is treated as graph state. The principal
    resolver receives runtime.context and must derive identity only from trusted
    host-provided data. Resolver inputs are detached and mutation is rejected.
    The resource resolver receives graph state; it must resolve the exact resource
    the node will affect, using trusted application data where state contains
    model- or caller-controlled identifiers.

    A denied or approval-required policy decision raises AuthorizationDenied
    before the node executes. Human approval interrupts for agent tool calls are
    provided by create_authorization_middleware; this node wrapper does not turn
    an approval-required decision into an approval itself. Resolver, policy, and
    configured audit callback errors propagate before protected execution.
    """

    if not callable(node):
        raise TypeError("node must be callable")
    if not isinstance(policy, (PolicyEngine, PolicyRegistry)):
        raise TypeError("policy must be a PolicyEngine instance or a PolicyRegistry instance")
    if not callable(principal_resolver):
        raise TypeError("principal_resolver must be callable")
    for name, resolver in (
        ("resource_resolver", resource_resolver),
        ("resource_attributes_resolver", resource_attributes_resolver),
        ("context_resolver", context_resolver),
        ("audit_callback", audit_callback),
        ("audit_event_callback", audit_event_callback),
    ):
        if resolver is not None and not callable(resolver):
            raise TypeError(f"{name} must be callable")
    if not isinstance(action, str) or not action.strip() or action.strip() == "*":
        raise ValueError("action must be a non-empty concrete action")

    node_signature = signature(node)
    parameters = tuple(node_signature.parameters.values())
    if not parameters or parameters[0].kind not in {
        Parameter.POSITIONAL_ONLY,
        Parameter.POSITIONAL_OR_KEYWORD,
    }:
        raise TypeError("node must accept graph state as its first positional parameter")
    state_parameter_name = parameters[0].name
    node_name = getattr(node, "__name__", type(node).__name__)
    normalized_action = action.strip()

    def authorize(args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
        bound = node_signature.bind_partial(*args, **kwargs)
        if state_parameter_name not in bound.arguments:
            raise TypeError("protected node must receive graph state")

        state = bound.arguments[state_parameter_name]
        runtime = next(
            (value for value in bound.arguments.values() if isinstance(value, Runtime)),
            None,
        )
        if runtime is None:
            raise RuntimeError(
                "protected LangGraph nodes must declare and receive a Runtime parameter; "
                "use runtime: Runtime[Context] and pass trusted context to graph.invoke"
            )
        runtime_context = runtime.context

        started = perf_counter()
        if isinstance(policy, PolicyRegistry):
            policy_snapshot = policy.snapshot()
            active_policy = policy_snapshot.engine
        else:
            policy_snapshot = None
            active_policy = policy

        principal = call_resolver_without_mutation(principal_resolver, runtime_context)
        if not isinstance(principal, Principal):
            raise TypeError("principal_resolver must return a Principal instance")

        resolved_resource = (
            node_name
            if resource_resolver is None
            else call_resolver_without_mutation(resource_resolver, state)
        )
        resource = normalize_resource_id(resolved_resource)
        resource_attributes = (
            {}
            if resource_attributes_resolver is None
            else call_resolver_without_mutation(resource_attributes_resolver, resource)
        )
        if not isinstance(resource_attributes, Mapping):
            raise TypeError("resource_attributes_resolver must return a mapping")
        context_attributes = (
            {}
            if context_resolver is None
            else call_resolver_without_mutation(context_resolver, runtime_context)
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

        if audit_event_callback is not None:
            event = AuditEvent.from_decision(
                request,
                decision,
                source="langgraph_node",
                duration_ms=duration_ms,
                policy_id=policy_snapshot.policy_id if policy_snapshot is not None else policy_id,
                policy_version=(
                    policy_snapshot.version if policy_snapshot is not None else policy_version
                ),
                policy_digest=(
                    policy_snapshot.digest if policy_snapshot is not None else policy_digest
                ),
            )
            audit_event_callback(event)

        if audit_callback is not None:
            audit_callback(request, decision)

        if not decision.allowed:
            raise AuthorizationDenied(request, decision)

    if iscoroutinefunction(node):

        @wraps(node)
        async def authorized_async(*args: Any, **kwargs: Any) -> Any:
            authorize(args, kwargs)
            return await cast(Any, node(*args, **kwargs))

        return cast(NodeFunction, authorized_async)

    @wraps(node)
    def authorized(*args: Any, **kwargs: Any) -> Any:
        authorize(args, kwargs)
        return node(*args, **kwargs)

    return cast(NodeFunction, authorized)
