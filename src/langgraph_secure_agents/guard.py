"""Execution guards for ordinary Python callables."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from functools import wraps
from inspect import iscoroutinefunction
from time import perf_counter
from typing import Any, ParamSpec, TypeVar, cast, overload

from ._resolver_safety import call_resolver_without_mutation
from .audit import AuditEvent, AuditEventCallback
from .models import AccessRequest, Decision, JSONValue, Principal
from .policy import PolicyEngine
from .policy_registry import PolicyRegistry

P = ParamSpec("P")
R = TypeVar("R")
AuditCallback = Callable[[AccessRequest, Decision], None]
ResourceResolver = Callable[P, str]
ResourceAttributesResolver = Callable[[str], Mapping[str, JSONValue]]
ContextResolver = Callable[[], Mapping[str, JSONValue]]
RequestIdResolver = Callable[P, str]
ExecutionIdResolver = Callable[[], str]


class AuthorizationDenied(PermissionError):
    """Raised when a protected callable is invoked without authorization."""

    def __init__(self, request: AccessRequest, decision: Decision) -> None:
        self.request = request
        self.decision = decision
        super().__init__(f"Access denied for action {request.action!r} ({decision.reason}).")


@overload
def protect_callable(
    function: Callable[P, Awaitable[R]],
    *,
    policy: PolicyEngine | PolicyRegistry,
    principal_resolver: Callable[[], Principal],
    action: str = "execute",
    resource_resolver: ResourceResolver[P] | None = None,
    resource_attributes_resolver: ResourceAttributesResolver | None = None,
    context_resolver: ContextResolver | None = None,
    audit_callback: AuditCallback | None = None,
    audit_event_callback: AuditEventCallback | None = None,
    request_id_resolver: RequestIdResolver[P] | None = None,
    execution_id_resolver: ExecutionIdResolver | None = None,
    policy_id: str | None = None,
    policy_version: str | None = None,
    policy_digest: str | None = None,
) -> Callable[P, Awaitable[R]]: ...


@overload
def protect_callable(
    function: Callable[P, R],
    *,
    policy: PolicyEngine | PolicyRegistry,
    principal_resolver: Callable[[], Principal],
    action: str = "execute",
    resource_resolver: ResourceResolver[P] | None = None,
    resource_attributes_resolver: ResourceAttributesResolver | None = None,
    context_resolver: ContextResolver | None = None,
    audit_callback: AuditCallback | None = None,
    audit_event_callback: AuditEventCallback | None = None,
    request_id_resolver: RequestIdResolver[P] | None = None,
    execution_id_resolver: ExecutionIdResolver | None = None,
    policy_id: str | None = None,
    policy_version: str | None = None,
    policy_digest: str | None = None,
) -> Callable[P, R]: ...


def protect_callable(
    function: Callable[P, Any],
    *,
    policy: PolicyEngine | PolicyRegistry,
    principal_resolver: Callable[[], Principal],
    action: str = "execute",
    resource_resolver: ResourceResolver[P] | None = None,
    resource_attributes_resolver: ResourceAttributesResolver | None = None,
    context_resolver: ContextResolver | None = None,
    audit_callback: AuditCallback | None = None,
    audit_event_callback: AuditEventCallback | None = None,
    request_id_resolver: RequestIdResolver[P] | None = None,
    execution_id_resolver: ExecutionIdResolver | None = None,
    policy_id: str | None = None,
    policy_version: str | None = None,
    policy_digest: str | None = None,
) -> Callable[P, Any]:
    """Return a callable that authorizes immediately before protected execution.

    Coroutine functions are authorized when their returned coroutine is awaited,
    not when the coroutine object is created. This ensures the trusted principal
    and policy are checked at the point execution begins.

    The principal resolver must obtain identity from trusted application context,
    not from arguments controlled by an LLM. The resource resolver must identify
    the same resource the wrapped function will actually access. The resource
    attributes resolver receives that resolved resource identifier and must load
    metadata for the exact resource being accessed. The context resolver must
    return trusted server-side request context. Resolver inputs are detached and
    mutation is rejected. Resolvers must otherwise be trusted, side-effect-free
    application code. If auditing is configured and the callback fails, execution
    fails closed.
    """

    if not callable(function):
        raise TypeError("function must be callable")
    if not isinstance(policy, (PolicyEngine, PolicyRegistry)):
        raise TypeError("policy must be a PolicyEngine or PolicyRegistry instance")
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
    if request_id_resolver is not None and not callable(request_id_resolver):
        raise TypeError("request_id_resolver must be callable")
    if execution_id_resolver is not None and not callable(execution_id_resolver):
        raise TypeError("execution_id_resolver must be callable")
    if not isinstance(action, str) or not action.strip() or action.strip() == "*":
        raise ValueError("action must be a non-empty concrete action")

    normalized_action = action.strip()
    if resource_resolver is None:
        resource_name = getattr(function, "__name__", type(function).__name__)

    def authorize(*args: P.args, **kwargs: P.kwargs) -> None:
        started = perf_counter()
        policy_snapshot = policy.snapshot() if isinstance(policy, PolicyRegistry) else None
        active_policy = policy_snapshot.engine if policy_snapshot is not None else policy
        principal = principal_resolver()
        if not isinstance(principal, Principal):
            raise TypeError("principal_resolver must return a Principal instance")

        if resource_resolver is None:
            resource = resource_name
        else:
            resource = call_resolver_without_mutation(resource_resolver, *args, **kwargs)

        resource_attributes = (
            {}
            if resource_attributes_resolver is None
            else call_resolver_without_mutation(resource_attributes_resolver, resource)
        )
        if not isinstance(resource_attributes, Mapping):
            raise TypeError("resource_attributes_resolver must return a mapping")
        context_attributes = (
            {} if context_resolver is None else call_resolver_without_mutation(context_resolver)
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
            request_id = (
                None
                if request_id_resolver is None
                else call_resolver_without_mutation(request_id_resolver, *args, **kwargs)
            )
            execution_id = (
                None
                if execution_id_resolver is None
                else call_resolver_without_mutation(execution_id_resolver)
            )
            event = AuditEvent.from_decision(
                request,
                decision,
                source="python_callable",
                duration_ms=duration_ms,
                request_id=request_id,
                execution_id=execution_id,
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

    if iscoroutinefunction(function):

        @wraps(function)
        async def guarded_async(*args: P.args, **kwargs: P.kwargs) -> Any:
            authorize(*args, **kwargs)
            return await cast(Awaitable[Any], function(*args, **kwargs))

        return guarded_async

    @wraps(function)
    def guarded(*args: P.args, **kwargs: P.kwargs) -> Any:
        authorize(*args, **kwargs)
        return function(*args, **kwargs)

    return guarded
