"""Execution guards for ordinary Python callables."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from functools import wraps
from inspect import iscoroutinefunction
from typing import Any, ParamSpec, TypeVar, cast, overload

from ._resolver_safety import call_resolver_without_mutation
from .models import AccessRequest, Decision, JSONValue, Principal
from .policy import PolicyEngine

P = ParamSpec("P")
R = TypeVar("R")
AuditCallback = Callable[[AccessRequest, Decision], None]
ResourceResolver = Callable[P, str]
ResourceAttributesResolver = Callable[[str], Mapping[str, JSONValue]]
ContextResolver = Callable[[], Mapping[str, JSONValue]]


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
    policy: PolicyEngine,
    principal_resolver: Callable[[], Principal],
    action: str = "execute",
    resource_resolver: ResourceResolver[P] | None = None,
    resource_attributes_resolver: ResourceAttributesResolver | None = None,
    context_resolver: ContextResolver | None = None,
    audit_callback: AuditCallback | None = None,
) -> Callable[P, Awaitable[R]]: ...


@overload
def protect_callable(
    function: Callable[P, R],
    *,
    policy: PolicyEngine,
    principal_resolver: Callable[[], Principal],
    action: str = "execute",
    resource_resolver: ResourceResolver[P] | None = None,
    resource_attributes_resolver: ResourceAttributesResolver | None = None,
    context_resolver: ContextResolver | None = None,
    audit_callback: AuditCallback | None = None,
) -> Callable[P, R]: ...


def protect_callable(
    function: Callable[P, Any],
    *,
    policy: PolicyEngine,
    principal_resolver: Callable[[], Principal],
    action: str = "execute",
    resource_resolver: ResourceResolver[P] | None = None,
    resource_attributes_resolver: ResourceAttributesResolver | None = None,
    context_resolver: ContextResolver | None = None,
    audit_callback: AuditCallback | None = None,
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
    if not isinstance(policy, PolicyEngine):
        raise TypeError("policy must be a PolicyEngine instance")
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
    if not isinstance(action, str) or not action.strip() or action.strip() == "*":
        raise ValueError("action must be a non-empty concrete action")

    normalized_action = action.strip()
    if resource_resolver is None:
        resource_name = getattr(function, "__name__", type(function).__name__)

    def authorize(*args: P.args, **kwargs: P.kwargs) -> None:
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
        decision = policy.evaluate(request)

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
