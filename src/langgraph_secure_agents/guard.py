"""Execution guards for ordinary Python callables."""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import ParamSpec, TypeVar

from .models import AccessRequest, Decision, Principal
from .policy import PolicyEngine

P = ParamSpec("P")
R = TypeVar("R")
AuditCallback = Callable[[AccessRequest, Decision], None]
ResourceResolver = Callable[P, str]


class AuthorizationDenied(PermissionError):
    """Raised when a protected callable is invoked without authorization."""

    def __init__(self, request: AccessRequest, decision: Decision) -> None:
        self.request = request
        self.decision = decision
        super().__init__(f"Access denied for action {request.action!r} ({decision.reason}).")


def protect_callable(
    function: Callable[P, R],
    *,
    policy: PolicyEngine,
    principal_resolver: Callable[[], Principal],
    action: str = "execute",
    resource_resolver: ResourceResolver[P] | None = None,
    audit_callback: AuditCallback | None = None,
) -> Callable[P, R]:
    """Return a callable that checks authorization immediately before execution.

    The principal resolver must obtain identity from trusted application context,
    not from arguments controlled by an LLM. The resource resolver must identify
    the same resource the wrapped function will actually access. If auditing is
    configured and the callback fails, execution fails closed.
    """

    if not callable(function):
        raise TypeError("function must be callable")
    if not isinstance(policy, PolicyEngine):
        raise TypeError("policy must be a PolicyEngine instance")
    if not callable(principal_resolver):
        raise TypeError("principal_resolver must be callable")
    if resource_resolver is not None and not callable(resource_resolver):
        raise TypeError("resource_resolver must be callable")
    if audit_callback is not None and not callable(audit_callback):
        raise TypeError("audit_callback must be callable")
    if not isinstance(action, str) or not action.strip() or action.strip() == "*":
        raise ValueError("action must be a non-empty concrete action")

    normalized_action = action.strip()
    if resource_resolver is None:
        resource_name = getattr(function, "__name__", type(function).__name__)

        def default_resource_resolver(*args: P.args, **kwargs: P.kwargs) -> str:
            return resource_name

        resolve_resource = default_resource_resolver
    else:
        resolve_resource = resource_resolver

    @wraps(function)
    def guarded(*args: P.args, **kwargs: P.kwargs) -> R:
        principal = principal_resolver()
        if not isinstance(principal, Principal):
            raise TypeError("principal_resolver must return a Principal instance")

        request = AccessRequest(
            principal=principal,
            action=normalized_action,
            resource=resolve_resource(*args, **kwargs),
        )
        decision = policy.evaluate(request)

        if audit_callback is not None:
            audit_callback(request, decision)

        if not decision.allowed:
            raise AuthorizationDenied(request, decision)

        return function(*args, **kwargs)

    return guarded
