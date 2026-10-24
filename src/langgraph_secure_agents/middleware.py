"""Optional middleware that enforces policies before agent tools execute."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Callable, Mapping
from time import perf_counter
from typing import Any

from langchain.agents.middleware import AgentMiddleware, wrap_tool_call
from langchain_core.messages import ToolMessage
from langgraph.types import interrupt

from ._resolver_safety import call_resolver_without_mutation
from .approvals import ApprovalStore
from .audit import AuditEvent, AuditEventCallback
from .models import (
    AccessRequest,
    AttributeReference,
    Decision,
    DecisionReason,
    JSONValue,
    PolicyRule,
    Principal,
)
from .policy import PolicyEngine
from .policy_registry import PolicyRegistry

PrincipalResolver = Callable[[object], Principal]
ActionResolver = Callable[[str, Mapping[str, Any]], str]
ResourceResolver = Callable[[str, Mapping[str, Any]], str]
ResourceAttributesResolver = Callable[[str], Mapping[str, JSONValue]]
ContextResolver = Callable[[object], Mapping[str, JSONValue]]
AuditCallback = Callable[[AccessRequest, Decision], None]
ApprovalValidator = Callable[[Mapping[str, Any], AccessRequest, str], bool]
ApprovalReviewerResolver = Callable[[object], str]


def _canonical_json_value(value: Any) -> Any:
    """Normalize supported values to unambiguous, standards-compliant JSON data."""

    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("approval fingerprints cannot contain non-finite numbers")
        return value
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("approval fingerprints require string keys in JSON objects")
            normalized[key] = _canonical_json_value(item)
        return normalized
    if isinstance(value, (list, tuple)):
        return [_canonical_json_value(item) for item in value]
    raise ValueError("approval fingerprints can only contain JSON-compatible values")


def _approval_execution_scope(runtime: Any) -> dict[str, str]:
    """Get stable checkpoint scope for binding a human approval to one execution."""

    execution_info = getattr(runtime, "execution_info", None)
    thread_id = getattr(execution_info, "thread_id", None)
    checkpoint_id = getattr(execution_info, "checkpoint_id", None)
    checkpoint_ns = getattr(execution_info, "checkpoint_ns", None)
    task_id = getattr(execution_info, "task_id", None)

    if (
        not isinstance(thread_id, str)
        or not thread_id
        or not isinstance(checkpoint_id, str)
        or not checkpoint_id
        or not isinstance(checkpoint_ns, str)
        or not isinstance(task_id, str)
        or not task_id
    ):
        raise RuntimeError(
            "approval-required tool calls need LangGraph 1.2+ execution metadata "
            "and an active checkpointer"
        )

    return {
        "thread_id": thread_id,
        "checkpoint_id": checkpoint_id,
        "checkpoint_ns": checkpoint_ns,
        "task_id": task_id,
    }


def _approval_fingerprint(
    *,
    tool_name: str,
    tool_args: Mapping[str, Any],
    tool_call_id: str,
    access_request: AccessRequest,
    matched_rule_ids: tuple[str, ...],
    matched_policy_rules: tuple[PolicyRule, ...],
    execution_scope: Mapping[str, str],
) -> str:
    """Bind approval to one execution, request data, and matched policy definitions."""

    payload = {
        "execution_scope": dict(execution_scope),
        "tool_name": tool_name,
        "tool_args": dict(tool_args),
        "tool_call_id": tool_call_id,
        "principal_id": access_request.principal.principal_id,
        "roles": sorted(access_request.principal.roles),
        "principal_attributes": dict(access_request.principal.attributes),
        "resource_attributes": dict(access_request.resource_attributes),
        "context": dict(access_request.context),
        "action": access_request.action,
        "resource": access_request.resource,
        "matched_rule_ids": list(matched_rule_ids),
        "matched_policy_rules": [
            {
                "rule_id": rule.rule_id,
                "effect": rule.effect.value,
                "actions": sorted(rule.actions),
                "resources": sorted(rule.resources),
                "principal_ids": sorted(rule.principal_ids),
                "roles": sorted(rule.roles),
                "conditions": [
                    {
                        "attribute": condition.attribute,
                        "operator": condition.operator.value,
                        "value": (
                            {"attribute_reference": condition.value.path}
                            if isinstance(condition.value, AttributeReference)
                            else condition.value
                        ),
                    }
                    for condition in rule.conditions
                ],
            }
            for rule in matched_policy_rules
        ],
    }
    try:
        canonical_payload = _canonical_json_value(payload)
        serialized = json.dumps(
            canonical_payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("approval-required tool arguments must be JSON-serializable") from exc
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def create_authorization_middleware(
    policy: PolicyEngine | PolicyRegistry,
    principal_resolver: PrincipalResolver,
    *,
    action_resolver: ActionResolver | None = None,
    resource_resolver: ResourceResolver | None = None,
    resource_attributes_resolver: ResourceAttributesResolver | None = None,
    context_resolver: ContextResolver | None = None,
    audit_callback: AuditCallback | None = None,
    audit_event_callback: AuditEventCallback | None = None,
    policy_id: str | None = None,
    policy_version: str | None = None,
    policy_digest: str | None = None,
    approval_validator: ApprovalValidator | None = None,
    approval_store: ApprovalStore | None = None,
    approval_reviewer_resolver: ApprovalReviewerResolver | None = None,
) -> Any:
    """Create middleware that authorizes every tool call before execution.

    The principal resolver receives the agent runtime's context. It must derive
    identity from trusted application data, never from tool arguments or LLM
    output. By default, the requested action is execute and the resource is
    the tool name. Custom resolvers can map tool calls to domain actions and
    resources. A denied call returns an error ToolMessage without invoking the
    tool handler.

    For REQUIRE_APPROVAL decisions, LangGraph interrupt() pauses execution before
    delegation. Resume the same checkpoint/thread with a trusted approval result
    containing both a boolean 'approved' field and the exact request_fingerprint
    shown in the interrupt payload. The host application must authenticate the
    reviewer and authorize access to the resume operation; the payload alone is
    not proof that an authorized human approved the action. The fingerprint is
    deterministic, not a one-time token. For built-in durable consumption,
    configure approval_store and approval_reviewer_resolver together. After an
    authenticated reviewer approves the exact pending request, the host's trusted
    approval endpoint should issue a short-lived token with store.issue(); the
    resumed approval must contain that token and fingerprint. The reviewer
    resolver must derive identity from trusted server-side state available during
    resume, never from the approval mapping. SQLiteApprovalStore atomically checks
    expiry, request fingerprint, reviewer identity, and one-time use before the
    tool handler runs. The store does not authenticate reviewers or secure the
    resume endpoint. Alternatively, approval_validator can implement an equivalent
    transactional backend; it must return literal True only for a valid first
    use. Configure one mechanism, not both. Without either mechanism, the legacy
    fingerprint check alone is not sufficient for side-effecting operations.

    Action and resource resolvers receive detached argument copies. The resource
    attributes resolver receives the resolved resource identifier, and the context
    resolver receives a detached runtime-context copy. Resolver results must come
    from trusted application data, not LLM claims. Mutating resolver inputs raises
    an error before the protected tool runs. Resolvers must otherwise be trusted,
    side-effect-free application code.

    If configured auditing raises, the tool handler is not invoked (fail closed).
    Approval outcomes are audited after the interrupt resumes.
    """

    if not isinstance(policy, (PolicyEngine, PolicyRegistry)):
        raise TypeError("policy must be a PolicyEngine or PolicyRegistry instance")
    if not callable(principal_resolver):
        raise TypeError("principal_resolver must be callable")
    if action_resolver is not None and not callable(action_resolver):
        raise TypeError("action_resolver must be callable")
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
    if approval_validator is not None and not callable(approval_validator):
        raise TypeError("approval_validator must be callable")
    if approval_reviewer_resolver is not None and not callable(approval_reviewer_resolver):
        raise TypeError("approval_reviewer_resolver must be callable")
    if approval_store is not None and approval_validator is not None:
        raise ValueError("configure approval_store or approval_validator, not both")
    if (approval_store is None) != (approval_reviewer_resolver is None):
        raise ValueError("approval_store and approval_reviewer_resolver must be configured together")

    @wrap_tool_call(name="secure_agent_authorization")
    def enforce_authorization(request: Any, handler: Callable[[Any], Any]) -> Any:
        started = perf_counter()
        policy_snapshot = policy.snapshot() if isinstance(policy, PolicyRegistry) else None
        active_policy = policy_snapshot.engine if policy_snapshot is not None else policy
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
        request_id = (
            tool_call_id.strip() if isinstance(tool_call_id, str) and tool_call_id.strip() else None
        )
        execution_info = getattr(runtime, "execution_info", None)
        task_id = getattr(execution_info, "task_id", None)
        execution_id = task_id.strip() if isinstance(task_id, str) and task_id.strip() else None
        principal = principal_resolver(runtime_context)
        if not isinstance(principal, Principal):
            raise TypeError("principal_resolver must return a Principal instance")

        action = (
            "execute"
            if action_resolver is None
            else call_resolver_without_mutation(action_resolver, tool_name, tool_args)
        )
        resource = (
            tool_name
            if resource_resolver is None
            else call_resolver_without_mutation(resource_resolver, tool_name, tool_args)
        )
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
        access_request = AccessRequest(
            principal=principal,
            action=action,
            resource=resource,
            resource_attributes=resource_attributes,
            context=context_attributes,
        )
        decision = active_policy.evaluate(access_request)

        def emit_audit(outcome: Decision, *, include_legacy: bool = True) -> None:
            duration_ms = (perf_counter() - started) * 1000.0
            if audit_event_callback is not None:
                event = AuditEvent.from_decision(
                    access_request,
                    outcome,
                    source="langchain_tool",
                    duration_ms=duration_ms,
                    request_id=request_id,
                    execution_id=execution_id,
                    tool_name=tool_name,
                    policy_id=policy_snapshot.policy_id if policy_snapshot is not None else policy_id,
                    policy_version=policy_snapshot.version if policy_snapshot is not None else policy_version,
                    policy_digest=policy_snapshot.digest if policy_snapshot is not None else policy_digest,
                )
                audit_event_callback(event)
            if include_legacy and audit_callback is not None:
                audit_callback(access_request, outcome)

        if decision.requires_approval:
            # Record the policy decision before interrupting so pending approvals are
            # observable even if the graph is never resumed.
            emit_audit(decision, include_legacy=False)
            if not isinstance(tool_call_id, str) or not tool_call_id:
                raise ValueError("approval-required tool calls must include a tool-call id")

            matched_policy_rules = tuple(
                rule for rule in active_policy.rules if rule.rule_id in decision.matched_rule_ids
            )
            if tuple(rule.rule_id for rule in matched_policy_rules) != decision.matched_rule_ids:
                raise RuntimeError("policy decision refers to an unknown policy rule")

            execution_scope = _approval_execution_scope(runtime)
            fingerprint = _approval_fingerprint(
                tool_name=tool_name,
                tool_args=tool_args,
                tool_call_id=tool_call_id,
                access_request=access_request,
                matched_rule_ids=decision.matched_rule_ids,
                matched_policy_rules=matched_policy_rules,
                execution_scope=execution_scope,
            )
            approval = interrupt(
                {
                    "type": "authorization_approval",
                    "message": "A human decision is required before this tool can execute.",
                    "tool_name": tool_name,
                    "tool_call_id": tool_call_id,
                    "principal_id": principal.principal_id,
                    "roles": sorted(principal.roles),
                    "action": access_request.action,
                    "resource": access_request.resource,
                    "policy_rule_ids": list(decision.matched_rule_ids),
                    "execution_scope": execution_scope,
                    "request_fingerprint": fingerprint,
                }
            )

            approval_valid = (
                isinstance(approval, Mapping)
                and type(approval.get("approved")) is bool
                and approval.get("request_fingerprint") == fingerprint
            )
            if approval_valid and approval_store is not None and approval.get("approved") is True:
                approval_token = approval.get("approval_token")
                assert approval_reviewer_resolver is not None
                reviewer_id = call_resolver_without_mutation(
                    approval_reviewer_resolver,
                    runtime_context,
                )
                if not isinstance(reviewer_id, str) or not reviewer_id.strip():
                    raise TypeError("approval_reviewer_resolver must return a non-empty reviewer ID")
                approval_valid = (
                    isinstance(approval_token, str)
                    and bool(approval_token)
                    and approval_store.consume(approval_token, fingerprint, reviewer_id.strip())
                )
            elif approval_valid and approval_validator is not None:
                validation_result = approval_validator(
                    approval,
                    access_request,
                    fingerprint,
                )
                approval_valid = type(validation_result) is bool and validation_result

            if not approval_valid:
                outcome = Decision(
                    allowed=False,
                    reason=DecisionReason.APPROVAL_INVALID,
                    matched_rule_ids=decision.matched_rule_ids,
                )
                emit_audit(outcome)
                return ToolMessage(
                    content="Approval response invalid; tool was not executed.",
                    tool_call_id=tool_call_id,
                    status="error",
                )

            if not approval["approved"]:
                outcome = Decision(
                    allowed=False,
                    reason=DecisionReason.APPROVAL_DENIED,
                    matched_rule_ids=decision.matched_rule_ids,
                )
                emit_audit(outcome)
                return ToolMessage(
                    content="Human approval denied.",
                    tool_call_id=tool_call_id,
                    status="error",
                )

            outcome = Decision(
                allowed=True,
                reason=DecisionReason.HUMAN_APPROVED,
                matched_rule_ids=decision.matched_rule_ids,
            )
            emit_audit(outcome)
            return handler(request)

        emit_audit(decision)

        if not decision.allowed:
            if not isinstance(tool_call_id, str) or not tool_call_id:
                raise ValueError("denied tool calls must include a tool-call id")
            return ToolMessage(
                content="Authorization denied.",
                tool_call_id=tool_call_id,
                status="error",
            )

        return handler(request)

    sync_middleware = enforce_authorization
    sentinel = ToolMessage(
        content="authorization sentinel",
        tool_call_id="__secure_agents_sentinel__",
    )

    async def enforce_authorization_async(request: Any, handler: Any) -> Any:
        # Reuse the exact synchronous authorization path, substituting a sentinel
        # handler so the real async tool is only awaited after authorization passes.
        result = sync_middleware.wrap_tool_call(request, lambda _: sentinel)
        if result is sentinel:
            return await handler(request)
        return result

    async_middleware = wrap_tool_call(name="secure_agent_authorization_async")(
        enforce_authorization_async
    )

    class _CombinedAuthorizationMiddleware(AgentMiddleware[Any, Any, Any]):
        def wrap_tool_call(self, request: Any, handler: Any) -> Any:
            return sync_middleware.wrap_tool_call(request, handler)

        async def awrap_tool_call(self, request: Any, handler: Any) -> Any:
            return await async_middleware.awrap_tool_call(request, handler)

    return _CombinedAuthorizationMiddleware()
