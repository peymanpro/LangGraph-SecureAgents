"""Structured authorization audit events and optional OpenTelemetry integration."""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from .models import AccessRequest, Decision, DecisionReason

AuditEventCallback = Callable[["AuditEvent"], None]


def _optional_text(value: str | None, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string or None")
    return value.strip()


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Immutable, versioned record of one authorization outcome.

    The event object contains the original principal and resource identifiers so
    trusted sinks can use them when necessary. Serializers and the OpenTelemetry
    adapter redact those fields by default; callers must explicitly opt in to
    exporting them. Request attribute values are never copied into an event.
    """

    principal_id: str
    principal_roles: tuple[str, ...]
    action: str
    resource: str
    decision_reason: DecisionReason
    allowed: bool
    requires_approval: bool
    matched_rule_ids: tuple[str, ...] = ()
    request_id: str | None = None
    execution_id: str | None = None
    tool_name: str | None = None
    source: str = "authorization"
    policy_id: str | None = None
    policy_version: str | None = None
    policy_digest: str | None = None
    duration_ms: float | None = None
    event_id: str = field(default_factory=lambda: uuid4().hex)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    schema_version = 1
    event_name = "authorization.decision"

    def __post_init__(self) -> None:
        for name in ("principal_id", "action", "resource", "source", "event_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
            object.__setattr__(self, name, value.strip())

        try:
            reason = DecisionReason(self.decision_reason)
        except (TypeError, ValueError) as exc:
            raise ValueError("decision_reason must be a known DecisionReason") from exc
        object.__setattr__(self, "decision_reason", reason)

        if type(self.allowed) is not bool:
            raise ValueError("allowed must be a boolean")
        if type(self.requires_approval) is not bool:
            raise ValueError("requires_approval must be a boolean")
        if self.requires_approval != (reason is DecisionReason.APPROVAL_REQUIRED):
            raise ValueError(
                "requires_approval must be true exactly when reason is 'approval_required'"
            )
        if self.allowed and reason not in {
            DecisionReason.EXPLICIT_ALLOW,
            DecisionReason.HUMAN_APPROVED,
        }:
            raise ValueError("decision_reason cannot describe an allowed outcome")
        if not self.allowed and reason in {
            DecisionReason.EXPLICIT_ALLOW,
            DecisionReason.HUMAN_APPROVED,
        }:
            raise ValueError("decision_reason cannot describe a denied outcome")

        if isinstance(self.principal_roles, (str, bytes)):
            raise ValueError("principal_roles must be a collection of role names")
        try:
            roles = tuple(sorted({self._validate_text(role, "principal role") for role in self.principal_roles}))
        except TypeError as exc:
            raise ValueError("principal_roles must be an iterable of strings") from exc
        object.__setattr__(self, "principal_roles", roles)

        if isinstance(self.matched_rule_ids, (str, bytes)):
            raise ValueError("matched_rule_ids must be a collection of rule IDs")
        try:
            rule_ids = tuple(self._validate_text(rule_id, "matched rule ID") for rule_id in self.matched_rule_ids)
        except TypeError as exc:
            raise ValueError("matched_rule_ids must be an iterable of strings") from exc
        if len(set(rule_ids)) != len(rule_ids):
            raise ValueError("matched_rule_ids cannot contain duplicates")
        object.__setattr__(self, "matched_rule_ids", rule_ids)

        for name in (
            "policy_id",
            "policy_version",
            "policy_digest",
            "request_id",
            "execution_id",
            "tool_name",
        ):
            object.__setattr__(self, name, _optional_text(getattr(self, name), name))

        if self.duration_ms is not None:
            if (
                isinstance(self.duration_ms, bool)
                or not isinstance(self.duration_ms, (int, float))
                or not math.isfinite(self.duration_ms)
                or self.duration_ms < 0
            ):
                raise ValueError("duration_ms must be a finite, non-negative number or None")
            object.__setattr__(self, "duration_ms", float(self.duration_ms))

        if not isinstance(self.timestamp, datetime):
            raise ValueError("timestamp must be a timezone-aware datetime")
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        object.__setattr__(self, "timestamp", self.timestamp.astimezone(UTC))

    @staticmethod
    def _validate_text(value: str, field_name: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field_name} must be a non-empty string")
        return value.strip()

    @classmethod
    def from_decision(
        cls,
        request: AccessRequest,
        decision: Decision,
        *,
        source: str = "authorization",
        duration_ms: float | None = None,
        request_id: str | None = None,
        execution_id: str | None = None,
        tool_name: str | None = None,
        policy_id: str | None = None,
        policy_version: str | None = None,
        policy_digest: str | None = None,
    ) -> AuditEvent:
        """Build an event from the exact request and outcome used by enforcement."""

        if not isinstance(request, AccessRequest):
            raise TypeError("request must be an AccessRequest instance")
        if not isinstance(decision, Decision):
            raise TypeError("decision must be a Decision instance")
        return cls(
            principal_id=request.principal.principal_id,
            principal_roles=tuple(request.principal.roles),
            action=request.action,
            resource=request.resource,
            decision_reason=decision.reason,
            allowed=decision.allowed,
            requires_approval=decision.requires_approval,
            matched_rule_ids=decision.matched_rule_ids,
            request_id=request_id,
            execution_id=execution_id,
            tool_name=tool_name,
            source=source,
            policy_id=policy_id,
            policy_version=policy_version,
            policy_digest=policy_digest,
            duration_ms=duration_ms,
        )

    @property
    def matched_rule_count(self) -> int:
        """Number of rules contributing to this decision."""

        return len(self.matched_rule_ids)

    def to_dict(self, *, include_sensitive: bool = False) -> dict[str, object]:
        """Return a JSON-compatible record, redacting identifiers by default."""

        if type(include_sensitive) is not bool:
            raise ValueError("include_sensitive must be a boolean")

        payload: dict[str, object] = {
            "schema_version": self.schema_version,
            "event_name": self.event_name,
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat().replace("+00:00", "Z"),
            "source": self.source,
            "action": self.action,
            "allowed": self.allowed,
            "decision_reason": self.decision_reason.value,
            "requires_approval": self.requires_approval,
            "matched_rule_count": self.matched_rule_count,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "duration_ms": self.duration_ms,
        }
        if include_sensitive:
            payload["principal_id"] = self.principal_id
            payload["principal_roles"] = list(self.principal_roles)
            payload["resource"] = self.resource
            payload["matched_rule_ids"] = list(self.matched_rule_ids)
            payload["request_id"] = self.request_id
            payload["execution_id"] = self.execution_id
            payload["tool_name"] = self.tool_name
            payload["policy_digest"] = self.policy_digest
        return payload

    def to_json(self, *, include_sensitive: bool = False, indent: int | None = None) -> str:
        """Serialize to deterministic JSON suitable for structured log pipelines."""

        return json.dumps(
            self.to_dict(include_sensitive=include_sensitive),
            ensure_ascii=False,
            sort_keys=True,
            separators=None if indent is not None else (",", ":"),
            indent=indent,
            allow_nan=False,
        )

    def to_otel_attributes(self, *, include_sensitive: bool = False) -> Mapping[str, Any]:
        """Return span/event attributes with privacy-safe defaults."""

        attributes: dict[str, Any] = {
            "event.name": self.event_name,
            "event.id": self.event_id,
            "authorization.source": self.source,
            "authorization.action": self.action,
            "authorization.allowed": self.allowed,
            "authorization.reason": self.decision_reason.value,
            "authorization.requires_approval": self.requires_approval,
            "authorization.matched_rule_count": self.matched_rule_count,
        }
        if self.duration_ms is not None:
            attributes["authorization.duration_ms"] = self.duration_ms
        if self.policy_id is not None:
            attributes["authorization.policy_id"] = self.policy_id
        if self.policy_version is not None:
            attributes["authorization.policy_version"] = self.policy_version
        if include_sensitive:
            attributes["enduser.id"] = self.principal_id
            attributes["authorization.principal_roles"] = self.principal_roles
            attributes["authorization.resource"] = self.resource
            attributes["authorization.matched_rule_ids"] = self.matched_rule_ids
            if self.request_id is not None:
                attributes["authorization.request_id"] = self.request_id
            if self.execution_id is not None:
                attributes["authorization.execution_id"] = self.execution_id
            if self.tool_name is not None:
                attributes["authorization.tool_name"] = self.tool_name
            if self.policy_digest is not None:
                attributes["authorization.policy_digest"] = self.policy_digest
        return attributes


def create_opentelemetry_callback(
    *,
    include_sensitive: bool = False,
    span_name: str = "authorization.decision",
) -> AuditEventCallback:
    """Create an optional callback that exports audit events to OpenTelemetry.

    The callback adds an event to an existing recording span. When no recording
    span is active, it creates a short span around the authorization event. The
    OpenTelemetry API is imported lazily; installing the core package does not
    install or require telemetry dependencies.
    """

    if type(include_sensitive) is not bool:
        raise ValueError("include_sensitive must be a boolean")
    if not isinstance(span_name, str) or not span_name.strip():
        raise ValueError("span_name must be a non-empty string")

    try:
        from opentelemetry import trace
    except ImportError as exc:
        raise ImportError(
            "OpenTelemetry support requires the optional dependency; "
            "install 'langgraph-secure-agents[opentelemetry]'"
        ) from exc

    tracer = trace.get_tracer("langgraph_secure_agents.audit")

    def emit(event: AuditEvent) -> None:
        if not isinstance(event, AuditEvent):
            raise TypeError("event must be an AuditEvent instance")
        attributes = dict(event.to_otel_attributes(include_sensitive=include_sensitive))
        current_span = trace.get_current_span()
        if current_span.is_recording():
            current_span.add_event(event.event_name, attributes=attributes)
            return
        with tracer.start_as_current_span(span_name, attributes=attributes) as span:
            span.add_event(event.event_name, attributes=attributes)

    return emit
