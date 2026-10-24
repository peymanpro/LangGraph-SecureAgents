from __future__ import annotations

import builtins
from datetime import UTC, datetime
from typing import Any

import pytest

from langgraph_secure_agents import AccessRequest, Decision, DecisionReason, Principal
from langgraph_secure_agents.audit import AuditEvent, create_opentelemetry_callback


def sample_event(**overrides: Any) -> AuditEvent:
    fields: dict[str, Any] = {
        "principal_id": "alice",
        "principal_roles": ("analyst", "hr"),
        "action": "read",
        "resource": "payroll:employee-7",
        "decision_reason": DecisionReason.EXPLICIT_ALLOW,
        "allowed": True,
        "requires_approval": False,
        "matched_rule_ids": ("analysts-read-payroll",),
        "source": "python_callable",
        "request_id": "request-123",
        "execution_id": "run-456",
        "tool_name": "read_payroll",
        "policy_id": "payroll-access",
        "policy_version": "1.2.0",
        "policy_digest": "a" * 64,
        "duration_ms": 2.5,
        "event_id": "event-123",
        "timestamp": datetime(2026, 10, 24, 12, 30, tzinfo=UTC),
    }
    fields.update(overrides)
    return AuditEvent(**fields)


def test_audit_event_builds_from_the_exact_access_decision() -> None:
    request = AccessRequest(
        principal=Principal("alice", roles=frozenset({"analyst"})),
        action="read",
        resource="payroll:employee-7",
    )
    decision = Decision(
        allowed=True,
        reason=DecisionReason.EXPLICIT_ALLOW,
        matched_rule_ids=("allow-payroll-read",),
    )

    event = AuditEvent.from_decision(
        request,
        decision,
        source="python_callable",
        duration_ms=1.25,
        policy_id="payroll-access",
        policy_version="1.2.0",
    )

    assert event.principal_id == "alice"
    assert event.principal_roles == ("analyst",)
    assert event.action == "read"
    assert event.resource == "payroll:employee-7"
    assert event.allowed
    assert event.decision_reason is DecisionReason.EXPLICIT_ALLOW
    assert event.matched_rule_ids == ("allow-payroll-read",)
    assert event.duration_ms == 1.25
    assert event.policy_id == "payroll-access"
    assert event.policy_version == "1.2.0"
    assert event.schema_version == 1
    assert event.event_name == "authorization.decision"


def test_audit_event_serialization_redacts_identifiers_by_default() -> None:
    event = sample_event()

    payload = event.to_dict()
    encoded = event.to_json()

    assert payload["event_id"] == "event-123"
    assert payload["timestamp"] == "2026-10-24T12:30:00Z"
    assert payload["matched_rule_count"] == 1
    assert "principal_id" not in payload
    assert "principal_roles" not in payload
    assert "resource" not in payload
    assert "matched_rule_ids" not in payload
    assert "request_id" not in payload
    assert "execution_id" not in payload
    assert "tool_name" not in payload
    assert "policy_digest" not in payload
    assert "alice" not in encoded
    assert "payroll:employee-7" not in encoded


def test_audit_event_can_explicitly_serialize_sensitive_fields() -> None:
    payload = sample_event().to_dict(include_sensitive=True)

    assert payload["principal_id"] == "alice"
    assert payload["principal_roles"] == ["analyst", "hr"]
    assert payload["resource"] == "payroll:employee-7"
    assert payload["matched_rule_ids"] == ["analysts-read-payroll"]
    assert payload["request_id"] == "request-123"
    assert payload["execution_id"] == "run-456"
    assert payload["tool_name"] == "read_payroll"
    assert payload["policy_digest"] == "a" * 64


@pytest.mark.parametrize("duration_ms", [-1, float("nan"), float("inf"), True])
def test_audit_event_rejects_invalid_durations(duration_ms: object) -> None:
    with pytest.raises(ValueError, match="duration_ms"):
        sample_event(duration_ms=duration_ms)


def test_audit_event_rejects_naive_timestamps_and_invalid_booleans() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        sample_event(timestamp=datetime(2026, 10, 24, 12, 30))

    with pytest.raises(ValueError, match="allowed must be a boolean"):
        sample_event(allowed=1)

    with pytest.raises(ValueError, match="requires_approval must be true exactly"):
        sample_event(
            decision_reason=DecisionReason.APPROVAL_REQUIRED,
            allowed=False,
            requires_approval=False,
        )


def test_audit_event_rejects_duplicate_matched_rule_ids() -> None:
    with pytest.raises(ValueError, match="cannot contain duplicates"):
        sample_event(matched_rule_ids=("rule-a", "rule-a"))


def test_audit_event_normalizes_timestamp_to_utc() -> None:
    from datetime import timedelta, timezone

    local_time = datetime(2026, 10, 24, 15, 30, tzinfo=timezone(timedelta(hours=3)))
    event = sample_event(timestamp=local_time)

    assert event.timestamp.tzinfo is UTC
    assert event.to_dict()["timestamp"] == "2026-10-24T12:30:00Z"


def test_opentelemetry_callback_adds_a_redacted_event_to_current_span(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from opentelemetry import trace

    class RecordingSpan:
        def __init__(self) -> None:
            self.events: list[tuple[str, dict[str, Any]]] = []

        def is_recording(self) -> bool:
            return True

        def add_event(self, name: str, attributes: dict[str, Any]) -> None:
            self.events.append((name, attributes))

    span = RecordingSpan()
    monkeypatch.setattr(trace, "get_current_span", lambda: span)
    callback = create_opentelemetry_callback()
    callback(sample_event())

    assert len(span.events) == 1
    name, attributes = span.events[0]
    assert name == "authorization.decision"
    assert attributes["authorization.allowed"] is True
    assert attributes["authorization.reason"] == "explicit_allow"
    assert attributes["authorization.duration_ms"] == 2.5
    assert "enduser.id" not in attributes
    assert "authorization.resource" not in attributes


def test_opentelemetry_callback_can_explicitly_include_sensitive_attributes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from opentelemetry import trace

    class RecordingSpan:
        def __init__(self) -> None:
            self.events: list[tuple[str, dict[str, Any]]] = []

        def is_recording(self) -> bool:
            return True

        def add_event(self, name: str, attributes: dict[str, Any]) -> None:
            self.events.append((name, attributes))

    span = RecordingSpan()
    monkeypatch.setattr(trace, "get_current_span", lambda: span)
    create_opentelemetry_callback(include_sensitive=True)(sample_event())

    attributes = span.events[0][1]
    assert attributes["enduser.id"] == "alice"
    assert attributes["authorization.resource"] == "payroll:employee-7"
    assert attributes["authorization.matched_rule_ids"] == ("analysts-read-payroll",)
    assert attributes["authorization.request_id"] == "request-123"
    assert attributes["authorization.execution_id"] == "run-456"
    assert attributes["authorization.tool_name"] == "read_payroll"
    assert attributes["authorization.policy_digest"] == "a" * 64


def test_opentelemetry_callback_creates_span_when_none_is_recording(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from contextlib import AbstractContextManager
    from opentelemetry import trace

    class RecordingSpan:
        def __init__(self) -> None:
            self.events: list[tuple[str, dict[str, Any]]] = []

        def is_recording(self) -> bool:
            return True

        def add_event(self, name: str, attributes: dict[str, Any]) -> None:
            self.events.append((name, attributes))

    span = RecordingSpan()

    class SpanContext(AbstractContextManager[RecordingSpan]):
        def __enter__(self) -> RecordingSpan:
            return span

        def __exit__(self, *args: object) -> bool:
            return False

    class FakeTracer:
        def __init__(self) -> None:
            self.names: list[str] = []
            self.attributes: list[dict[str, Any]] = []

        def start_as_current_span(
            self,
            name: str,
            *,
            attributes: dict[str, Any],
        ) -> SpanContext:
            self.names.append(name)
            self.attributes.append(attributes)
            return SpanContext()

    tracer = FakeTracer()
    non_recording_span = type("NonRecordingSpan", (), {"is_recording": lambda self: False})()
    monkeypatch.setattr(trace, "get_current_span", lambda: non_recording_span)
    monkeypatch.setattr(trace, "get_tracer", lambda name: tracer)

    create_opentelemetry_callback(span_name="custom.authorization")(sample_event())

    assert tracer.names == ["custom.authorization"]
    assert span.events[0][0] == "authorization.decision"


def test_opentelemetry_callback_gives_install_guidance_if_optional_api_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_import = builtins.__import__

    def import_without_otel(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "opentelemetry":
            raise ImportError("blocked for test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_without_otel)

    with pytest.raises(ImportError, match="langgraph-secure-agents\\[opentelemetry\\]"):
        create_opentelemetry_callback()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"include_sensitive": 1},
        {"span_name": ""},
    ],
)
def test_opentelemetry_callback_rejects_invalid_configuration(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        create_opentelemetry_callback(**kwargs)  # type: ignore[arg-type]
