from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from langgraph_secure_agents import (
    AuditEvent,
    DecisionReason,
    SQLiteAuditSink,
)


def sample_event(event_id: str = "event-1") -> AuditEvent:
    return AuditEvent(
        principal_id="alice",
        principal_roles=("analyst",),
        action="read",
        resource="payroll:7",
        decision_reason=DecisionReason.EXPLICIT_ALLOW,
        allowed=True,
        requires_approval=False,
        matched_rule_ids=("read-payroll",),
        event_id=event_id,
        timestamp=datetime(2026, 10, 24, 12, 30, tzinfo=UTC),
    )


def test_sink_persists_hash_chained_records_and_redacts_by_default(tmp_path: Path) -> None:
    database = tmp_path / "audit.sqlite3"
    sink = SQLiteAuditSink(database)
    first = sink.append(sample_event("event-1"))
    second = sink.append(sample_event("event-2"))

    assert first.sequence == 1
    assert first.previous_hash == "0" * 64
    assert second.sequence == 2
    assert second.previous_hash == first.entry_hash
    assert sink.count == 2
    assert sink.verify_integrity()
    assert "principal_id" not in first.payload
    assert "alice" not in str(first.payload)
    assert [record.event_id for record in sink.records(limit=1)] == ["event-1"]
    assert [record.event_id for record in sink.records(after_sequence=1)] == ["event-2"]
    sink.close()

    reopened = SQLiteAuditSink(database)
    assert reopened.count == 2
    assert reopened.verify_integrity()
    reopened.close()


def test_sink_can_be_used_as_a_callback_and_opt_into_sensitive_fields() -> None:
    sink = SQLiteAuditSink(":memory:", include_sensitive=True)
    sink(sample_event())

    record = sink.records()[0]
    assert record.payload["principal_id"] == "alice"
    assert record.payload["resource"] == "payroll:7"
    assert sink.verify_integrity()
    sink.close()


def test_integrity_verification_detects_tampering(tmp_path: Path) -> None:
    database = tmp_path / "tamper.sqlite3"
    sink = SQLiteAuditSink(database)
    sink.append(sample_event())
    assert sink.verify_integrity()
    sink.close()

    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE audit_records SET payload_json = ? WHERE sequence = 1",
            ('{"event_id":"event-1","timestamp":"2026-10-24T12:30:00Z"}',),
        )

    tampered = SQLiteAuditSink(database)
    assert tampered.verify_integrity() is False
    tampered.close()


def test_duplicate_event_id_fails_without_corrupting_existing_chain() -> None:
    sink = SQLiteAuditSink(":memory:")
    sink.append(sample_event("same-event"))
    with pytest.raises(sqlite3.IntegrityError):
        sink.append(sample_event("same-event"))
    assert sink.count == 1
    assert sink.verify_integrity()
    sink.close()


def test_empty_chain_is_valid_and_bad_payload_is_reported(tmp_path: Path) -> None:
    database = tmp_path / "bad-payload.sqlite3"
    sink = SQLiteAuditSink(database)
    assert sink.verify_integrity()
    sink.append(sample_event("event-1"))
    sink.close()

    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE audit_records SET payload_json = ? WHERE sequence = 1",
            ("[]",),
        )

    tampered = SQLiteAuditSink(database)
    assert tampered.verify_integrity() is False
    with pytest.raises(ValueError, match="JSON object"):
        tampered.records()
    tampered.close()


@pytest.mark.parametrize(
    ("after_sequence", "limit"),
    [(-1, 1), (True, 1), (0, 0), (0, True), (1.5, 2)],
)
def test_records_reject_invalid_pagination(
    after_sequence: int,
    limit: int,
) -> None:
    sink = SQLiteAuditSink(":memory:")
    with pytest.raises(ValueError):
        sink.records(after_sequence=after_sequence, limit=limit)
    sink.close()


@pytest.mark.parametrize(
    ("database", "include_sensitive", "timeout"),
    [
        ("", False, 5.0),
        (":memory:", 1, 5.0),
        (":memory:", False, -1.0),
        (":memory:", False, float("inf")),
        (":memory:", False, True),
    ],
)
def test_sink_rejects_invalid_configuration(
    database: str,
    include_sensitive: bool,
    timeout: float,
) -> None:
    with pytest.raises(ValueError):
        SQLiteAuditSink(database, include_sensitive=include_sensitive, timeout=timeout)


def test_append_rejects_non_audit_event() -> None:
    sink = SQLiteAuditSink(":memory:")
    with pytest.raises(TypeError, match="AuditEvent"):
        sink.append("not-an-event")  # type: ignore[arg-type]
    sink.close()


def test_concurrent_appends_preserve_a_contiguous_valid_hash_chain() -> None:
    from concurrent.futures import ThreadPoolExecutor

    sink = SQLiteAuditSink(":memory:")

    def append(index: int) -> None:
        sink.append(sample_event(f"event-{index}"))

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(append, range(40)))

    records = sink.records(limit=100)
    assert sink.count == 40
    assert len(records) == 40
    assert [record.sequence for record in records] == list(range(1, 41))
    assert len({record.event_id for record in records}) == 40
    assert all(
        record.previous_hash == ("0" * 64 if index == 0 else records[index - 1].entry_hash)
        for index, record in enumerate(records)
    )
    assert sink.verify_integrity()
    sink.close()


@pytest.mark.parametrize(
    ("payload_json", "failure"),
    [
        ("not-json", "invalid-json"),
        ("[]", "not-object"),
        ('{"event_id":"wrong-id","timestamp":"2026-10-24T12:30:00Z"}', "event-id"),
        ('{"event_id":"event-1","timestamp":"2026-10-24T12:30:01Z"}', "timestamp"),
    ],
)
def test_integrity_verification_rejects_malformed_or_mismatched_payloads(
    tmp_path: Path,
    payload_json: str,
    failure: str,
) -> None:
    database = tmp_path / f"invalid-{failure}.sqlite3"
    sink = SQLiteAuditSink(database)
    sink.append(sample_event("event-1"))
    sink.close()

    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE audit_records SET payload_json = ? WHERE sequence = 1",
            (payload_json,),
        )

    tampered = SQLiteAuditSink(database)
    assert tampered.verify_integrity() is False
    tampered.close()
