"""Durable SQLite audit sink with a verifiable append-only hash chain."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import cast

from .audit import AuditEvent

_GENESIS_HASH = "0" * 64


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """One persisted audit record and its hash-chain metadata."""

    sequence: int
    event_id: str
    payload: dict[str, object]
    previous_hash: str
    entry_hash: str


class SQLiteAuditSink:
    """Synchronous, durable audit callback backed by SQLite.

    Each append is committed before the callback returns. The hash chain detects
    modification, deletion, and reordering of individual records unless an actor
    can rewrite the complete database and recompute every hash. For stronger
    adversarial guarantees, periodically anchor exported chain heads in a separately
    controlled system. Records are not automatically pruned because deletion would
    break the retained chain; archive/retention policy belongs to the operator.
    """

    def __init__(
        self,
        database: str | Path,
        *,
        include_sensitive: bool = False,
        timeout: float = 5.0,
    ) -> None:
        if not isinstance(database, (str, Path)) or not str(database).strip():
            raise ValueError("database must be a non-empty path")
        if type(include_sensitive) is not bool:
            raise ValueError("include_sensitive must be a boolean")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise ValueError("timeout must be a finite non-negative number")
        if not math.isfinite(timeout) or timeout < 0:
            raise ValueError("timeout must be a finite non-negative number")

        self._include_sensitive = include_sensitive
        self._lock = RLock()
        self._connection = sqlite3.connect(
            str(database),
            timeout=float(timeout),
            isolation_level=None,
            check_same_thread=False,
        )
        self._connection.execute(f"PRAGMA busy_timeout = {int(timeout * 1000)}")
        if str(database) != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = FULL")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS audit_records (
                sequence INTEGER PRIMARY KEY,
                event_id TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL UNIQUE
            );
            """
        )

    @staticmethod
    def _entry_hash(sequence: int, previous_hash: str, payload_json: str) -> str:
        material = f"{sequence}\n{previous_hash}\\n{payload_json}".encode("utf-8")
        return hashlib.sha256(material).hexdigest()

    def __call__(self, event: AuditEvent) -> None:
        """Persist one event; suitable for the audit_event_callback parameter."""

        self.append(event)

    def append(self, event: AuditEvent) -> AuditRecord:
        """Append and commit an audit event, raising on persistence failure."""

        if not isinstance(event, AuditEvent):
            raise TypeError("event must be an AuditEvent instance")
        payload_json = event.to_json(include_sensitive=self._include_sensitive)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                last = self._connection.execute(
                    "SELECT sequence, entry_hash FROM audit_records "
                    "ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                sequence = 1 if last is None else int(last[0]) + 1
                previous_hash = _GENESIS_HASH if last is None else str(last[1])
                entry_hash = self._entry_hash(sequence, previous_hash, payload_json)
                self._connection.execute(
                    """
                    INSERT INTO audit_records
                        (sequence, event_id, timestamp, payload_json, previous_hash, entry_hash)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sequence,
                        event.event_id,
                        event.timestamp.isoformat().replace("+00:00", "Z"),
                        payload_json,
                        previous_hash,
                        entry_hash,
                    ),
                )
                self._connection.execute("COMMIT")
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise

        return AuditRecord(
            sequence=sequence,
            event_id=event.event_id,
            payload=cast(dict[str, object], json.loads(payload_json)),
            previous_hash=previous_hash,
            entry_hash=entry_hash,
        )

    def records(self, *, after_sequence: int = 0, limit: int = 100) -> tuple[AuditRecord, ...]:
        """Read an ordered page of records without changing the stored chain."""

        if isinstance(after_sequence, bool) or not isinstance(after_sequence, int) or after_sequence < 0:
            raise ValueError("after_sequence must be a non-negative integer")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")

        with self._lock:
            rows = self._connection.execute(
                """
                SELECT sequence, event_id, payload_json, previous_hash, entry_hash
                FROM audit_records
                WHERE sequence > ?
                ORDER BY sequence ASC
                LIMIT ?
                """,
                (after_sequence, limit),
            ).fetchall()

        result: list[AuditRecord] = []
        for sequence, event_id, payload_json, previous_hash, entry_hash in rows:
            payload = json.loads(str(payload_json))
            if not isinstance(payload, dict):
                raise ValueError("stored audit payload must be a JSON object")
            result.append(
                AuditRecord(
                    sequence=int(sequence),
                    event_id=str(event_id),
                    payload=cast(dict[str, object], payload),
                    previous_hash=str(previous_hash),
                    entry_hash=str(entry_hash),
                )
            )
        return tuple(result)

    @property
    def count(self) -> int:
        """Return the number of retained records."""

        with self._lock:
            row = self._connection.execute("SELECT COUNT(*) FROM audit_records").fetchone()
            return 0 if row is None else int(row[0])

    def verify_integrity(self) -> bool:
        """Verify sequence continuity, event metadata, and every link in the chain."""

        with self._lock:
            rows = self._connection.execute(
                """
                SELECT sequence, event_id, timestamp, payload_json, previous_hash, entry_hash
                FROM audit_records
                ORDER BY sequence ASC
                """
            ).fetchall()

        previous_hash = _GENESIS_HASH
        expected_sequence = 1
        for sequence, event_id, timestamp, payload_json, stored_previous, stored_hash in rows:
            sequence = int(sequence)
            payload_json = str(payload_json)
            if sequence != expected_sequence or str(stored_previous) != previous_hash:
                return False
            try:
                payload = json.loads(payload_json)
            except (TypeError, ValueError):
                return False
            if (
                not isinstance(payload, dict)
                or payload.get("event_id") != str(event_id)
                or payload.get("timestamp") != str(timestamp)
            ):
                return False
            expected_hash = self._entry_hash(sequence, previous_hash, payload_json)
            if not hmac.compare_digest(expected_hash, str(stored_hash)):
                return False
            previous_hash = expected_hash
            expected_sequence += 1
        return True

    def close(self) -> None:
        """Close the underlying SQLite connection."""

        with self._lock:
            self._connection.close()
