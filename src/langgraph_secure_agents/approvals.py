"""Durable, single-use approval grants backed by SQLite."""

from __future__ import annotations

import hashlib
import math
import secrets
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import RLock
from typing import Protocol


class ApprovalStore(Protocol):
    """Minimal contract used by enforcement middleware for one-time consumption."""

    def consume(self, token: str, request_fingerprint: str, reviewer_id: str) -> bool:
        """Atomically consume a grant bound to this request and reviewer."""


Clock = Callable[[], datetime]


def _required_text(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value.strip()


def _utc_now(clock: Clock) -> datetime:
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("clock must return a timezone-aware datetime")
    return value.astimezone(UTC)


class SQLiteApprovalStore:
    """Persistent approval-token store with expiry and atomic one-time use.

    The raw bearer token is returned only by :meth:`issue`; only its SHA-256
    digest is persisted. The request fingerprint is unique for the lifetime of
    the database, so a consumed or expired grant cannot be reissued for the same
    operation. Callers must authenticate the reviewer before issuing a grant and
    supply that same trusted reviewer identity when consuming it.
    """

    def __init__(
        self,
        database: str | Path,
        *,
        timeout: float = 5.0,
        clock: Clock | None = None,
    ) -> None:
        if not isinstance(database, (str, Path)) or not str(database).strip():
            raise ValueError("database must be a non-empty path")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise ValueError("timeout must be a finite non-negative number")
        if not math.isfinite(timeout) or timeout < 0:
            raise ValueError("timeout must be a finite non-negative number")

        self._clock = clock or (lambda: datetime.now(UTC))
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
            CREATE TABLE IF NOT EXISTS approval_grants (
                token_hash TEXT PRIMARY KEY,
                request_fingerprint TEXT NOT NULL UNIQUE,
                reviewer_id TEXT NOT NULL,
                issued_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                consumed_at REAL
            );
            CREATE INDEX IF NOT EXISTS approval_grants_expiry
                ON approval_grants(expires_at);
            """
        )

    def issue(
        self,
        request_fingerprint: str,
        reviewer_id: str,
        *,
        ttl: timedelta = timedelta(minutes=5),
    ) -> str:
        """Issue a one-time opaque token after the caller authenticates approval."""

        fingerprint = _required_text(request_fingerprint, "request_fingerprint")
        reviewer = _required_text(reviewer_id, "reviewer_id")
        if not isinstance(ttl, timedelta) or ttl <= timedelta(0):
            raise ValueError("ttl must be a positive timedelta")

        now = _utc_now(self._clock).timestamp()
        expires_at = now + ttl.total_seconds()
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._connection.execute(
                    """
                    INSERT INTO approval_grants
                        (token_hash, request_fingerprint, reviewer_id, issued_at, expires_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (token_hash, fingerprint, reviewer, now, expires_at),
                )
                self._connection.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                self._connection.execute("ROLLBACK")
                raise ValueError(
                    "an approval grant already exists for this request fingerprint"
                ) from exc
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise
        return token

    def consume(self, token: str, request_fingerprint: str, reviewer_id: str) -> bool:
        """Atomically consume a matching, unexpired grant exactly once.

        A false result intentionally does not reveal whether the token was
        unknown, expired, already consumed, or bound to another reviewer/request.
        Database errors propagate so enforcement can fail closed.
        """

        if not isinstance(token, str) or not token:
            return False
        fingerprint = _required_text(request_fingerprint, "request_fingerprint")
        reviewer = _required_text(reviewer_id, "reviewer_id")
        now = _utc_now(self._clock).timestamp()
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                cursor = self._connection.execute(
                    """
                    UPDATE approval_grants
                    SET consumed_at = ?
                    WHERE token_hash = ?
                      AND request_fingerprint = ?
                      AND reviewer_id = ?
                      AND consumed_at IS NULL
                      AND issued_at <= ?
                      AND expires_at > ?
                    """,
                    (now, token_hash, fingerprint, reviewer, now, now),
                )
                consumed = cursor.rowcount == 1
                self._connection.execute("COMMIT")
                return consumed
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise

    def purge_expired(self) -> int:
        """Delete expired grants; this never makes an expired token usable again."""

        now = _utc_now(self._clock).timestamp()
        with self._lock:
            cursor = self._connection.execute(
                "DELETE FROM approval_grants WHERE expires_at <= ?",
                (now,),
            )
            return cursor.rowcount

    def close(self) -> None:
        """Close the underlying SQLite connection."""

        with self._lock:
            self._connection.close()

