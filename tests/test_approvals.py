from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from langgraph_secure_agents import SQLiteApprovalStore


def test_grant_is_bound_to_fingerprint_and_reviewer_and_is_single_use(
    tmp_path: Path,
) -> None:
    database = tmp_path / "approvals.sqlite3"
    store = SQLiteApprovalStore(database)
    token = store.issue("fingerprint-a", "reviewer-1")

    assert store.consume(token, "fingerprint-b", "reviewer-1") is False
    assert store.consume(token, "fingerprint-a", "reviewer-2") is False
    assert store.consume(token, "fingerprint-a", "reviewer-1") is True
    assert store.consume(token, "fingerprint-a", "reviewer-1") is False

    with sqlite3.connect(database) as connection:
        stored_hash = connection.execute("SELECT token_hash FROM approval_grants").fetchone()[0]
    assert stored_hash != token
    store.close()


def test_grant_expiry_and_purge_use_utc_clock(tmp_path: Path) -> None:
    current = [datetime(2026, 10, 24, 12, 0, tzinfo=UTC)]
    store = SQLiteApprovalStore(tmp_path / "expiry.sqlite3", clock=lambda: current[0])
    token = store.issue("fingerprint-expiry", "reviewer", ttl=timedelta(seconds=10))

    current[0] += timedelta(seconds=10)
    assert store.consume(token, "fingerprint-expiry", "reviewer") is False
    assert store.purge_expired() == 1
    assert store.purge_expired() == 0
    store.close()


def test_only_one_concurrent_consumer_can_use_a_grant(tmp_path: Path) -> None:
    store = SQLiteApprovalStore(tmp_path / "concurrent.sqlite3")
    token = store.issue("fingerprint-concurrent", "reviewer")

    def consume() -> bool:
        return store.consume(token, "fingerprint-concurrent", "reviewer")

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda _: consume(), range(24)))

    assert sum(results) == 1
    store.close()


def test_duplicate_fingerprint_cannot_receive_a_second_grant(tmp_path: Path) -> None:
    store = SQLiteApprovalStore(tmp_path / "duplicate.sqlite3")
    store.issue("same-fingerprint", "reviewer")
    with pytest.raises(ValueError, match="already exists"):
        store.issue("same-fingerprint", "reviewer")
    store.close()


@pytest.mark.parametrize("ttl", [timedelta(0), timedelta(seconds=-1), 10, None])
def test_issue_rejects_invalid_ttl(tmp_path: Path, ttl: object) -> None:
    store = SQLiteApprovalStore(tmp_path / "ttl.sqlite3")
    with pytest.raises(ValueError, match="ttl"):
        store.issue("fingerprint", "reviewer", ttl=ttl)  # type: ignore[arg-type]
    store.close()


@pytest.mark.parametrize(
    ("database", "timeout"),
    [
        ("", 5.0),
        (":memory:", -1.0),
        (":memory:", float("nan")),
        (":memory:", True),
    ],
)
def test_store_rejects_invalid_configuration(database: str, timeout: float) -> None:
    with pytest.raises(ValueError):
        SQLiteApprovalStore(database, timeout=timeout)


def test_store_rejects_naive_clock_and_invalid_identifiers(tmp_path: Path) -> None:
    naive = SQLiteApprovalStore(
        tmp_path / "naive.sqlite3",
        clock=lambda: datetime(2026, 10, 24, 12, 0),
    )
    with pytest.raises(ValueError, match="timezone-aware"):
        naive.issue("fingerprint", "reviewer")
    naive.close()

    store = SQLiteApprovalStore(tmp_path / "validation.sqlite3")
    with pytest.raises(ValueError, match="request_fingerprint"):
        store.issue("", "reviewer")
    with pytest.raises(ValueError, match="reviewer_id"):
        store.issue("fingerprint", "")
    with pytest.raises(ValueError, match="request_fingerprint"):
        store.consume("token", "", "reviewer")
    with pytest.raises(ValueError, match="reviewer_id"):
        store.consume("token", "fingerprint", "")
    assert store.consume("", "fingerprint", "reviewer") is False
    store.close()

def test_database_failures_propagate_and_transactions_are_rolled_back(
    tmp_path: Path,
) -> None:
    issue_store = SQLiteApprovalStore(tmp_path / "issue-failure.sqlite3")
    issue_store._connection.execute("DROP TABLE approval_grants")
    with pytest.raises(sqlite3.OperationalError, match="no such table"):
        issue_store.issue("fingerprint-1", "reviewer-1")
    assert issue_store._connection.in_transaction is False
    issue_store.close()

    consume_store = SQLiteApprovalStore(":memory:")
    consume_store._connection.execute("DROP TABLE approval_grants")
    with pytest.raises(sqlite3.OperationalError, match="no such table"):
        consume_store.consume("opaque-token", "fingerprint-2", "reviewer-2")
    assert consume_store._connection.in_transaction is False
    consume_store.close()
