from __future__ import annotations

from pathlib import Path

import pytest

from langgraph_secure_agents import (
    AuthorizationDenied,
    Effect,
    PolicyBundle,
    PolicyRegistry,
    PolicyRule,
    PolicyUpdateConflict,
    Principal,
    protect_callable,
)


def bundle(version: str, role: str = "analyst", *, policy_id: str = "finance") -> PolicyBundle:
    return PolicyBundle(
        policy_id=policy_id,
        version=version,
        description="Test policy",
        rules=(
            PolicyRule(
                rule_id="allow-report",
                effect=Effect.ALLOW,
                actions=frozenset({"read"}),
                resources=frozenset({"report"}),
                roles=frozenset({role}),
            ),
        ),
    )


def test_publish_swaps_one_complete_snapshot_and_checks_generation() -> None:
    registry = PolicyRegistry(bundle("1.0.0"))
    original = registry.snapshot()
    published = registry.publish(bundle("1.1.0", "manager"), expected_generation=1)

    assert original.generation == 1
    assert original.version == "1.0.0"
    assert published.generation == 2
    assert published.version == "1.1.0"
    assert published.digest == published.bundle.digest
    assert registry.snapshot() is published

    with pytest.raises(PolicyUpdateConflict, match="expected policy generation"):
        registry.publish(bundle("1.2.0"), expected_generation=1)


def test_registry_rejects_policy_id_changes_and_version_reuse() -> None:
    registry = PolicyRegistry(bundle("1.0.0"))
    with pytest.raises(ValueError, match="policy_id"):
        registry.publish(bundle("1.1.0", policy_id="other"))

    registry.publish(bundle("2.0.0", "manager"))
    with pytest.raises(ValueError, match="version cannot be reused"):
        registry.publish(bundle("1.0.0", "guest"))


def test_identical_reload_is_a_no_op_and_history_is_bounded() -> None:
    registry = PolicyRegistry(bundle("1.0.0"), history_limit=2)
    initial = registry.snapshot()
    assert registry.publish(bundle("1.0.0")) is initial

    registry.publish(bundle("1.1.0"))
    registry.publish(bundle("1.2.0"))
    registry.publish(bundle("1.3.0"))

    assert registry.snapshot().generation == 4
    assert [item.version for item in registry.history] == ["1.1.0", "1.2.0"]


def test_rollback_publishes_old_bundle_as_a_new_generation() -> None:
    registry = PolicyRegistry(bundle("1.0.0"))
    registry.publish(bundle("1.1.0", "manager"))
    rolled_back = registry.rollback(expected_generation=2)

    assert rolled_back.version == "1.0.0"
    assert rolled_back.generation == 3
    assert registry.snapshot() is rolled_back
    assert registry.history == ()

    with pytest.raises(RuntimeError, match="no previous policy"):
        registry.rollback()
    with pytest.raises(PolicyUpdateConflict):
        registry.publish(bundle("2.0.0"), expected_generation=2)


def test_reload_reads_validated_file_and_preserves_current_on_invalid_input(
    tmp_path: Path,
) -> None:
    registry = PolicyRegistry(bundle("1.0.0"))
    file_path = tmp_path / "policy.json"
    file_path.write_text(bundle("1.2.0", "manager").to_json(), encoding="utf-8")

    snapshot = registry.reload(file_path, expected_generation=1)
    assert snapshot.version == "1.2.0"
    assert snapshot.generation == 2

    file_path.write_text('{"schema_version": 999}', encoding="utf-8")
    with pytest.raises(ValueError):
        registry.reload(file_path, expected_generation=2)
    assert registry.snapshot() is snapshot


@pytest.mark.parametrize("history_limit", [0, -1, True, 1.5])
def test_registry_rejects_invalid_history_limit(history_limit: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        PolicyRegistry(bundle("1.0.0"), history_limit=history_limit)  # type: ignore[arg-type]


@pytest.mark.parametrize("expected_generation", [0, -1, True, 1.5])
def test_registry_rejects_invalid_expected_generation(expected_generation: object) -> None:
    registry = PolicyRegistry(bundle("1.0.0"))
    with pytest.raises(ValueError, match="expected_generation"):
        registry.publish(
            bundle("1.1.0"),
            expected_generation=expected_generation,  # type: ignore[arg-type]
        )


def test_callable_guard_observes_policy_reload_and_audits_active_version() -> None:
    registry = PolicyRegistry(bundle("1.0.0"))
    events = []
    calls = []

    def read_report() -> str:
        calls.append("executed")
        return "report"

    protected = protect_callable(
        read_report,
        policy=registry,
        principal_resolver=lambda: Principal("alice", roles=frozenset({"analyst"})),
        action="read",
        resource_resolver=lambda: "report",
        audit_event_callback=events.append,
    )
    assert protected() == "report"

    registry.publish(bundle("1.1.0", "manager"))
    with pytest.raises(AuthorizationDenied):
        protected()

    assert calls == ["executed"]
    assert [event.policy_version for event in events] == ["1.0.0", "1.1.0"]
    assert [event.policy_digest for event in events] == [
        bundle("1.0.0").digest,
        bundle("1.1.0", "manager").digest,
    ]


def test_concurrent_compare_and_swap_allows_only_one_policy_writer() -> None:
    from concurrent.futures import ThreadPoolExecutor

    registry = PolicyRegistry(bundle("1.0.0"))

    def publish(version: str) -> str:
        try:
            registry.publish(bundle(version), expected_generation=1)
            return "published"
        except PolicyUpdateConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(publish, ("1.1.0", "1.2.0")))

    assert results.count("published") == 1
    assert results.count("conflict") == 1
    assert registry.snapshot().generation == 2
