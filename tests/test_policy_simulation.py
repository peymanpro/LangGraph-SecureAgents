from __future__ import annotations

import json

import pytest

from langgraph_secure_agents import (
    AccessRequest,
    Effect,
    PolicyRule,
    Principal,
)
from langgraph_secure_agents.bundle import PolicyBundle


def bundle_with_rules(version: str, rules: tuple[PolicyRule, ...]) -> PolicyBundle:
    return PolicyBundle(policy_id="payroll", version=version, rules=rules)


def analyst_read_rule() -> PolicyRule:
    return PolicyRule(
        rule_id="analysts-read-reports",
        effect=Effect.ALLOW,
        actions=frozenset({"read"}),
        resources=frozenset({"reports"}),
        roles=frozenset({"analyst"}),
    )


def requests() -> tuple[AccessRequest, ...]:
    return (
        AccessRequest(
            principal=Principal("user-private-1", roles=frozenset({"analyst"})),
            action="read",
            resource="reports",
        ),
        AccessRequest(
            principal=Principal("user-private-2", roles=frozenset({"analyst"})),
            action="delete",
            resource="payroll",
        ),
        AccessRequest(
            principal=Principal("user-private-3", roles=frozenset({"guest"})),
            action="read",
            resource="reports",
        ),
        AccessRequest(
            principal=Principal("user-private-4", roles=frozenset({"analyst"})),
            action="read",
            resource="payroll",
        ),
    )


def test_simulate_reports_candidate_outcomes_and_aggregate_counts() -> None:
    candidate = bundle_with_rules(
        "1.1.0",
        (
            analyst_read_rule(),
            PolicyRule(
                rule_id="deny-analyst-payroll",
                effect=Effect.DENY,
                actions=frozenset({"read"}),
                resources=frozenset({"payroll"}),
                roles=frozenset({"analyst"}),
            ),
            PolicyRule(
                rule_id="approval-for-payroll-delete",
                effect=Effect.REQUIRE_APPROVAL,
                actions=frozenset({"delete"}),
                resources=frozenset({"payroll"}),
                roles=frozenset({"analyst"}),
            ),
        ),
    )

    report = candidate.simulate(requests())

    assert report.total == 4
    assert report.allowed == 1
    assert report.denied == 2
    assert report.approval_required == 1
    assert report.changed == 0
    assert [case.index for case in report.cases] == [0, 1, 2, 3]
    assert report.cases[0].decision.allowed
    assert report.cases[1].decision.requires_approval
    assert report.cases[2].decision.reason.value == "default_deny"
    assert report.cases[3].decision.reason.value == "explicit_deny"
    assert all(case.baseline_decision is None for case in report.cases)
    assert all(case.changed is None for case in report.cases)


def test_simulate_compares_candidate_with_baseline() -> None:
    baseline = bundle_with_rules("1.0.0", (analyst_read_rule(),))
    candidate = bundle_with_rules(
        "1.1.0",
        (
            analyst_read_rule(),
            PolicyRule(
                rule_id="deny-analyst-payroll",
                effect=Effect.DENY,
                actions=frozenset({"read"}),
                resources=frozenset({"payroll"}),
                roles=frozenset({"analyst"}),
            ),
            PolicyRule(
                rule_id="approval-for-payroll-delete",
                effect=Effect.REQUIRE_APPROVAL,
                actions=frozenset({"delete"}),
                resources=frozenset({"payroll"}),
                roles=frozenset({"analyst"}),
            ),
        ),
    )

    report = candidate.simulate(requests(), baseline=baseline)

    assert report.baseline_policy_id == baseline.policy_id
    assert report.baseline_version == "1.0.0"
    assert report.baseline_digest == baseline.digest
    assert report.allowed == 1
    assert report.denied == 2
    assert report.approval_required == 1
    assert report.changed == 1
    assert report.cases[0].changed is False
    assert report.cases[1].changed is True
    assert report.cases[2].changed is False
    assert report.cases[3].changed is False


def test_simulation_report_serializes_summaries_without_sensitive_requests() -> None:
    candidate = bundle_with_rules("1.0.0", (analyst_read_rule(),))
    report = candidate.simulate(requests())

    encoded = json.dumps(report.to_dict())

    assert '"total": 4' in encoded
    assert '"allowed": 1' in encoded
    assert '"denied": 3' in encoded
    assert "user-private-" not in encoded
    assert "reports" not in encoded


def test_bundle_explain_delegates_to_policy_engine() -> None:
    bundle = bundle_with_rules("1.0.0", (analyst_read_rule(),))

    explanation = bundle.explain(requests()[0])

    assert explanation.decision.allowed
    assert explanation.rules[0].matched


def test_simulation_rejects_invalid_baseline_and_request_collections() -> None:
    candidate = bundle_with_rules("1.0.0", (analyst_read_rule(),))

    with pytest.raises(TypeError, match="baseline must be a PolicyBundle"):
        candidate.simulate(requests(), baseline="not-a-bundle")  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="iterable of AccessRequest"):
        candidate.simulate("not-requests")  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="iterable of AccessRequest"):
        candidate.simulate(42)  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="AccessRequest instance"):
        candidate.simulate([object()])  # type: ignore[list-item]
