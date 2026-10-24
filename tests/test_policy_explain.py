from __future__ import annotations

import json

import pytest

from langgraph_secure_agents import (
    AccessRequest,
    AttributeCondition,
    ConditionOperator,
    Effect,
    PolicyEngine,
    PolicyRule,
    Principal,
)


def test_explain_reports_decision_and_condition_results_without_values() -> None:
    engine = PolicyEngine(
        [
            PolicyRule(
                rule_id="allow-analysts-in-prod",
                effect=Effect.ALLOW,
                actions=frozenset({"read"}),
                resources=frozenset({"reports"}),
                roles=frozenset({"analyst"}),
                conditions=(
                    AttributeCondition("context.environment", ConditionOperator.EQ, "prod"),
                    AttributeCondition(
                        "principal.attributes.clearance",
                        ConditionOperator.EQ,
                        "high",
                    ),
                ),
            ),
            PolicyRule(
                rule_id="deny-admins",
                effect=Effect.DENY,
                actions=frozenset({"read"}),
                resources=frozenset({"reports"}),
                roles=frozenset({"admin"}),
            ),
        ]
    )
    request = AccessRequest(
        principal=Principal(
            "private-user-id",
            roles=frozenset({"analyst"}),
            attributes={"clearance": "high"},
        ),
        action="read",
        resource="reports",
        context={"environment": "prod"},
    )

    explanation = engine.explain(request)

    assert explanation.decision == engine.evaluate(request)
    assert explanation.decision.allowed
    assert explanation.rules[0].matched
    assert explanation.rules[0].reason == "matched"
    assert [condition.matched for condition in explanation.rules[0].conditions] == [True, True]
    assert not explanation.rules[1].selectors_match
    assert explanation.rules[1].conditions == ()
    assert explanation.rules[1].reason == "selector_mismatch"

    encoded = json.dumps(explanation.to_dict())
    assert "private-user-id" not in encoded
    assert '"prod"' not in encoded
    assert '"high"' not in encoded


def test_explain_identifies_failed_condition_without_revealing_value() -> None:
    engine = PolicyEngine(
        [
            PolicyRule(
                rule_id="requires-production",
                effect=Effect.ALLOW,
                actions=frozenset({"read"}),
                resources=frozenset({"reports"}),
                roles=frozenset({"analyst"}),
                conditions=(
                    AttributeCondition("context.environment", ConditionOperator.EQ, "prod"),
                ),
            )
        ]
    )
    request = AccessRequest(
        principal=Principal("alice", roles=frozenset({"analyst"})),
        action="read",
        resource="reports",
        context={"environment": "development-secret"},
    )

    explanation = engine.explain(request)

    assert not explanation.decision.allowed
    assert explanation.rules[0].selectors_match
    assert not explanation.rules[0].matched
    assert explanation.rules[0].reason == "condition_failed"
    assert explanation.rules[0].conditions[0].attribute == "context.environment"
    assert not explanation.rules[0].conditions[0].matched
    assert "development-secret" not in json.dumps(explanation.to_dict())


def test_explain_rejects_non_access_request() -> None:
    with pytest.raises(TypeError, match="AccessRequest instance"):
        PolicyEngine().explain("not-a-request")  # type: ignore[arg-type]
