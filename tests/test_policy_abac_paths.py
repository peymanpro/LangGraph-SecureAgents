from __future__ import annotations

from langgraph_secure_agents import (
    AccessRequest,
    AttributeCondition,
    ConditionOperator,
    Effect,
    PolicyEngine,
    PolicyRule,
    Principal,
)


def test_abac_can_reference_authenticated_identity_roles_and_resource_id() -> None:
    policy = PolicyEngine(
        [
            PolicyRule(
                rule_id="alice-reads-her-report",
                effect=Effect.ALLOW,
                actions=frozenset({"read"}),
                resources=frozenset({"reports"}),
                roles=frozenset({"analyst"}),
                conditions=(
                    AttributeCondition(
                        "principal.principal_id",
                        ConditionOperator.EQ,
                        "alice",
                    ),
                    AttributeCondition(
                        "principal.roles",
                        ConditionOperator.CONTAINS,
                        "analyst",
                    ),
                    AttributeCondition(
                        "resource.id",
                        ConditionOperator.EQ,
                        "reports",
                    ),
                ),
            )
        ]
    )
    request = AccessRequest(
        principal=Principal("alice", roles=frozenset({"analyst"})),
        action="read",
        resource="reports",
    )

    assert policy.evaluate(request).allowed


def test_numeric_equality_accepts_int_and_float_without_bool_coercion() -> None:
    policy = PolicyEngine(
        [
            PolicyRule(
                rule_id="risk-threshold",
                effect=Effect.ALLOW,
                actions=frozenset({"read"}),
                resources=frozenset({"reports"}),
                roles=frozenset({"analyst"}),
                conditions=(AttributeCondition("context.risk_score", ConditionOperator.EQ, 1.0),),
            )
        ]
    )
    request = AccessRequest(
        principal=Principal("alice", roles=frozenset({"analyst"})),
        action="read",
        resource="reports",
        context={"risk_score": 1},
    )

    assert policy.evaluate(request).allowed


def test_contains_rejects_scalar_container_types() -> None:
    policy = PolicyEngine(
        [
            PolicyRule(
                rule_id="invalid-container",
                effect=Effect.ALLOW,
                actions=frozenset({"read"}),
                resources=frozenset({"reports"}),
                roles=frozenset({"analyst"}),
                conditions=(
                    AttributeCondition("context.value", ConditionOperator.CONTAINS, "read"),
                ),
            )
        ]
    )
    request = AccessRequest(
        principal=Principal("alice", roles=frozenset({"analyst"})),
        action="read",
        resource="reports",
        context={"value": 7},
    )

    assert not policy.evaluate(request).allowed
