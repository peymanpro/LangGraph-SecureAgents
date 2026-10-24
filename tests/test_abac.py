from __future__ import annotations

import pytest

from langgraph_secure_agents import (
    AccessRequest,
    AttributeCondition,
    AttributeReference,
    ConditionOperator,
    DecisionReason,
    Effect,
    PolicyEngine,
    PolicyRule,
    Principal,
)


def allow_rule(*conditions: AttributeCondition) -> PolicyRule:
    return PolicyRule(
        rule_id="allow-conditional-read",
        effect=Effect.ALLOW,
        actions=frozenset({"read"}),
        resources=frozenset({"*"}),
        roles=frozenset({"analyst"}),
        conditions=conditions,
    )


def request(
    *,
    principal_attributes: dict[str, object] | None = None,
    resource_attributes: dict[str, object] | None = None,
    context: dict[str, object] | None = None,
) -> AccessRequest:
    return AccessRequest(
        principal=Principal(
            "alice",
            roles=frozenset({"analyst"}),
            attributes=principal_attributes or {},
        ),
        action="read",
        resource="document:42",
        resource_attributes=resource_attributes or {},
        context=context or {},
    )


def test_abac_allows_matching_tenant_using_attribute_reference() -> None:
    policy = PolicyEngine(
        [
            allow_rule(
                AttributeCondition(
                    "principal.attributes.tenant_id",
                    ConditionOperator.EQ,
                    AttributeReference("resource.attributes.tenant_id"),
                )
            )
        ]
    )

    decision = policy.evaluate(
        request(
            principal_attributes={"tenant_id": "tenant-a"},
            resource_attributes={"tenant_id": "tenant-a"},
        )
    )

    assert decision.allowed
    assert decision.matched_rule_ids == ("allow-conditional-read",)


def test_abac_denies_cross_tenant_resource_even_when_role_matches() -> None:
    policy = PolicyEngine(
        [
            allow_rule(
                AttributeCondition(
                    "principal.attributes.tenant_id",
                    ConditionOperator.EQ,
                    AttributeReference("resource.attributes.tenant_id"),
                )
            )
        ]
    )

    decision = policy.evaluate(
        request(
            principal_attributes={"tenant_id": "tenant-a"},
            resource_attributes={"tenant_id": "tenant-b"},
        )
    )

    assert not decision.allowed
    assert decision.reason is DecisionReason.DEFAULT_DENY


def test_every_condition_on_a_rule_must_match() -> None:
    policy = PolicyEngine(
        [
            allow_rule(
                AttributeCondition(
                    "principal.attributes.tenant_id",
                    ConditionOperator.EQ,
                    AttributeReference("resource.attributes.tenant_id"),
                ),
                AttributeCondition(
                    "principal.attributes.user_id",
                    ConditionOperator.EQ,
                    AttributeReference("resource.attributes.owner_id"),
                ),
            )
        ]
    )

    same_tenant_wrong_owner = policy.evaluate(
        request(
            principal_attributes={"tenant_id": "tenant-a", "user_id": "alice"},
            resource_attributes={"tenant_id": "tenant-a", "owner_id": "bob"},
        )
    )

    assert not same_tenant_wrong_owner.allowed


def test_conditional_deny_still_overrides_a_matching_allow() -> None:
    policy = PolicyEngine(
        [
            PolicyRule(
                rule_id="allow-analyst-read",
                effect=Effect.ALLOW,
                actions=frozenset({"read"}),
                resources=frozenset({"*"}),
                roles=frozenset({"analyst"}),
            ),
            PolicyRule(
                rule_id="deny-restricted-without-clearance",
                effect=Effect.DENY,
                actions=frozenset({"read"}),
                resources=frozenset({"*"}),
                roles=frozenset({"analyst"}),
                conditions=(
                    AttributeCondition(
                        "resource.attributes.classification",
                        ConditionOperator.EQ,
                        "restricted",
                    ),
                    AttributeCondition(
                        "principal.attributes.clearance",
                        ConditionOperator.NE,
                        "secret",
                    ),
                ),
            ),
        ]
    )

    decision = policy.evaluate(
        request(
            principal_attributes={"clearance": "internal"},
            resource_attributes={"classification": "restricted"},
        )
    )

    assert not decision.allowed
    assert decision.reason is DecisionReason.EXPLICIT_DENY
    assert decision.matched_rule_ids == ("deny-restricted-without-clearance",)


@pytest.mark.parametrize(
    ("condition", "context", "expected_allowed"),
    [
        (AttributeCondition("context.risk_score", ConditionOperator.EQ, 3), {"risk_score": 3}, True),
        (AttributeCondition("context.risk_score", ConditionOperator.NE, 4), {"risk_score": 3}, True),
        (AttributeCondition("context.risk_score", ConditionOperator.IN, [1, 3, 5]), {"risk_score": 3}, True),
        (AttributeCondition("context.risk_score", ConditionOperator.NOT_IN, [4, 5]), {"risk_score": 3}, True),
        (AttributeCondition("context.risk_score", ConditionOperator.GT, 2), {"risk_score": 3}, True),
        (AttributeCondition("context.risk_score", ConditionOperator.GTE, 3), {"risk_score": 3}, True),
        (AttributeCondition("context.risk_score", ConditionOperator.LT, 4), {"risk_score": 3}, True),
        (AttributeCondition("context.risk_score", ConditionOperator.LTE, 3), {"risk_score": 3}, True),
        (AttributeCondition("context.labels", ConditionOperator.CONTAINS, "hr"), {"labels": ["finance", "hr"]}, True),
        (AttributeCondition("context.present", ConditionOperator.EXISTS), {"present": None}, True),
        (AttributeCondition("context.missing", ConditionOperator.NOT_EXISTS), {}, True),
    ],
)
def test_supported_attribute_operators(
    condition: AttributeCondition,
    context: dict[str, object],
    expected_allowed: bool,
) -> None:
    decision = PolicyEngine([allow_rule(condition)]).evaluate(request(context=context))

    assert decision.allowed is expected_allowed


@pytest.mark.parametrize(
    ("operator", "value"),
    [
        (ConditionOperator.EQ, 1),
        (ConditionOperator.NE, 1),
        (ConditionOperator.IN, [1, 2]),
        (ConditionOperator.NOT_IN, [1, 2]),
        (ConditionOperator.GT, 1),
        (ConditionOperator.GTE, 1),
        (ConditionOperator.LT, 1),
        (ConditionOperator.LTE, 1),
        (ConditionOperator.CONTAINS, 1),
        (ConditionOperator.EXISTS, None),
        (ConditionOperator.NOT_EXISTS, None),
    ],
)
def test_missing_attributes_fail_closed_except_not_exists(
    operator: ConditionOperator,
    value: object,
) -> None:
    condition = AttributeCondition("context.missing", operator, value)
    decision = PolicyEngine([allow_rule(condition)]).evaluate(request())

    assert decision.allowed is (operator is ConditionOperator.NOT_EXISTS)


def test_membership_operator_fails_closed_for_non_collection_reference() -> None:
    condition = AttributeCondition(
        "context.value",
        ConditionOperator.NOT_IN,
        AttributeReference("context.other"),
    )
    decision = PolicyEngine([allow_rule(condition)]).evaluate(
        request(context={"value": "a", "other": "not-a-collection"})
    )

    assert not decision.allowed


def test_attribute_equality_does_not_treat_boolean_as_integer() -> None:
    condition = AttributeCondition("context.flag", ConditionOperator.EQ, 1)
    decision = PolicyEngine([allow_rule(condition)]).evaluate(request(context={"flag": True}))

    assert not decision.allowed


def test_nested_attribute_input_is_defensively_frozen() -> None:
    attributes: dict[str, object] = {"profile": {"teams": ["hr"]}}
    principal = Principal("alice", attributes=attributes)  # type: ignore[arg-type]
    attributes["profile"]["teams"].append("finance")  # type: ignore[index, union-attr]

    assert principal.attributes["profile"]["teams"] == ("hr",)  # type: ignore[index]


@pytest.mark.parametrize(
    "path",
    [
        "context",
        "context..tenant_id",
        "principal.__class__",
        "resource.attributes.tenant_id.__class__",
        "system.env",
    ],
)
def test_attribute_paths_are_validated_and_never_executed(path: str) -> None:
    with pytest.raises(ValueError, match="attribute path|condition attribute"):
        AttributeReference(path)


def test_attribute_values_reject_non_finite_numbers_and_arbitrary_objects() -> None:
    with pytest.raises(ValueError, match="non-finite"):
        Principal("alice", attributes={"risk": float("nan")})  # type: ignore[dict-item]

    with pytest.raises(ValueError, match="JSON-compatible"):
        Principal("alice", attributes={"object": object()})  # type: ignore[dict-item]


def test_conditions_must_be_typed_attribute_conditions() -> None:
    with pytest.raises(ValueError, match="AttributeCondition"):
        PolicyRule(
            rule_id="invalid-condition",
            effect=Effect.ALLOW,
            actions=frozenset({"read"}),
            resources=frozenset({"*"}),
            roles=frozenset({"analyst"}),
            conditions=("context.risk_score > 3",),  # type: ignore[arg-type]
        )
