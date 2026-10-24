from __future__ import annotations

from itertools import permutations

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


def test_deny_override_is_independent_of_rule_order() -> None:
    allow_rules = [
        PolicyRule(
            rule_id=f"allow-{index}",
            effect=Effect.ALLOW,
            actions=frozenset({"read"}),
            resources=frozenset({"document:1"}),
            roles=frozenset({"analyst"}),
        )
        for index in range(3)
    ]
    deny_rule = PolicyRule(
        rule_id="deny-sensitive-document",
        effect=Effect.DENY,
        actions=frozenset({"read"}),
        resources=frozenset({"document:1"}),
        roles=frozenset({"analyst"}),
    )
    request = AccessRequest(
        principal=Principal("alice", roles=frozenset({"analyst"})),
        action="read",
        resource="document:1",
    )

    for ordered_rules in permutations((*allow_rules, deny_rule)):
        decision = PolicyEngine(ordered_rules).evaluate(request)
        assert decision.allowed is False
        assert decision.reason is DecisionReason.EXPLICIT_DENY
        assert decision.matched_rule_ids == ("deny-sensitive-document",)


def test_tenant_abac_fails_closed_for_missing_or_mismatched_attributes() -> None:
    rule = PolicyRule(
        rule_id="same-tenant-only",
        effect=Effect.ALLOW,
        actions=frozenset({"read"}),
        resources=frozenset({"*"}),
        roles=frozenset({"analyst"}),
        conditions=(
            AttributeCondition(
                "principal.attributes.tenant_id",
                ConditionOperator.EQ,
                AttributeReference("resource.attributes.tenant_id"),
            ),
        ),
    )
    policy = PolicyEngine([rule])

    def access(*, principal_attributes: dict[str, object], resource_attributes: dict[str, object]):
        return AccessRequest(
            principal=Principal(
                "alice",
                roles=frozenset({"analyst"}),
                attributes=principal_attributes,
            ),
            action="read",
            resource="document:1",
            resource_attributes=resource_attributes,
        )

    same_tenant = policy.evaluate(
        access(
            principal_attributes={"tenant_id": "tenant-a"},
            resource_attributes={"tenant_id": "tenant-a"},
        )
    )
    cross_tenant = policy.evaluate(
        access(
            principal_attributes={"tenant_id": "tenant-a"},
            resource_attributes={"tenant_id": "tenant-b"},
        )
    )
    missing_resource_tenant = policy.evaluate(
        access(principal_attributes={"tenant_id": "tenant-a"}, resource_attributes={})
    )
    missing_principal_tenant = policy.evaluate(
        access(principal_attributes={}, resource_attributes={"tenant_id": "tenant-a"})
    )

    assert same_tenant.allowed is True
    assert cross_tenant.reason is DecisionReason.DEFAULT_DENY
    assert missing_resource_tenant.reason is DecisionReason.DEFAULT_DENY
    assert missing_principal_tenant.reason is DecisionReason.DEFAULT_DENY


def test_attribute_comparison_does_not_equate_boolean_and_integer() -> None:
    rule = PolicyRule(
        rule_id="boolean-true-only",
        effect=Effect.ALLOW,
        actions=frozenset({"read"}),
        resources=frozenset({"document:1"}),
        roles=frozenset({"analyst"}),
        conditions=(
            AttributeCondition("context.enabled", ConditionOperator.EQ, True),
        ),
    )
    policy = PolicyEngine([rule])
    request = AccessRequest(
        principal=Principal("alice", roles=frozenset({"analyst"})),
        action="read",
        resource="document:1",
        context={"enabled": 1},
    )

    assert policy.evaluate(request).reason is DecisionReason.DEFAULT_DENY
