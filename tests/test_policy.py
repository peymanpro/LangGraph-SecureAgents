import pytest

from langgraph_secure_agents.models import AccessRequest, Effect, PolicyRule, Principal
from langgraph_secure_agents.policy import PolicyEngine


def rule(
    rule_id: str,
    effect: Effect,
    *,
    actions: frozenset[str] = frozenset({"read"}),
    resources: frozenset[str] = frozenset({"reports"}),
    principal_ids: frozenset[str] = frozenset(),
    roles: frozenset[str] = frozenset({"analyst"}),
) -> PolicyRule:
    return PolicyRule(
        rule_id=rule_id,
        effect=effect,
        actions=actions,
        resources=resources,
        principal_ids=principal_ids,
        roles=roles,
    )


def request(
    *,
    principal_id: str = "alice",
    roles: frozenset[str] = frozenset({"analyst"}),
    action: str = "read",
    resource: str = "reports",
) -> AccessRequest:
    return AccessRequest(
        principal=Principal(principal_id=principal_id, roles=roles),
        action=action,
        resource=resource,
    )


def test_empty_policy_denies_by_default() -> None:
    decision = PolicyEngine().evaluate(request())

    assert not decision.allowed
    assert decision.reason == "default_deny"
    assert decision.matched_rule_ids == ()


def test_matching_allow_rule_allows_request() -> None:
    engine = PolicyEngine([rule("analysts-read-reports", Effect.ALLOW)])

    decision = engine.evaluate(request())

    assert decision.allowed
    assert decision.reason == "explicit_allow"
    assert decision.matched_rule_ids == ("analysts-read-reports",)


def test_matching_deny_overrides_matching_allow() -> None:
    engine = PolicyEngine(
        [
            rule("allow-analysts", Effect.ALLOW),
            rule("deny-alice", Effect.DENY, principal_ids=frozenset({"alice"}), roles=frozenset()),
        ]
    )

    decision = engine.evaluate(request())

    assert not decision.allowed
    assert decision.reason == "explicit_deny"
    assert decision.matched_rule_ids == ("deny-alice",)


@pytest.mark.parametrize(
    ("actions", "resources", "action", "resource"),
    [
        (frozenset({"*"}), frozenset({"reports"}), "delete", "reports"),
        (frozenset({"read"}), frozenset({"*"}), "read", "payroll"),
        (frozenset({"*"}), frozenset({"*"}), "delete", "unlisted-resource"),
    ],
)
def test_standalone_wildcards_match_as_documented(
    actions: frozenset[str], resources: frozenset[str], action: str, resource: str
) -> None:
    engine = PolicyEngine(
        [
            rule(
                "wildcard-allow",
                Effect.ALLOW,
                actions=actions,
                resources=resources,
                principal_ids=frozenset({"*"}),
                roles=frozenset(),
            )
        ]
    )

    decision = engine.evaluate(
        request(principal_id="bob", roles=frozenset(), action=action, resource=resource)
    )

    assert decision.allowed


def test_principal_id_and_role_constraints_are_combined_with_and() -> None:
    engine = PolicyEngine([rule("alice-analyst", Effect.ALLOW, principal_ids=frozenset({"alice"}))])

    wrong_principal = engine.evaluate(request(principal_id="bob"))
    wrong_role = engine.evaluate(request(roles=frozenset({"guest"})))

    assert not wrong_principal.allowed
    assert not wrong_role.allowed


@pytest.mark.parametrize(
    ("action", "resource", "principal_id"),
    [
        ("write", "reports", "alice"),
        ("read", "payroll", "alice"),
        ("read", "reports", "bob"),
    ],
)
def test_non_matching_request_is_denied(action: str, resource: str, principal_id: str) -> None:
    engine = PolicyEngine(
        [rule("alice-read-reports", Effect.ALLOW, principal_ids=frozenset({"alice"}))]
    )

    decision = engine.evaluate(request(action=action, resource=resource, principal_id=principal_id))

    assert not decision.allowed
    assert decision.reason == "default_deny"


def test_duplicate_rule_ids_are_rejected() -> None:
    first = rule("duplicate", Effect.ALLOW)
    second = rule("duplicate", Effect.DENY)

    with pytest.raises(ValueError, match="duplicate policy rule id"):
        PolicyEngine([first, second])


def test_non_policy_rule_entries_are_rejected() -> None:
    with pytest.raises(TypeError, match="PolicyRule"):
        PolicyEngine(["not-a-policy-rule"])  # type: ignore[list-item]


def test_deny_overrides_allow_regardless_of_rule_order() -> None:
    allow = rule("allow-analysts", Effect.ALLOW)
    deny = rule(
        "deny-alice",
        Effect.DENY,
        principal_ids=frozenset({"alice"}),
        roles=frozenset(),
    )

    allow_then_deny = PolicyEngine([allow, deny]).evaluate(request())
    deny_then_allow = PolicyEngine([deny, allow]).evaluate(request())

    assert not allow_then_deny.allowed
    assert not deny_then_allow.allowed
    assert allow_then_deny.reason == "explicit_deny"
    assert deny_then_allow.reason == "explicit_deny"


def test_approval_required_policy_is_not_a_normal_allow() -> None:
    decision = PolicyEngine(
        [
            rule(
                "finance-approval",
                Effect.REQUIRE_APPROVAL,
                principal_ids=frozenset({"alice"}),
                roles=frozenset(),
            )
        ]
    ).evaluate(request())

    assert not decision.allowed
    assert decision.requires_approval
    assert decision.reason == "approval_required"
    assert decision.matched_rule_ids == ("finance-approval",)


def test_explicit_deny_overrides_approval_requirement() -> None:
    approval = rule(
        "requires-approval",
        Effect.REQUIRE_APPROVAL,
        principal_ids=frozenset({"alice"}),
        roles=frozenset(),
    )
    deny = rule(
        "explicit-deny",
        Effect.DENY,
        principal_ids=frozenset({"alice"}),
        roles=frozenset(),
    )

    decision = PolicyEngine([approval, deny]).evaluate(request())

    assert not decision.allowed
    assert not decision.requires_approval
    assert decision.reason == "explicit_deny"
    assert decision.matched_rule_ids == ("explicit-deny",)


def test_approval_requirement_overrides_matching_allow_rule() -> None:
    approval = rule(
        "requires-approval",
        Effect.REQUIRE_APPROVAL,
        principal_ids=frozenset({"alice"}),
        roles=frozenset(),
    )
    allow = rule("allow-analysts", Effect.ALLOW)

    decision = PolicyEngine([allow, approval]).evaluate(request())

    assert not decision.allowed
    assert decision.requires_approval
    assert decision.reason == "approval_required"


def test_rules_property_returns_immutable_tuple() -> None:
    rules = (rule("one", Effect.ALLOW),)
    engine = PolicyEngine(rules)

    assert engine.rules == rules
    assert isinstance(engine.rules, tuple)


def test_evaluate_rejects_non_access_request() -> None:
    with pytest.raises(TypeError, match="AccessRequest instance"):
        PolicyEngine().evaluate("not-an-access-request")  # type: ignore[arg-type]
