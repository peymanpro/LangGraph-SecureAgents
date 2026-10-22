import pytest

from langgraph_secure_agents.models import AccessRequest, Effect, PolicyRule, Principal


def test_principal_normalizes_identity_and_roles() -> None:
    principal = Principal(" alice ", roles={" admin ", "reader"})

    assert principal.principal_id == "alice"
    assert principal.roles == frozenset({"admin", "reader"})


def test_access_request_requires_a_concrete_action_and_resource() -> None:
    principal = Principal("alice")

    with pytest.raises(ValueError, match="concrete action"):
        AccessRequest(principal=principal, action="*", resource="reports")

    with pytest.raises(ValueError, match="concrete action"):
        AccessRequest(principal=principal, action="read", resource="*")


def test_policy_rule_accepts_string_effect_and_normalizes_selectors() -> None:
    rule = PolicyRule(
        rule_id="allow-read",
        effect="allow",  # type: ignore[arg-type]
        actions={" read "},
        resources={" reports "},
        roles={" analyst "},
    )

    assert rule.effect is Effect.ALLOW
    assert rule.actions == frozenset({"read"})
    assert rule.resources == frozenset({"reports"})
    assert rule.roles == frozenset({"analyst"})


def test_policy_rule_requires_explicit_subject_selector() -> None:
    with pytest.raises(ValueError, match="principal_ids or roles"):
        PolicyRule(
            rule_id="too-broad",
            effect=Effect.ALLOW,
            actions={"read"},
            resources={"reports"},
        )


def test_wildcard_cannot_be_mixed_with_specific_actions() -> None:
    with pytest.raises(ValueError, match="cannot combine"):
        PolicyRule(
            rule_id="ambiguous-action",
            effect=Effect.ALLOW,
            actions={"*", "read"},
            resources={"reports"},
            roles={"analyst"},
        )


def test_global_principal_wildcard_cannot_have_role_constraints() -> None:
    with pytest.raises(ValueError, match="cannot be combined"):
        PolicyRule(
            rule_id="ambiguous-subject",
            effect=Effect.ALLOW,
            actions={"read"},
            resources={"reports"},
            principal_ids={"*"},
            roles={"analyst"},
        )


def test_selector_collection_cannot_be_a_plain_string() -> None:
    with pytest.raises(ValueError, match="collection of strings"):
        PolicyRule(
            rule_id="invalid-selector",
            effect=Effect.ALLOW,
            actions="read",  # type: ignore[arg-type]
            resources={"reports"},
            roles={"analyst"},
        )
