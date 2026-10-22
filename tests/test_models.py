import pytest

from langgraph_secure_agents.models import AccessRequest, Decision, Effect, PolicyRule, Principal


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


def test_blank_principal_id_is_rejected() -> None:
    with pytest.raises(ValueError, match="principal_id must be a non-empty string"):
        Principal("   ")


def test_non_iterable_roles_are_rejected() -> None:
    with pytest.raises(ValueError, match="roles must be an iterable"):
        Principal("alice", roles=42)  # type: ignore[arg-type]


def test_non_string_role_is_rejected() -> None:
    with pytest.raises(ValueError, match="roles must be a non-empty string"):
        Principal("alice", roles={1})  # type: ignore[arg-type]


def test_access_request_requires_a_principal_instance() -> None:
    with pytest.raises(ValueError, match="Principal instance"):
        AccessRequest(principal="alice", action="read", resource="reports")  # type: ignore[arg-type]


def test_policy_rule_rejects_unknown_effect() -> None:
    with pytest.raises(ValueError, match="effect must be"):
        PolicyRule(
            rule_id="invalid-effect",
            effect="maybe",  # type: ignore[arg-type]
            actions={"read"},
            resources={"reports"},
            roles={"analyst"},
        )


def test_policy_rule_rejects_empty_action_selectors() -> None:
    with pytest.raises(ValueError, match="actions must contain at least one value"):
        PolicyRule(
            rule_id="empty-actions",
            effect=Effect.ALLOW,
            actions=frozenset(),
            resources={"reports"},
            roles={"analyst"},
        )


def test_partial_wildcard_patterns_are_rejected() -> None:
    with pytest.raises(ValueError, match="standalone"):
        PolicyRule(
            rule_id="partial-action-wildcard",
            effect=Effect.ALLOW,
            actions={"read*"},
            resources={"reports"},
            roles={"analyst"},
        )


def test_principal_wildcard_cannot_be_mixed_with_specific_identities() -> None:
    with pytest.raises(ValueError, match="cannot combine"):
        PolicyRule(
            rule_id="mixed-principal-wildcard",
            effect=Effect.ALLOW,
            actions={"read"},
            resources={"reports"},
            principal_ids={"*", "alice"},
        )


def test_decision_normalizes_rule_ids_to_an_immutable_tuple() -> None:
    rule_ids = ["deny-payroll"]
    decision = Decision(
        allowed=False,
        reason="explicit_deny",
        matched_rule_ids=rule_ids,  # type: ignore[arg-type]
    )
    rule_ids.append("later-change")

    assert decision.matched_rule_ids == ("deny-payroll",)
    assert isinstance(decision.matched_rule_ids, tuple)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"allowed": 1, "reason": "default_deny"}, "allowed must be a boolean"),
        ({"allowed": False, "reason": " "}, "reason must be a non-empty string"),
        (
            {"allowed": False, "reason": "approval_required", "requires_approval": False},
            "requires_approval must be true exactly",
        ),
        (
            {"allowed": True, "reason": "approval_required", "requires_approval": True},
            "cannot describe an allowed decision",
        ),
        (
            {"allowed": True, "reason": "explicit_deny"},
            "cannot describe an allowed decision",
        ),
        (
            {"allowed": False, "reason": "explicit_allow"},
            "cannot describe a denied decision",
        ),
        (
            {"allowed": False, "reason": "explicit_deny", "matched_rule_ids": "deny"},
            "collection of rule IDs",
        ),
        (
            {
                "allowed": False,
                "reason": "explicit_deny",
                "matched_rule_ids": ("deny", "deny"),
            },
            "cannot contain duplicates",
        ),
    ],
)
def test_decision_rejects_invalid_or_conflicting_state(
    kwargs: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        Decision(**kwargs)  # type: ignore[arg-type]


def test_decision_requires_approval_flag_must_be_boolean() -> None:
    with pytest.raises(ValueError, match="requires_approval must be a boolean"):
        Decision(
            allowed=False,
            reason="default_deny",
            requires_approval="yes",  # type: ignore[arg-type]
        )


def test_decision_rejects_non_iterable_rule_ids() -> None:
    with pytest.raises(ValueError, match="matched_rule_ids must be an iterable"):
        Decision(
            allowed=False,
            reason="explicit_deny",
            matched_rule_ids=42,  # type: ignore[arg-type]
        )



def test_decision_rejects_unknown_reason() -> None:
    with pytest.raises(ValueError, match="known DecisionReason"):
        Decision(allowed=False, reason="unknown_reason")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        (
            {"allowed": True, "reason": "explicit_allow", "matched_rule_ids": ()},
            "requires matched_rule_ids",
        ),
        (
            {"allowed": False, "reason": "explicit_deny", "matched_rule_ids": ()},
            "requires matched_rule_ids",
        ),
        (
            {"allowed": False, "reason": "approval_required", "matched_rule_ids": (),
             "requires_approval": True},
            "requires matched_rule_ids",
        ),
        (
            {"allowed": False, "reason": "default_deny", "matched_rule_ids": ("irrelevant",)},
            "default_deny cannot have matched_rule_ids",
        ),
    ],
)
def test_decision_requires_rule_ids_consistent_with_reason(
    kwargs: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        Decision(**kwargs)  # type: ignore[arg-type]
