"""Deterministic policy evaluation with deny-overrides semantics."""

from __future__ import annotations

from collections.abc import Iterable

from .models import AccessRequest, Decision, Effect, PolicyRule


class PolicyEngine:
    """Evaluate authorization requests without involving an LLM."""
    
    __slots__ = ("_rules",)

    def __setattr__(self, name: str, value: object) -> None:
        if name == "_rules" and hasattr(self, "_rules"):
            raise AttributeError("PolicyEngine rules are immutable after construction")
        object.__setattr__(self, name, value)

    #

    A matching DENY rule always overrides every other effect. Otherwise a
    matching REQUIRE_APPROVAL rule takes precedence over ALLOW and returns a
    non-allowing decision that an approval-aware integration may handle.
    Requests not covered by an allow or approval rule are denied by default.
    """

    def __init__(self, rules: Iterable[PolicyRule] = ()) -> None:
        materialized_rules = tuple(rules)
        seen_ids: set[str] = set()
        for rule in materialized_rules:
            if not isinstance(rule, PolicyRule):
                raise TypeError("rules must contain only PolicyRule instances")
            if rule.rule_id in seen_ids:
                raise ValueError(f"duplicate policy rule id: {rule.rule_id}")
            seen_ids.add(rule.rule_id)
        self._rules = materialized_rules

    @property
    def rules(self) -> tuple[PolicyRule, ...]:
        """Return the policy rules as an immutable tuple."""

        return self._rules

    def evaluate(self, request: AccessRequest) -> Decision:
        """Return the authorization decision for a concrete access request."""

        if not isinstance(request, AccessRequest):
            raise TypeError("request must be an AccessRequest instance")

        matching_rules = tuple(rule for rule in self._rules if self._matches(rule, request))
        denying_rule_ids = tuple(
            rule.rule_id for rule in matching_rules if rule.effect is Effect.DENY
        )
        if denying_rule_ids:
            return Decision(
                allowed=False,
                reason="explicit_deny",
                matched_rule_ids=denying_rule_ids,
            )

        approval_rule_ids = tuple(
            rule.rule_id for rule in matching_rules if rule.effect is Effect.REQUIRE_APPROVAL
        )
        if approval_rule_ids:
            return Decision(
                allowed=False,
                reason="approval_required",
                matched_rule_ids=approval_rule_ids,
                requires_approval=True,
            )

        allowing_rule_ids = tuple(
            rule.rule_id for rule in matching_rules if rule.effect is Effect.ALLOW
        )
        if allowing_rule_ids:
            return Decision(
                allowed=True,
                reason="explicit_allow",
                matched_rule_ids=allowing_rule_ids,
            )

        return Decision(allowed=False, reason="default_deny")

    @staticmethod
    def _matches(rule: PolicyRule, request: AccessRequest) -> bool:
        if rule.actions != frozenset({"*"}) and request.action not in rule.actions:
            return False
        if rule.resources != frozenset({"*"}) and request.resource not in rule.resources:
            return False

        if rule.principal_ids and rule.principal_ids != frozenset({"*"}):
            if request.principal.principal_id not in rule.principal_ids:
                return False

        if rule.roles and not request.principal.roles.intersection(rule.roles):
            return False

        return True
