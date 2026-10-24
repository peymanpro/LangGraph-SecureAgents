"""Deterministic policy evaluation with deny-overrides and safe ABAC conditions."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from math import isfinite
from typing import Any

from .models import (
    AccessRequest,
    AttributeCondition,
    AttributeReference,
    ConditionOperator,
    Decision,
    DecisionReason,
    Effect,
    PolicyRule,
)

_MISSING = object()


class PolicyEngine:
    """Evaluate authorization requests without involving an LLM.

    A matching DENY rule always overrides every other effect. Otherwise a
    matching REQUIRE_APPROVAL rule takes precedence over ALLOW. Requests not
    covered by an allow or approval rule are denied by default.

    Conditions on a rule are combined with logical AND. Missing attributes,
    incompatible operand types, and unresolved attribute references never
    satisfy a condition. Conditions are evaluated by built-in operators only;
    policy strings are never executed as code.
    """

    __slots__ = ("_rules",)

    def __setattr__(self, name: str, value: object) -> None:
        if name == "_rules" and hasattr(self, "_rules"):
            raise AttributeError("PolicyEngine rules are immutable after construction")
        object.__setattr__(self, name, value)

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
        """Return the deterministic authorization decision for a concrete request."""

        if not isinstance(request, AccessRequest):
            raise TypeError("request must be an AccessRequest instance")

        matching_rules = tuple(rule for rule in self._rules if self._matches(rule, request))
        denying_rule_ids = tuple(
            rule.rule_id for rule in matching_rules if rule.effect is Effect.DENY
        )
        if denying_rule_ids:
            return Decision(
                allowed=False,
                reason=DecisionReason.EXPLICIT_DENY,
                matched_rule_ids=denying_rule_ids,
            )

        approval_rule_ids = tuple(
            rule.rule_id for rule in matching_rules if rule.effect is Effect.REQUIRE_APPROVAL
        )
        if approval_rule_ids:
            return Decision(
                allowed=False,
                reason=DecisionReason.APPROVAL_REQUIRED,
                matched_rule_ids=approval_rule_ids,
                requires_approval=True,
            )

        allowing_rule_ids = tuple(
            rule.rule_id for rule in matching_rules if rule.effect is Effect.ALLOW
        )
        if allowing_rule_ids:
            return Decision(
                allowed=True,
                reason=DecisionReason.EXPLICIT_ALLOW,
                matched_rule_ids=allowing_rule_ids,
            )

        return Decision(allowed=False, reason=DecisionReason.DEFAULT_DENY)

    @classmethod
    def _matches(cls, rule: PolicyRule, request: AccessRequest) -> bool:
        if rule.actions != frozenset({"*"}) and request.action not in rule.actions:
            return False
        if rule.resources != frozenset({"*"}) and request.resource not in rule.resources:
            return False

        if rule.principal_ids and rule.principal_ids != frozenset({"*"}):
            if request.principal.principal_id not in rule.principal_ids:
                return False

        if rule.roles and not request.principal.roles.intersection(rule.roles):
            return False

        return all(cls._condition_matches(condition, request) for condition in rule.conditions)

    @classmethod
    def _condition_matches(
        cls,
        condition: AttributeCondition,
        request: AccessRequest,
    ) -> bool:
        actual = cls._resolve_attribute(condition.attribute, request)
        operator = condition.operator

        if operator is ConditionOperator.EXISTS:
            return actual is not _MISSING
        if operator is ConditionOperator.NOT_EXISTS:
            return actual is _MISSING
        if actual is _MISSING:
            return False

        expected: Any = condition.value
        if isinstance(expected, AttributeReference):
            expected = cls._resolve_attribute(expected.path, request)
            if expected is _MISSING:
                return False

        if operator is ConditionOperator.EQ:
            return cls._safe_equal(actual, expected)
        if operator is ConditionOperator.NE:
            return not cls._safe_equal(actual, expected)
        if operator is ConditionOperator.IN:
            return cls._member_of(actual, expected)
        if operator is ConditionOperator.NOT_IN:
            return not cls._member_of(actual, expected)
        if operator is ConditionOperator.CONTAINS:
            return cls._contains(actual, expected)

        if (
            type(actual) not in (int, float)
            or type(expected) not in (int, float)
            or not isfinite(actual)
            or not isfinite(expected)
        ):
            return False
        if operator is ConditionOperator.GT:
            return actual > expected
        if operator is ConditionOperator.GTE:
            return actual >= expected
        if operator is ConditionOperator.LT:
            return actual < expected
        if operator is ConditionOperator.LTE:
            return actual <= expected
        return False

    @staticmethod
    def _resolve_attribute(path: str, request: AccessRequest) -> object:
        """Resolve a validated path using mapping lookup only; never use getattr/eval."""

        parts = path.split(".")
        root = parts[0]

        if root == "principal":
            if parts[1] == "principal_id":
                return request.principal.principal_id
            if parts[1] == "roles":
                return request.principal.roles
            current: object = request.principal.attributes
            remaining = parts[2:]
        elif root == "resource":
            if parts[1] == "id":
                return request.resource
            current = request.resource_attributes
            remaining = parts[2:]
        else:
            current = request.context
            remaining = parts[1:]

        for part in remaining:
            if not isinstance(current, Mapping) or part not in current:
                return _MISSING
            current = current[part]
        return current

    @classmethod
    def _safe_equal(cls, left: object, right: object) -> bool:
        """Use predictable JSON-like equality without bool/int coercion."""

        if type(left) is not type(right):
            if (
                type(left) in (int, float)
                and type(right) in (int, float)
                and type(left) is not bool
                and type(right) is not bool
            ):
                return left == right
            return False
        if isinstance(left, Mapping) and isinstance(right, Mapping):
            if left.keys() != right.keys():
                return False
            return all(cls._safe_equal(left[key], right[key]) for key in left)
        if isinstance(left, tuple) and isinstance(right, tuple):
            return len(left) == len(right) and all(
                cls._safe_equal(left_item, right_item)
                for left_item, right_item in zip(left, right, strict=True)
            )
        return left == right

    @classmethod
    def _member_of(cls, value: object, collection: object) -> bool:
        if not isinstance(collection, (tuple, frozenset)):
            return False
        return any(cls._safe_equal(value, candidate) for candidate in collection)

    @classmethod
    def _contains(cls, container: object, value: object) -> bool:
        if isinstance(container, str):
            return isinstance(value, str) and value in container
        if isinstance(container, Mapping):
            return isinstance(value, str) and value in container
        if isinstance(container, (tuple, frozenset)):
            return any(cls._safe_equal(value, item) for item in container)
        return False
