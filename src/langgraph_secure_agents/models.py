"""Immutable domain models for authorization decisions and attribute-based policies."""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import TypeAlias


def _normalized_text(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value.strip()


def _normalized_set(
    values: Iterable[str],
    field_name: str,
    *,
    allow_empty: bool = False,
) -> frozenset[str]:
    if isinstance(values, (str, bytes)):
        raise ValueError(f"{field_name} must be a collection of strings, not a string")
    normalized: set[str] = set()
    try:
        for value in values:
            normalized.add(_normalized_text(value, field_name))
    except TypeError as exc:
        raise ValueError(f"{field_name} must be an iterable of strings") from exc
    if not normalized and not allow_empty:
        raise ValueError(f"{field_name} must contain at least one value")
    return frozenset(normalized)


JSONScalar: TypeAlias = str | int | float | bool | None
JSONValue: TypeAlias = JSONScalar | tuple["JSONValue", ...] | Mapping[str, "JSONValue"]


def _freeze_attribute_value(value: object, *, depth: int = 0) -> JSONValue:
    """Validate and recursively freeze JSON-compatible attribute values."""

    if depth > 32:
        raise ValueError("attribute values must not exceed 32 nested levels")
    if value is None or type(value) in (str, bool, int):
        return value  # type: ignore[return-value]
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("attribute values cannot contain non-finite numbers")
        return value
    if isinstance(value, Mapping):
        frozen: dict[str, JSONValue] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError("attribute mapping keys must be non-empty strings")
            normalized_key = key.strip()
            if "." in normalized_key:
                raise ValueError("attribute keys cannot contain dots; use nested mappings")
            frozen[normalized_key] = _freeze_attribute_value(item, depth=depth + 1)
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_attribute_value(item, depth=depth + 1) for item in value)
    raise ValueError("attributes must contain only JSON-compatible values")


def _freeze_attributes(
    attributes: Mapping[str, object],
    *,
    field_name: str,
) -> Mapping[str, JSONValue]:
    if not isinstance(attributes, Mapping):
        raise ValueError(f"{field_name} must be a mapping of attribute names to JSON values")
    frozen: dict[str, JSONValue] = {}
    for key, value in attributes.items():
        if not isinstance(key, str) or not key.strip():
            raise ValueError(f"{field_name} keys must be non-empty strings")
        normalized_key = key.strip()
        if "." in normalized_key:
            raise ValueError(f"{field_name} keys cannot contain dots; use nested mappings")
        frozen[normalized_key] = _freeze_attribute_value(value)
    return MappingProxyType(frozen)


class Effect(StrEnum):
    """The effect a matching policy rule has on an access request."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class ConditionOperator(StrEnum):
    """Safe, built-in operators supported by attribute conditions."""

    EQ = "eq"
    NE = "ne"
    IN = "in"
    NOT_IN = "not_in"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    CONTAINS = "contains"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"


def _validate_attribute_path(path: str, field_name: str = "attribute path") -> str:
    normalized = _normalized_text(path, field_name)
    parts = normalized.split(".")
    if any(not part or part.strip() != part for part in parts):
        raise ValueError(f"{field_name} contains an empty or malformed path segment")

    root = parts[0]
    valid = (
        (
            root == "principal"
            and (
                parts[1:2] in (["principal_id"], ["roles"])
                or (len(parts) >= 3 and parts[1] == "attributes")
            )
        )
        or (
            root == "resource"
            and (
                parts[1:2] == ["id"]
                or (len(parts) >= 3 and parts[1] == "attributes")
            )
        )
        or (root == "context" and len(parts) >= 2)
    )
    if not valid:
        raise ValueError(
            f"{field_name} must start with principal.principal_id, principal.roles, "
            "principal.attributes, resource.id, resource.attributes, or context"
        )
    if root in {"principal", "resource"} and parts[1] in {
        "principal_id", "roles", "id", "attributes"
    }:
        if root == "principal" and parts[1] in {"principal_id", "roles"} and len(parts) != 2:
            raise ValueError(f"{field_name} cannot traverse a built-in principal field")
        if root == "resource" and parts[1] == "id" and len(parts) != 2:
            raise ValueError(f"{field_name} cannot traverse the resource id")
    return normalized


@dataclass(frozen=True, slots=True)
class AttributeReference:
    """Reference another trusted attribute when comparing policy values.

    Paths are resolved only through mapping keys and supported built-in fields;
    Python attributes, methods, and expressions are never evaluated.
    """

    path: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _validate_attribute_path(self.path))


@dataclass(frozen=True, slots=True)
class AttributeCondition:
    """One typed ABAC condition; all conditions on a rule must pass.

    The attribute identifies the left-hand path. The value is a literal JSON
    value or an AttributeReference for attribute-to-attribute comparisons.
    Missing attributes never satisfy a condition except NOT_EXISTS.
    """

    attribute: str
    operator: ConditionOperator
    value: JSONValue | AttributeReference | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "attribute",
            _validate_attribute_path(self.attribute, "condition attribute"),
        )
        try:
            operator = ConditionOperator(self.operator)
        except (TypeError, ValueError) as exc:
            raise ValueError("operator must be a supported ConditionOperator") from exc
        object.__setattr__(self, "operator", operator)

        if operator in {ConditionOperator.EXISTS, ConditionOperator.NOT_EXISTS}:
            if self.value is not None:
                raise ValueError(f"{operator.value} conditions do not accept a value")
            return

        if isinstance(self.value, AttributeReference):
            frozen_value: JSONValue | AttributeReference | None = self.value
        else:
            frozen_value = _freeze_attribute_value(self.value)
        if operator in {ConditionOperator.IN, ConditionOperator.NOT_IN} and not isinstance(
            frozen_value, AttributeReference
        ):
            if not isinstance(frozen_value, tuple):
                raise ValueError(f"{operator.value} conditions require a list or tuple value")
        object.__setattr__(self, "value", frozen_value)


@dataclass(frozen=True, slots=True)
class Principal:
    """An authenticated identity supplied by trusted application code.

    This object does not authenticate users. Applications must construct it
    from trusted identity data, never directly from untrusted LLM output.
    Attribute values are recursively immutable and JSON-compatible.
    """

    principal_id: str
    roles: frozenset[str] = frozenset()
    attributes: Mapping[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized_id = _normalized_text(self.principal_id, "principal_id")
        object.__setattr__(self, "principal_id", normalized_id)
        object.__setattr__(
            self,
            "roles",
            _normalized_set(self.roles, "roles", allow_empty=True),
        )
        object.__setattr__(
            self,
            "attributes",
            _freeze_attributes(self.attributes, field_name="principal attributes"),
        )


@dataclass(frozen=True, slots=True)
class AccessRequest:
    """A concrete access request with trusted resource and environment attributes."""

    principal: Principal
    action: str
    resource: str
    resource_attributes: Mapping[str, JSONValue] = field(default_factory=dict)
    context: Mapping[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.principal, Principal):
            raise ValueError("principal must be a Principal instance")
        action = _normalized_text(self.action, "action")
        resource = _normalized_text(self.resource, "resource")
        if action == "*" or resource == "*":
            raise ValueError("access requests must name a concrete action and resource")
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "resource", resource)
        object.__setattr__(
            self,
            "resource_attributes",
            _freeze_attributes(self.resource_attributes, field_name="resource attributes"),
        )
        object.__setattr__(
            self,
            "context",
            _freeze_attributes(self.context, field_name="context"),
        )


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """A policy rule with explicit selectors and optional AND-ed ABAC conditions.

    Selectors are exact matches unless the whole action/resource selector is
    the wildcard. A principal wildcard explicitly targets every principal.
    When both principal IDs and roles are supplied, both constraints must match.
    """

    rule_id: str
    effect: Effect
    actions: frozenset[str]
    resources: frozenset[str]
    principal_ids: frozenset[str] = frozenset()
    roles: frozenset[str] = frozenset()
    conditions: tuple[AttributeCondition, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "rule_id", _normalized_text(self.rule_id, "rule_id"))
        try:
            effect = Effect(self.effect)
        except (TypeError, ValueError) as exc:
            raise ValueError("effect must be ALLOW, DENY, or REQUIRE_APPROVAL") from exc
        object.__setattr__(self, "effect", effect)

        actions = _normalized_set(self.actions, "actions")
        resources = _normalized_set(self.resources, "resources")
        principal_ids = _normalized_set(self.principal_ids, "principal_ids", allow_empty=True)
        roles = _normalized_set(self.roles, "roles", allow_empty=True)

        for field_name, selectors in (("actions", actions), ("resources", resources)):
            if "*" in selectors and selectors != frozenset({"*"}):
                raise ValueError(f"{field_name} cannot combine '*' with specific selectors")
            if any("*" in selector and selector != "*" for selector in selectors):
                raise ValueError(f"{field_name} only supports the standalone '*' wildcard")

        if not principal_ids and not roles:
            raise ValueError("a policy rule must specify principal_ids or roles")
        if "*" in principal_ids and principal_ids != frozenset({"*"}):
            raise ValueError("principal_ids cannot combine '*' with specific identities")
        if "*" in principal_ids and roles:
            raise ValueError("principal_ids={'*'} cannot be combined with role constraints")

        if isinstance(self.conditions, (str, bytes)):
            raise ValueError("conditions must be a collection of AttributeCondition instances")
        try:
            conditions = tuple(self.conditions)
        except TypeError as exc:
            raise ValueError(
                "conditions must be a collection of AttributeCondition instances"
            ) from exc
        if any(not isinstance(condition, AttributeCondition) for condition in conditions):
            raise ValueError("conditions must contain only AttributeCondition instances")

        object.__setattr__(self, "actions", actions)
        object.__setattr__(self, "resources", resources)
        object.__setattr__(self, "principal_ids", principal_ids)
        object.__setattr__(self, "roles", roles)
        object.__setattr__(self, "conditions", conditions)


class DecisionReason(StrEnum):
    """Stable machine-readable reasons emitted by the policy layer."""

    EXPLICIT_ALLOW = "explicit_allow"
    EXPLICIT_DENY = "explicit_deny"
    DEFAULT_DENY = "default_deny"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_INVALID = "approval_invalid"
    APPROVAL_DENIED = "approval_denied"
    HUMAN_APPROVED = "human_approved"


@dataclass(frozen=True, slots=True)
class Decision:
    """A deterministic authorization outcome and its explainable basis."""

    allowed: bool
    reason: DecisionReason
    matched_rule_ids: tuple[str, ...] = ()
    requires_approval: bool = False

    def __post_init__(self) -> None:
        if type(self.allowed) is not bool:
            raise ValueError("allowed must be a boolean")

        normalized_reason = _normalized_text(self.reason, "reason")
        try:
            reason = DecisionReason(normalized_reason)
        except ValueError as exc:
            raise ValueError("reason must be a known DecisionReason") from exc

        if type(self.requires_approval) is not bool:
            raise ValueError("requires_approval must be a boolean")

        if isinstance(self.matched_rule_ids, (str, bytes)):
            raise ValueError("matched_rule_ids must be a collection of rule IDs")
        try:
            rule_ids = tuple(
                _normalized_text(rule_id, "matched_rule_ids") for rule_id in self.matched_rule_ids
            )
        except TypeError as exc:
            raise ValueError("matched_rule_ids must be an iterable of strings") from exc

        if len(set(rule_ids)) != len(rule_ids):
            raise ValueError("matched_rule_ids cannot contain duplicates")

        if self.requires_approval != (reason is DecisionReason.APPROVAL_REQUIRED):
            raise ValueError(
                "requires_approval must be true exactly when reason is 'approval_required'"
            )

        allowed_reasons = {
            DecisionReason.EXPLICIT_ALLOW,
            DecisionReason.HUMAN_APPROVED,
        }
        if self.allowed and reason not in allowed_reasons:
            raise ValueError(f"reason {reason.value!r} cannot describe an allowed decision")
        if not self.allowed and reason in allowed_reasons:
            raise ValueError(f"reason {reason.value!r} cannot describe a denied decision")

        rule_required_reasons = {
            DecisionReason.EXPLICIT_ALLOW,
            DecisionReason.EXPLICIT_DENY,
            DecisionReason.APPROVAL_REQUIRED,
            DecisionReason.APPROVAL_INVALID,
            DecisionReason.APPROVAL_DENIED,
            DecisionReason.HUMAN_APPROVED,
        }
        if reason in rule_required_reasons and not rule_ids:
            raise ValueError(f"reason {reason.value!r} requires matched_rule_ids")
        if reason is DecisionReason.DEFAULT_DENY and rule_ids:
            raise ValueError("default_deny cannot have matched_rule_ids")

        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "matched_rule_ids", rule_ids)
