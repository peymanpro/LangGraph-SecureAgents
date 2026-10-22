"""Immutable domain models for authorization decisions."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum


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


class Effect(StrEnum):
    """The effect a matching policy rule has on an access request."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclass(frozen=True, slots=True)
class Principal:
    """An authenticated identity supplied by trusted application code.

    This object does not authenticate users. Applications must construct it
    from a trusted identity source, never directly from untrusted LLM output.
    """

    principal_id: str
    roles: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        normalized_id = _normalized_text(self.principal_id, "principal_id")
        object.__setattr__(self, "principal_id", normalized_id)
        object.__setattr__(
            self,
            "roles",
            _normalized_set(self.roles, "roles", allow_empty=True),
        )


@dataclass(frozen=True, slots=True)
class AccessRequest:
    """A concrete request to perform an action on a resource."""

    principal: Principal
    action: str
    resource: str

    def __post_init__(self) -> None:
        if not isinstance(self.principal, Principal):
            raise ValueError("principal must be a Principal instance")
        action = _normalized_text(self.action, "action")
        resource = _normalized_text(self.resource, "resource")
        if action == "*" or resource == "*":
            raise ValueError("access requests must name a concrete action and resource")
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "resource", resource)


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """A policy rule with explicit subject, action, resource, and effect.

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

        object.__setattr__(self, "actions", actions)
        object.__setattr__(self, "resources", resources)
        object.__setattr__(self, "principal_ids", principal_ids)
        object.__setattr__(self, "roles", roles)


@dataclass(frozen=True, slots=True)
class Decision:
    """A deterministic authorization outcome and its explainable basis."""

    allowed: bool
    reason: str
    matched_rule_ids: tuple[str, ...] = ()
    requires_approval: bool = False

    def __post_init__(self) -> None:
        if type(self.allowed) is not bool:
            raise ValueError("allowed must be a boolean")

        reason = _normalized_text(self.reason, "reason")
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

        if self.requires_approval != (reason == "approval_required"):
            raise ValueError(
                "requires_approval must be true exactly when reason is 'approval_required'"
            )

        denied_reasons = {
            "explicit_deny",
            "default_deny",
            "approval_required",
            "approval_invalid",
            "approval_denied",
        }
        allowed_reasons = {"explicit_allow", "human_approved"}
        if self.allowed and reason in denied_reasons:
            raise ValueError(f"reason {reason!r} cannot describe an allowed decision")
        if not self.allowed and reason in allowed_reasons:
            raise ValueError(f"reason {reason!r} cannot describe a denied decision")

        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "matched_rule_ids", rule_ids)
