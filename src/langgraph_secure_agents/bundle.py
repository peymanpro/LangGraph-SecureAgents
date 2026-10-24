"""Versioned, portable policy bundles for declarative authorization."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import AttributeCondition, AttributeReference, Effect, PolicyRule
from .policy import PolicyEngine

_SCHEMA_VERSION = 1
_SEMVER_PATTERN = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?"
)
_BUNDLE_KEYS = {"schema_version", "policy_id", "version", "description", "rules"}
_RULE_KEYS = {"rule_id", "effect", "actions", "resources", "principal_ids", "roles", "conditions"}
_CONDITION_KEYS = {"attribute", "operator", "value", "value_from"}


def _required_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value.strip()


def _reject_unknown_keys(
    value: Mapping[str, object],
    allowed: set[str],
    required: set[str],
    *,
    where: str,
) -> None:
    unknown = set(value) - allowed
    missing = required - set(value)
    if unknown:
        raise ValueError(f"{where} contains unknown field(s): {', '.join(sorted(unknown))}")
    if missing:
        raise ValueError(f"{where} is missing required field(s): {', '.join(sorted(missing))}")


def _plain_json(value: object) -> object:
    """Convert immutable JSON-like values into ordinary JSON containers."""

    if isinstance(value, Mapping):
        return {key: _plain_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain_json(item) for item in value]
    return value


def _condition_to_dict(condition: AttributeCondition) -> dict[str, object]:
    result: dict[str, object] = {
        "attribute": condition.attribute,
        "operator": condition.operator.value,
    }
    if isinstance(condition.value, AttributeReference):
        result["value_from"] = condition.value.path
    elif condition.operator.value not in {"exists", "not_exists"}:
        result["value"] = _plain_json(condition.value)
    return result


def _rule_to_dict(rule: PolicyRule) -> dict[str, object]:
    return {
        "rule_id": rule.rule_id,
        "effect": rule.effect.value,
        "actions": sorted(rule.actions),
        "resources": sorted(rule.resources),
        "principal_ids": sorted(rule.principal_ids),
        "roles": sorted(rule.roles),
        "conditions": [_condition_to_dict(condition) for condition in rule.conditions],
    }


def _parse_condition(value: object, index: int) -> AttributeCondition:
    where = f"rules[].conditions[{index}]"
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{where} must be an object with string keys")
    condition = dict(value)
    _reject_unknown_keys(
        condition,
        _CONDITION_KEYS,
        {"attribute", "operator"},
        where=where,
    )
    has_value = "value" in condition
    has_reference = "value_from" in condition
    if has_value and has_reference:
        raise ValueError(f"{where} cannot contain both 'value' and 'value_from'")
    if has_reference and not isinstance(condition["value_from"], str):
        raise ValueError(f"{where}.value_from must be an attribute path")
    if has_reference:
        operand: object = AttributeReference(condition["value_from"])
    elif has_value:
        operand = condition["value"]
    else:
        operand = None
    if condition["operator"] not in {"exists", "not_exists"} and not has_value and not has_reference:
        raise ValueError(f"{where} requires 'value' or 'value_from'")
    if condition["operator"] in {"exists", "not_exists"} and (has_value or has_reference):
        raise ValueError(f"{where} does not accept 'value' or 'value_from'")
    return AttributeCondition(
        attribute=_required_text(condition["attribute"], f"{where}.attribute"),
        operator=_required_text(condition["operator"], f"{where}.operator"),  # type: ignore[arg-type]
        value=operand,  # type: ignore[arg-type]
    )


def _parse_rule(value: object, index: int) -> PolicyRule:
    where = f"rules[{index}]"
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{where} must be an object with string keys")
    rule = dict(value)
    _reject_unknown_keys(rule, _RULE_KEYS, _RULE_KEYS, where=where)
    conditions_value = rule["conditions"]
    if not isinstance(conditions_value, list):
        raise ValueError(f"{where}.conditions must be a list")
    for selector in ("actions", "resources", "principal_ids", "roles"):
        if not isinstance(rule[selector], list) or any(
            not isinstance(item, str) for item in rule[selector]
        ):
            raise ValueError(f"{where}.{selector} must be a list of strings")
    if not isinstance(rule["effect"], str):
        raise ValueError(f"{where}.effect must be a string")
    return PolicyRule(
        rule_id=_required_text(rule["rule_id"], f"{where}.rule_id"),
        effect=rule["effect"],  # type: ignore[arg-type]
        actions=frozenset(rule["actions"]),  # type: ignore[arg-type]
        resources=frozenset(rule["resources"]),  # type: ignore[arg-type]
        principal_ids=frozenset(rule["principal_ids"]),  # type: ignore[arg-type]
        roles=frozenset(rule["roles"]),  # type: ignore[arg-type]
        conditions=tuple(_parse_condition(item, i) for i, item in enumerate(conditions_value)),
    )


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"JSON policy bundle contains duplicate key {key!r}")
        result[key] = value
    return result


def _reject_non_json_constant(value: str) -> None:
    raise ValueError(f"JSON policy bundle contains unsupported constant {value!r}")


@dataclass(frozen=True, slots=True)
class PolicyBundle:
    """Immutable versioned policy configuration that can be validated and deployed.

    Bundle versions use semantic-version syntax. The schema version is independent
    from the policy's own version and allows future format migrations.
    """

    policy_id: str
    version: str
    rules: tuple[PolicyRule, ...]
    description: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "policy_id", _required_text(self.policy_id, "policy_id"))
        version = _required_text(self.version, "version")
        if not _SEMVER_PATTERN.fullmatch(version):
            raise ValueError("version must be a semantic version such as '1.0.0'")
        object.__setattr__(self, "version", version)
        if not isinstance(self.description, str):
            raise ValueError("description must be a string")
        if isinstance(self.rules, (str, bytes)):
            raise ValueError("rules must be a collection of PolicyRule instances")
        try:
            rules = tuple(self.rules)
        except TypeError as exc:
            raise ValueError("rules must be a collection of PolicyRule instances") from exc
        PolicyEngine(rules)
        object.__setattr__(self, "rules", rules)

    @property
    def schema_version(self) -> int:
        """Return the bundle format version."""

        return _SCHEMA_VERSION

    @property
    def engine(self) -> PolicyEngine:
        """Create a deterministic engine from this immutable bundle."""

        return PolicyEngine(self.rules)

    @property
    def digest(self) -> str:
        """Return a stable SHA-256 digest of the canonical bundle representation."""

        canonical = json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible dictionary representation."""

        return {
            "schema_version": self.schema_version,
            "policy_id": self.policy_id,
            "version": self.version,
            "description": self.description,
            "rules": [_rule_to_dict(rule) for rule in self.rules],
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        """Serialize the bundle as JSON with stable rule/selector representation."""

        return json.dumps(
            self.to_dict(),
            indent=indent,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )

    @classmethod
    def from_dict(cls, value: object) -> PolicyBundle:
        """Parse and validate a bundle dictionary; unknown fields are rejected."""

        if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
            raise ValueError("policy bundle must be an object with string keys")
        payload = dict(value)
        _reject_unknown_keys(payload, _BUNDLE_KEYS, _BUNDLE_KEYS - {"description"}, where="bundle")
        if payload["schema_version"] != _SCHEMA_VERSION:
            raise ValueError(f"unsupported policy bundle schema_version: {payload['schema_version']!r}")
        if not isinstance(payload["rules"], list):
            raise ValueError("bundle.rules must be a list")
        if "description" in payload and not isinstance(payload["description"], str):
            raise ValueError("bundle.description must be a string")
        return cls(
            policy_id=_required_text(payload["policy_id"], "policy_id"),
            version=_required_text(payload["version"], "version"),
            description=payload.get("description", ""),  # type: ignore[arg-type]
            rules=tuple(_parse_rule(rule, i) for i, rule in enumerate(payload["rules"])),
        )

    @classmethod
    def from_json(cls, content: str) -> PolicyBundle:
        """Parse strict JSON, rejecting duplicate keys and non-standard constants."""

        if not isinstance(content, str):
            raise TypeError("content must be a JSON string")
        try:
            payload = json.loads(
                content,
                object_pairs_hook=_reject_duplicate_json_keys,
                parse_constant=_reject_non_json_constant,
            )
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid policy bundle JSON: {exc.msg}") from exc
        except RecursionError as exc:
            raise ValueError("policy bundle JSON is nested too deeply") from exc
        return cls.from_dict(payload)

    @classmethod
    def from_yaml(cls, content: str) -> PolicyBundle:
        """Parse a YAML bundle using PyYAML's safe loader (optional dependency)."""

        if not isinstance(content, str):
            raise TypeError("content must be a YAML string")
        try:
            import yaml
        except ImportError as exc:
            raise ImportError(
                "YAML support requires PyYAML; install 'langgraph-secure-agents[yaml]'"
            ) from exc
        try:
            payload = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            raise ValueError(f"invalid policy bundle YAML: {exc}") from exc
        return cls.from_dict(payload)

    def to_yaml(self) -> str:
        """Serialize as YAML, requiring the optional PyYAML dependency."""

        try:
            import yaml
        except ImportError as exc:
            raise ImportError(
                "YAML support requires PyYAML; install 'langgraph-secure-agents[yaml]'"
            ) from exc
        return yaml.safe_dump(self.to_dict(), sort_keys=True, allow_unicode=True)
