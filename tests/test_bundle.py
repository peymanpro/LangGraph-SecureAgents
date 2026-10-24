from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from langgraph_secure_agents import (
    AttributeCondition,
    AttributeReference,
    ConditionOperator,
    Effect,
    PolicyRule,
)
from langgraph_secure_agents.bundle import PolicyBundle


def sample_bundle() -> PolicyBundle:
    return PolicyBundle(
        policy_id="payroll-access",
        version="1.2.0",
        description="Controls access to payroll data",
        rules=(
            PolicyRule(
                rule_id="analysts-read-own-tenant",
                effect=Effect.ALLOW,
                actions=frozenset({"read"}),
                resources=frozenset({"payroll"}),
                roles=frozenset({"analyst"}),
                conditions=(
                    AttributeCondition(
                        "principal.attributes.tenant_id",
                        ConditionOperator.EQ,
                        AttributeReference("resource.attributes.tenant_id"),
                    ),
                    AttributeCondition(
                        "context.environment",
                        ConditionOperator.IN,
                        ["prod", "stage"],
                    ),
                ),
            ),
            PolicyRule(
                rule_id="deny-restricted",
                effect=Effect.DENY,
                actions=frozenset({"read"}),
                resources=frozenset({"payroll"}),
                principal_ids=frozenset({"contractor-1"}),
                conditions=(
                    AttributeCondition(
                        "resource.attributes.classification",
                        ConditionOperator.EQ,
                        "restricted",
                    ),
                ),
            ),
        ),
    )


def test_json_bundle_round_trip_preserves_policy_and_digest() -> None:
    original = sample_bundle()

    encoded = original.to_json()
    restored = PolicyBundle.from_json(encoded)

    assert restored == original
    assert restored.to_dict() == original.to_dict()
    assert restored.digest == original.digest
    assert len(original.digest) == 64
    assert original.schema_version == 1


def test_canonical_digest_does_not_depend_on_mapping_key_insertion_order() -> None:
    first = PolicyBundle.from_dict(
        {
            "schema_version": 1,
            "policy_id": "sample",
            "version": "1.0.0",
            "description": "",
            "rules": [
                {
                    "rule_id": "rule-one",
                    "effect": "allow",
                    "actions": ["read"],
                    "resources": ["reports"],
                    "principal_ids": [],
                    "roles": ["analyst"],
                    "conditions": [
                        {
                            "attribute": "context.profile",
                            "operator": "eq",
                            "value": {"department": "hr", "level": 2},
                        }
                    ],
                }
            ],
        }
    )
    second = PolicyBundle.from_dict(
        {
            "rules": [
                {
                    "conditions": [
                        {
                            "value": {"level": 2, "department": "hr"},
                            "operator": "eq",
                            "attribute": "context.profile",
                        }
                    ],
                    "roles": ["analyst"],
                    "principal_ids": [],
                    "resources": ["reports"],
                    "actions": ["read"],
                    "effect": "allow",
                    "rule_id": "rule-one",
                }
            ],
            "description": "",
            "version": "1.0.0",
            "policy_id": "sample",
            "schema_version": 1,
        }
    )

    assert first.digest == second.digest


def test_policy_bundle_builds_a_policy_engine() -> None:
    bundle = sample_bundle()

    assert bundle.engine.rules == bundle.rules


def test_json_bundle_rejects_duplicate_keys() -> None:
    with pytest.raises(ValueError, match="duplicate key"):
        PolicyBundle.from_json(
            '{"schema_version":1,"policy_id":"first","policy_id":"second",'
            '"version":"1.0.0","rules":[]}'
        )


def test_json_bundle_rejects_duplicate_nested_keys() -> None:
    text = json.dumps(sample_bundle().to_dict())
    text = text.replace(
        '"rule_id": "analysts-read-own-tenant"',
        '"rule_id": "first", "rule_id": "second"',
    )

    with pytest.raises(ValueError, match="duplicate key"):
        PolicyBundle.from_json(text)


def test_json_bundle_rejects_non_standard_numbers() -> None:
    with pytest.raises(ValueError, match="unsupported constant"):
        PolicyBundle.from_json(
            '{"schema_version":1,"policy_id":"sample","version":"1.0.0",'
            '"rules":[],"description":"","risk":NaN}'
        )


@pytest.mark.parametrize("content", ["", "{", "not json", "[]"])
def test_json_bundle_rejects_invalid_documents(content: str) -> None:
    with pytest.raises((ValueError, TypeError)):
        PolicyBundle.from_json(content)


def test_bundle_rejects_unknown_fields() -> None:
    payload = sample_bundle().to_dict()
    payload["unexpected"] = True

    with pytest.raises(ValueError, match="unknown field"):
        PolicyBundle.from_dict(payload)


def test_bundle_requires_metadata_fields() -> None:
    with pytest.raises(ValueError, match="missing required field"):
        PolicyBundle.from_dict({"schema_version": 1, "policy_id": "sample"})


@pytest.mark.parametrize("schema_version", [0, 2, "1"])
def test_bundle_rejects_unsupported_schema_version(schema_version: object) -> None:
    payload = sample_bundle().to_dict()
    payload["schema_version"] = schema_version

    with pytest.raises(ValueError, match="unsupported policy bundle schema_version"):
        PolicyBundle.from_dict(payload)


@pytest.mark.parametrize("version", ["", "latest", "1.0", "01.0.0"])
def test_bundle_requires_semantic_policy_version(version: str) -> None:
    with pytest.raises(ValueError, match="semantic version"):
        PolicyBundle(policy_id="sample", version=version, rules=())


def test_bundle_metadata_and_rules_are_validated() -> None:
    with pytest.raises(ValueError, match="policy_id must be a non-empty string"):
        PolicyBundle(policy_id=" ", version="1.0.0", rules=())

    with pytest.raises(ValueError, match="semantic version"):
        PolicyBundle(policy_id="sample", version=None, rules=())  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="description must be a string"):
        PolicyBundle(policy_id="sample", version="1.0.0", rules=(), description=None)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="collection of PolicyRule"):
        PolicyBundle(policy_id="sample", version="1.0.0", rules="not-rules")  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="PolicyRule"):
        PolicyBundle(policy_id="sample", version="1.0.0", rules=("not-a-rule",))  # type: ignore[arg-type]


def test_bundle_rejects_invalid_rule_and_condition_shapes() -> None:
    payload = sample_bundle().to_dict()
    payload["rules"] = ["not-a-rule"]

    with pytest.raises(ValueError, match=r"rules\[0\] must be an object"):
        PolicyBundle.from_dict(payload)

    payload = sample_bundle().to_dict()
    payload["rules"][0]["unexpected"] = "field"  # type: ignore[index]

    with pytest.raises(ValueError, match="unknown field"):
        PolicyBundle.from_dict(payload)

    payload = sample_bundle().to_dict()
    payload["rules"][0]["conditions"] = "not-a-list"  # type: ignore[index]

    with pytest.raises(ValueError, match="conditions must be a list"):
        PolicyBundle.from_dict(payload)


def test_bundle_rejects_invalid_selector_and_condition_shapes() -> None:
    payload = sample_bundle().to_dict()
    payload["rules"][0]["actions"] = "read"  # type: ignore[index]

    with pytest.raises(ValueError, match="actions must be a list of strings"):
        PolicyBundle.from_dict(payload)

    payload = sample_bundle().to_dict()
    payload["rules"][0]["effect"] = 123  # type: ignore[index]

    with pytest.raises(ValueError, match="effect must be a string"):
        PolicyBundle.from_dict(payload)

    payload = sample_bundle().to_dict()
    payload["rules"][0]["conditions"][0]["value"] = "literal"  # type: ignore[index]

    with pytest.raises(ValueError, match="both 'value' and 'value_from'"):
        PolicyBundle.from_dict(payload)


def test_bundle_rejects_malformed_attribute_references_and_conditions() -> None:
    payload = sample_bundle().to_dict()
    payload["rules"][0]["conditions"][0]["value_from"] = 42  # type: ignore[index]

    with pytest.raises(ValueError, match="value_from must be an attribute path"):
        PolicyBundle.from_dict(payload)

    payload = sample_bundle().to_dict()
    payload["rules"][0]["conditions"][0]["value_from"] = "context"  # type: ignore[index]

    with pytest.raises(ValueError, match="attribute path"):
        PolicyBundle.from_dict(payload)

    payload = sample_bundle().to_dict()
    payload["rules"][0]["conditions"][0]["operator"] = "unknown"  # type: ignore[index]

    with pytest.raises(ValueError, match="supported ConditionOperator"):
        PolicyBundle.from_dict(payload)

    payload = sample_bundle().to_dict()
    payload["rules"][0]["conditions"][0]["unexpected"] = True  # type: ignore[index]

    with pytest.raises(ValueError, match="unknown field"):
        PolicyBundle.from_dict(payload)


def test_yaml_round_trip_uses_safe_serialization() -> None:
    original = sample_bundle()

    restored = PolicyBundle.from_yaml(original.to_yaml())

    assert restored == original
    assert restored.digest == original.digest


def test_yaml_support_can_be_absent_without_breaking_core_bundle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = sample_bundle()

    with monkeypatch.context() as patcher:
        patcher.setitem(sys.modules, "yaml", None)
        with pytest.raises(ImportError, match=r"install 'langgraph-secure-agents\[yaml\]'"):
            original.to_yaml()
        with pytest.raises(ImportError, match=r"install 'langgraph-secure-agents\[yaml\]'"):
            PolicyBundle.from_yaml("schema_version: 1")

    assert PolicyBundle.from_json(original.to_json()) == original


def test_lint_warns_when_bundle_is_empty() -> None:
    bundle = PolicyBundle(policy_id="empty", version="1.0.0", rules=())

    findings = bundle.lint()

    assert [(item.code, item.severity.value) for item in findings] == [("BND001", "warning")]


def test_lint_flags_wildcard_allow_and_universal_principal() -> None:
    bundle = PolicyBundle(
        policy_id="broad-access",
        version="1.0.0",
        rules=(
            PolicyRule(
                rule_id="all-access",
                effect=Effect.ALLOW,
                actions=frozenset({"*"}),
                resources=frozenset({"*"}),
                principal_ids=frozenset({"*"}),
            ),
        ),
    )

    findings = bundle.lint()

    assert {item.code for item in findings} == {"SEC001", "SEC002"}
    assert all(item.rule_id == "all-access" for item in findings)
    assert all(item.severity.value == "warning" for item in findings)


def test_lint_reports_broad_approval_scope_as_informational() -> None:
    bundle = PolicyBundle(
        policy_id="approval",
        version="1.0.0",
        rules=(
            PolicyRule(
                rule_id="review-everything",
                effect=Effect.REQUIRE_APPROVAL,
                actions=frozenset({"*"}),
                resources=frozenset({"payroll"}),
                roles=frozenset({"analyst"}),
            ),
        ),
    )

    findings = bundle.lint()

    assert [(item.code, item.severity.value) for item in findings] == [("APR001", "info")]


def test_lint_reports_duplicate_conditions_once_per_rule() -> None:
    duplicate = AttributeCondition("context.environment", ConditionOperator.EQ, "prod")
    bundle = PolicyBundle(
        policy_id="duplicates",
        version="1.0.0",
        rules=(
            PolicyRule(
                rule_id="duplicated-condition",
                effect=Effect.ALLOW,
                actions=frozenset({"read"}),
                resources=frozenset({"reports"}),
                roles=frozenset({"analyst"}),
                conditions=(duplicate, duplicate),
            ),
        ),
    )

    findings = bundle.lint()

    assert [(item.code, item.rule_id) for item in findings] == [("POL001", "duplicated-condition")]


def test_lint_is_quiet_for_narrow_policy_rules() -> None:
    bundle = PolicyBundle(
        policy_id="narrow",
        version="1.0.0",
        rules=(
            PolicyRule(
                rule_id="alice-reads-report-42",
                effect=Effect.ALLOW,
                actions=frozenset({"read"}),
                resources=frozenset({"report:42"}),
                principal_ids=frozenset({"alice"}),
            ),
        ),
    )

    assert bundle.lint() == ()


def test_file_round_trip_supports_json_and_yaml(tmp_path: Path) -> None:
    bundle = sample_bundle()
    json_path = tmp_path / "policy.json"
    yaml_path = tmp_path / "policy.yaml"

    assert bundle.to_file(json_path) == json_path
    assert PolicyBundle.from_file(json_path) == bundle

    assert bundle.to_file(yaml_path) == yaml_path
    assert PolicyBundle.from_file(yaml_path) == bundle


def test_file_api_rejects_unsupported_extensions(tmp_path: Path) -> None:
    bundle = sample_bundle()
    invalid_path = tmp_path / "policy.txt"

    with pytest.raises(ValueError, match="must use .json"):
        bundle.to_file(invalid_path)

    with pytest.raises(ValueError, match="must use .json"):
        PolicyBundle.from_file(invalid_path)


def test_yaml_parser_rejects_duplicate_keys_and_malformed_yaml() -> None:
    duplicate = """
schema_version: 1
schema_version: 1
policy_id: sample
version: 1.0.0
rules: []
"""
    with pytest.raises(ValueError, match="duplicate key"):
        PolicyBundle.from_yaml(duplicate)

    with pytest.raises(ValueError, match="invalid policy bundle YAML"):
        PolicyBundle.from_yaml("schema_version: [")


def test_bundle_rejects_boolean_schema_version_and_non_string_condition_operator() -> None:
    payload = sample_bundle().to_dict()
    payload["schema_version"] = True

    with pytest.raises(ValueError, match="unsupported policy bundle schema_version"):
        PolicyBundle.from_dict(payload)

    payload = sample_bundle().to_dict()
    payload["rules"][0]["conditions"][0]["operator"] = ["eq"]  # type: ignore[index]

    with pytest.raises(ValueError, match="operator must be a string"):
        PolicyBundle.from_dict(payload)


def test_bundle_parser_rejects_malformed_condition_objects() -> None:
    payload = sample_bundle().to_dict()
    payload["rules"][0]["conditions"] = ["not-an-object"]  # type: ignore[index]
    with pytest.raises(ValueError, match="must be an object with string keys"):
        PolicyBundle.from_dict(payload)

    payload = sample_bundle().to_dict()
    payload["rules"][0]["conditions"][0]["attribute"] = 42  # type: ignore[index]
    with pytest.raises(ValueError, match="attribute must be a string"):
        PolicyBundle.from_dict(payload)

    payload = sample_bundle().to_dict()
    payload["rules"][0]["conditions"][0]["operator"] = 42  # type: ignore[index]
    with pytest.raises(ValueError, match="operator must be a string"):
        PolicyBundle.from_dict(payload)

    payload = sample_bundle().to_dict()
    condition = payload["rules"][0]["conditions"][0]  # type: ignore[index]
    condition.pop("value_from")
    with pytest.raises(ValueError, match="requires 'value' or 'value_from'"):
        PolicyBundle.from_dict(payload)

    payload = sample_bundle().to_dict()
    condition = payload["rules"][0]["conditions"][0]  # type: ignore[index]
    condition["operator"] = "exists"
    with pytest.raises(ValueError, match="does not accept 'value' or 'value_from'"):
        PolicyBundle.from_dict(payload)

    payload = sample_bundle().to_dict()
    payload["rules"][0]["effect"] = "not-an-effect"  # type: ignore[index]
    with pytest.raises(ValueError, match="effect must be a supported effect"):
        PolicyBundle.from_dict(payload)


def test_bundle_parser_rejects_invalid_container_types() -> None:
    with pytest.raises(ValueError, match="collection of PolicyRule"):
        PolicyBundle(policy_id="sample", version="1.0.0", rules=42)  # type: ignore[arg-type]

    payload = sample_bundle().to_dict()
    payload["rules"] = "not-a-list"
    with pytest.raises(ValueError, match="bundle.rules must be a list"):
        PolicyBundle.from_dict(payload)

    payload = sample_bundle().to_dict()
    payload["description"] = 42
    with pytest.raises(ValueError, match="bundle.description must be a string"):
        PolicyBundle.from_dict(payload)

    with pytest.raises(TypeError, match="content must be a JSON string"):
        PolicyBundle.from_json(42)  # type: ignore[arg-type]

def test_json_parser_normalizes_recursion_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    from langgraph_secure_agents import bundle as bundle_module

    def raise_recursion_error(*args: object, **kwargs: object) -> object:
        raise RecursionError("parser depth exceeded")

    monkeypatch.setattr(bundle_module.json, "loads", raise_recursion_error)

    with pytest.raises(ValueError, match="nested too deeply"):
        PolicyBundle.from_json("{}")


def test_yaml_parser_rejects_non_string_and_unhashable_mapping_keys() -> None:
    with pytest.raises(TypeError, match="content must be a YAML string"):
        PolicyBundle.from_yaml(None)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="mapping keys must be hashable"):
        PolicyBundle.from_yaml("? [first, second]\n: invalid\n")
