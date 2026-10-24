"""Run a model-free policy bundle lint, explanation, and migration simulation."""

from __future__ import annotations

import json
from pathlib import Path

from langgraph_secure_agents import (
    AccessRequest,
    Effect,
    PolicyBundle,
    PolicyRule,
    Principal,
)


def make_request(
    *,
    principal_id: str,
    tenant_id: str,
    resource_tenant_id: str,
    classification: str = "internal",
    action: str = "read",
) -> AccessRequest:
    return AccessRequest(
        principal=Principal(
            principal_id,
            roles=frozenset({"analyst"}),
            attributes={"tenant_id": tenant_id},
        ),
        action=action,
        resource="payroll",
        resource_attributes={
            "tenant_id": resource_tenant_id,
            "classification": classification,
        },
        context={"environment": "production"},
    )


def main() -> None:
    bundle_path = Path(__file__).parent / "policies" / "payroll.yaml"
    candidate = PolicyBundle.from_file(bundle_path)

    findings = candidate.lint()
    print(f"Policy: {candidate.policy_id} v{candidate.version}")
    print(f"SHA-256: {candidate.digest}")
    print(f"Lint findings: {len(findings)}")
    for finding in findings:
        print(f"- {finding.severity.value} {finding.code}: {finding.message}")

    baseline = PolicyBundle(
        policy_id=candidate.policy_id,
        version="0.9.0",
        description="Illustrative previous version before tenant and classification checks.",
        rules=(
            PolicyRule(
                rule_id="legacy-analysts-read-payroll",
                effect=Effect.ALLOW,
                actions=frozenset({"read"}),
                resources=frozenset({"payroll"}),
                roles=frozenset({"analyst"}),
            ),
            PolicyRule(
                rule_id="legacy-analysts-delete-payroll",
                effect=Effect.ALLOW,
                actions=frozenset({"delete"}),
                resources=frozenset({"payroll"}),
                roles=frozenset({"analyst"}),
            ),
        ),
    )

    scenarios = (
        make_request(
            principal_id="alice",
            tenant_id="tenant-a",
            resource_tenant_id="tenant-a",
        ),
        make_request(
            principal_id="bob",
            tenant_id="tenant-a",
            resource_tenant_id="tenant-b",
        ),
        make_request(
            principal_id="carol",
            tenant_id="tenant-a",
            resource_tenant_id="tenant-a",
            classification="restricted",
        ),
        make_request(
            principal_id="dana",
            tenant_id="tenant-a",
            resource_tenant_id="tenant-a",
            action="delete",
        ),
    )

    report = candidate.simulate(scenarios, baseline=baseline)
    print("\\nCandidate-versus-baseline simulation:")
    print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))

    explanation = candidate.explain(scenarios[1])
    print("\\nWhy the cross-tenant request was denied:")
    print(json.dumps(explanation.to_dict(), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
