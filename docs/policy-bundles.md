# Versioned policy bundles

A **PolicyBundle** packages a policy identifier, a semantic version, a format schema version, a description, and validated rules into a JSON or YAML file. It gives teams a declarative artifact to review and test instead of rebuilding policy objects in application code.

## Load and validate a policy file

JSON support is built into the package. YAML is optional:

    python -m pip install "langgraph-secure-agents[yaml]"

Load the included [payroll policy example](../examples/policies/payroll.yaml):

    from langgraph_secure_agents import PolicyBundle

    bundle = PolicyBundle.from_file("examples/policies/payroll.yaml")

    print(bundle.policy_id, bundle.version)
    print("SHA-256:", bundle.digest)

    for finding in bundle.lint():
        print(f"{finding.severity.value} {finding.code}: {finding.message}")

    policy = bundle.engine

The loader accepts .json, .yaml, and .yml. Parsing validates the schema and builds the same PolicyRule, AttributeCondition, and AttributeReference objects used by the core engine. It rejects unknown fields, unsupported schema versions, duplicate JSON/YAML keys, invalid selectors, malformed attribute paths, and invalid conditions. YAML uses PyYAML's safe loader and does not construct arbitrary Python objects.

The top-level fields are:

| Field | Meaning |
| --- | --- |
| schema_version | Bundle file format version. Currently 1. |
| policy_id | Stable identifier for the policy family, such as payroll-access. |
| version | Semantic version of this policy, such as 1.0.0. |
| description | Human-readable purpose of the policy. |
| rules | A list of rules. Each rule includes selectors and a list of conditions. |

Conditions use attribute and operator, plus either a literal value or a value_from attribute path. The two operand fields cannot be used together. For existence operators, omit both fields.

## Lint before rollout

bundle.lint() returns immutable diagnostics. Linting never changes a decision or weakens enforcement.

| Code | Meaning |
| --- | --- |
| BND001 | Empty bundle; every request will be denied by default. |
| SEC001 | An allow rule uses a wildcard action or resource. |
| SEC002 | An allow rule applies to every principal. |
| APR001 | An approval rule has a broad wildcard scope. |
| POL001 | A rule repeats an identical condition. |

Diagnostics contain a severity, a stable code, a message, and (where relevant) the rule ID. Applications can build their own release gates from these findings; the library does not silently rewrite or auto-approve broad policies.

## Explain decisions

Use bundle.explain(request) or bundle.engine.explain(request) to inspect the result and the rule-by-rule evaluation:

    explanation = bundle.explain(request)
    print(explanation.decision.reason)
    print(explanation.to_dict())

The explanation reports selector matches, condition outcomes, rule IDs, and reasons such as selector_mismatch and condition_failed. It intentionally omits actual principal, resource, context, and condition values so the explanation can be inspected without duplicating sensitive request data.

## Simulate a policy change

Use candidate.simulate(requests, baseline=current) to run the same sample requests through both versions before rollout:

    report = candidate.simulate(test_requests, baseline=current)
    summary = report.to_dict()["summary"]

    print(summary["total"])
    print(summary["allowed"], summary["denied"], summary["approval_required"])
    print("Effective outcomes changed:", summary["changed"])

The report compares effective outcomes (allow, deny, or approval required), records the input order as case indexes, and includes a decision summary for each case. It does not copy request identities, resource IDs, or attributes into the report. Keep the test input order stable if you need to correlate case indexes with your own fixtures.

The repository contains a runnable end-to-end example:

    python -m pip install "langgraph-secure-agents[yaml]"
    python examples/policy_bundle_workflow.py

The example loads the YAML policy, runs lint, compares it with a previous version against model-free test requests, and prints an explanation for a cross-tenant denial.

## Digest and deployment trust

bundle.digest is a deterministic SHA-256 digest of the canonical serialized bundle. It is useful for change detection, cache keys, and recording which artifact was evaluated. It is **not** a digital signature and does not prove who created the file. Verify provenance and integrity through your trusted deployment process, and only load policy files from locations controlled by trusted maintainers.

Bundles are immutable after construction. The optional `PolicyRegistry` provides in-process atomic publication, generation checks, and bounded rollback history:

    from langgraph_secure_agents import PolicyBundle, PolicyRegistry

    registry = PolicyRegistry(PolicyBundle.from_file("policies/payroll.json"))
    current = registry.snapshot()

    # Parse and validate the file before swapping the active snapshot.
    deployed = registry.reload(
        "policies/payroll-v2.json",
        expected_generation=current.generation,
    )
    print(deployed.generation, deployed.version, deployed.digest)

    # If the rollout is wrong, publish the previous snapshot as a new generation.
    restored = registry.rollback(expected_generation=deployed.generation)

The registry swaps a complete immutable snapshot under a lock. Each guarded callable or middleware invocation that receives the registry captures one snapshot and uses its policy engine and bundle metadata for that decision. An optional `expected_generation` implements compare-and-swap and rejects stale concurrent updates with `PolicyUpdateConflict`. Reusing a published semantic version with different content is rejected. The generation number increases on rollback; it is not rewound.

The registry is process-local: its history is not persisted, updates are not broadcast to other workers, and it does not watch the filesystem. In multi-worker deployments, coordinate validated bundle publication and rollout across workers, and reload a trusted bundle after process restart. The registry does not authenticate deployers, sign artifacts, or prove policy provenance.

The application must continue to construct principals and resource/context attributes from trusted sources and protect the same resource that the policy evaluates. This package does not provide database-level tenant isolation.
