# LangGraph-SecureAgents

**Deterministic authorization for LangGraph-powered agents.**

[![PyPI version](https://img.shields.io/pypi/v/langgraph-secure-agents)](https://pypi.org/project/langgraph-secure-agents/)
[![Python versions](https://img.shields.io/pypi/pyversions/langgraph-secure-agents)](https://pypi.org/project/langgraph-secure-agents/)
[![CI](https://img.shields.io/github/actions/workflow/status/peymanpro/LangGraph-SecureAgents/ci.yml?branch=main&label=CI)](https://github.com/peymanpro/LangGraph-SecureAgents/actions/workflows/ci.yml)
[![Latest GitHub release](https://img.shields.io/github/v/release/peymanpro/LangGraph-SecureAgents)](https://github.com/peymanpro/LangGraph-SecureAgents/releases)
[![MIT License](https://img.shields.io/github/license/peymanpro/LangGraph-SecureAgents)](LICENSE)

LangGraph-SecureAgents evaluates authorization in trusted application code and can enforce the decision immediately before a protected Python callable or agent tool executes. LangGraph can orchestrate the agent; **an LLM cannot grant itself permissions**.

**Security model:** Authorization is enforced at the callable and agent-tool boundaries you configure. The integrating application remains responsible for authenticating callers, constructing principals from trusted context, mapping each request to the actual resource being accessed, and retaining downstream access controls. See the [threat model](docs/threat-model.md) for the trust boundaries and deployment guidance.

## What it provides

- **Deterministic policy evaluation** with default-deny behavior and explicit-deny rules taking precedence over allow rules.
- **Role- and attribute-based access control (RBAC/ABAC)**, including conditions over trusted principal, resource, and request-context attributes.
- **Versioned policy bundles** that load declarative JSON/YAML rules, lint risky scopes, explain decisions, and simulate proposed changes against a baseline.
- **Structured authorization audit events** with privacy-conscious serialization and an optional OpenTelemetry adapter.
- **Callable protection** with `protect_callable`, so authorization is checked immediately before execution.
- **Optional LangChain agent middleware** that checks tool calls before the tool handler runs.
- **Human-approval interrupts** for selected sensitive agent actions.
- **Fail-closed controls** when configured audit callbacks or authorization-related checks fail.

## How it fits into an application

The host application authenticates the caller and constructs a trusted `Principal`. The policy engine then evaluates a concrete action/resource request before a guarded operation proceeds.

```text
Trusted application identity
           |
           v
        Principal
           |
           v
      PolicyEngine
           |
   allow / deny / approval
           |
           v
 Python callable or agent tool
           |
   execute only if authorized
```

The library does not authenticate users or make untrusted runtime context trustworthy. Those responsibilities stay with the application.

## Installation

Requires **Python 3.11 or newer**.

Install the core policy engine and callable guard:

```bash
python -m pip install langgraph-secure-agents
```

For the optional LangChain/LangGraph agent middleware:

```bash
python -m pip install "langgraph-secure-agents[langchain-agents]"
```

For the optional OpenTelemetry audit adapter:

```bash
python -m pip install "langgraph-secure-agents[opentelemetry]"
```

The core policy engine does not require an LLM provider, the optional agent middleware, or telemetry dependencies.

## Quick start: evaluate an authorization policy

This example requires no LLM or agent framework.

```python
from langgraph_secure_agents import (
    AccessRequest,
    DecisionReason,
    Effect,
    PolicyEngine,
    PolicyRule,
    Principal,
)

policy = PolicyEngine(
    [
        PolicyRule(
            rule_id="analysts-read-reports",
            effect=Effect.ALLOW,
            roles=frozenset({"analyst"}),
            actions=frozenset({"read"}),
            resources=frozenset({"reports"}),
        )
    ]
)

request = AccessRequest(
    principal=Principal("user-123", roles=frozenset({"analyst"})),
    action="read",
    resource="reports",
)

decision = policy.evaluate(request)

assert decision.allowed
assert decision.reason is DecisionReason.EXPLICIT_ALLOW
```

A request with no matching allow rule is denied by default. An explicit matching deny rule overrides an allow rule. Use the public `DecisionReason` enum for machine-readable outcomes rather than matching free-form text.

## Attribute-based access control (ABAC)

Policies can combine the existing principal/action/resource selectors with typed conditions over trusted principal attributes, resource attributes, and request context. Conditions on a rule are combined with AND. Missing attributes and incompatible comparison types fail closed; only the explicit `not_exists` operator matches a missing attribute.

The following policy permits analysts to read a document only when its tenant matches the authenticated principal's tenant. The host application must load both sets of attributes from trusted sources; never copy tenant identifiers or privileged attributes from model-generated tool arguments.

```python
from langgraph_secure_agents import (
    AccessRequest,
    AttributeCondition,
    AttributeReference,
    ConditionOperator,
    Effect,
    PolicyEngine,
    PolicyRule,
    Principal,
)

tenant_policy = PolicyEngine(
    [
        PolicyRule(
            rule_id="analysts-read-own-tenant-documents",
            effect=Effect.ALLOW,
            roles={"analyst"},
            actions={"read"},
            resources={"*"},
            conditions=(
                AttributeCondition(
                    attribute="principal.attributes.tenant_id",
                    operator=ConditionOperator.EQ,
                    value=AttributeReference("resource.attributes.tenant_id"),
                ),
            ),
        )
    ]
)

request = AccessRequest(
    principal=Principal(
        "user-123",
        roles=frozenset({"analyst"}),
        attributes={"tenant_id": "tenant-a"},  # Trusted authenticated identity data
    ),
    action="read",
    resource="document:42",
    resource_attributes={"tenant_id": "tenant-a"},  # Trusted resource metadata
)

assert tenant_policy.evaluate(request).allowed
```

Supported operators are `eq`, `ne`, `in`, `not_in`, `gt`, `gte`, `lt`, `lte`, `contains`, `exists`, and `not_exists`. Use `AttributeReference("context.environment")` or another validated attribute path to compare two attributes instead of hard-coding a value. Attribute paths are resolved using mapping lookups only; the library does not execute expressions or Python code from policy input.

`resource_attributes` and `context` must be populated by trusted server-side code. ABAC rules do not replace resource-level authorization in databases or APIs, and tenant isolation depends on supplying the actual resource attributes used by the protected operation.

The same conditions are supported by both callable guards and the optional agent middleware. For a callable guard, pass a `resource_attributes_resolver(resource_id)` to load trusted metadata for the resolved resource, plus a zero-argument `context_resolver()` for trusted request context. For the middleware, `resource_attributes_resolver(resource_id)` receives the resolved resource ID and `context_resolver(runtime_context)` selects trusted values from the host-supplied runtime context. Resolver results must describe the actual resource and must not copy authorization attributes from model-generated tool arguments.

## Versioned policy bundles

Keep authorization rules in a reviewed policy file instead of constructing every rule in application code. A bundle carries a stable policy ID, semantic version, schema version, validated rules, and a deterministic SHA-256 digest.

For JSON, no extra dependency is needed. To load or save YAML, install the optional extra:

~~~bash
python -m pip install "langgraph-secure-agents[yaml]"
~~~

~~~python
from langgraph_secure_agents import PolicyBundle

policy_bundle = PolicyBundle.from_file("policies/payroll.yaml")
policy = policy_bundle.engine

for finding in policy_bundle.lint():
    print(f"{finding.severity.value} {finding.code}: {finding.message}")

decision = policy.evaluate(request)
explanation = policy_bundle.explain(request)
~~~

The parser rejects duplicate JSON/YAML keys, unsupported schema versions, unknown fields, and malformed rules. Lint flags broad wildcard allows, universal-principal allows, broad approval scopes, and repeated conditions without silently changing policy behavior. Explanations show which selectors and conditions matched, but omit actual attribute values.

Before rollout, compare a candidate policy with the currently deployed bundle using a representative request set:

~~~python
report = candidate.simulate(test_requests, baseline=current_bundle)
print(report.to_dict()["summary"])
~~~

The report summarizes allowed, denied, approval-required, and changed outcomes without copying identities, resource IDs, or attributes into the report. A digest helps identify a bundle's exact content, but it is not a digital signature or proof of who authored it.

The repository includes [a payroll policy in YAML](examples/policies/payroll.yaml) and a runnable [bundle lint, explanation, and simulation example](examples/policy_bundle_workflow.py). See the full [policy bundle guide](docs/policy-bundles.md) for the format, diagnostic codes, and deployment trust boundaries.

## Structured audit events and OpenTelemetry

Use `audit_event_callback` to receive a typed `AuditEvent` for each authorization outcome at a protected callable or agent-tool boundary. Events include a unique event ID, UTC timestamp, source, action, resource, decision reason, matched-rule IDs, evaluation duration, and optional policy bundle metadata. Middleware events also carry the tool-call ID, runtime task ID, and tool name when available; callable guards can resolve trusted request and execution IDs.

```python
from langgraph_secure_agents import PolicyBundle, create_opentelemetry_callback
from langgraph_secure_agents.middleware import create_authorization_middleware

policy_bundle = PolicyBundle.from_file("policies/payroll.yaml")
audit_to_otel = create_opentelemetry_callback()

authorization_middleware = create_authorization_middleware(
    policy_bundle.engine,
    principal_resolver=resolve_principal,
    audit_event_callback=audit_to_otel,
    policy_id=policy_bundle.policy_id,
    policy_version=policy_bundle.version,
    policy_digest=policy_bundle.digest,
)
```

The adapter attaches an `authorization.decision` event to the current recording span; if no recording span is active, it creates a short span for the event. OpenTelemetry is optional and imported only when the adapter is configured. The original `audit_callback(request, decision)` remains supported.

**Privacy and failure behavior:** `AuditEvent.to_dict()`, `to_json()`, and the OpenTelemetry adapter omit principal IDs, roles, resource identifiers, matched rule IDs, and the policy digest by default. Set `include_sensitive=True` only when the destination is trusted to store that information. The event object delivered to a custom callback still contains its principal/resource identifiers, so custom sinks must protect them. Request attribute values, tool arguments, and model-generated content are not copied into the event. If a configured audit callback raises, the protected operation does not run.

For approval-required tool calls, the middleware records the policy's `approval_required` decision before interrupting. After resume, it emits a second event for the final `human_approved`, `approval_denied`, or `approval_invalid` outcome. This distinguishes the policy decision from the human-review result. Audit callbacks are synchronous and should hand events to a durable sink efficiently; the library does not provide storage or delivery retries.

See the [audit event guide](docs/audit-events.md) for the event schema, redaction contract, callback behavior, and operational guidance.

## Protect an existing Python callable

Wrap a function that accesses a protected resource. The resolver must identify the same resource that the function actually accesses.

```python
from langgraph_secure_agents import (
    Effect,
    PolicyEngine,
    PolicyRule,
    Principal,
    protect_callable,
)

report_policy = PolicyEngine(
    [
        PolicyRule(
            rule_id="analysts-read-report-123",
            effect=Effect.ALLOW,
            roles=frozenset({"analyst"}),
            actions=frozenset({"read"}),
            resources=frozenset({"report:123"}),
        )
    ]
)


def current_principal() -> Principal:
    # Replace with trusted, request-scoped identity from your application.
    return Principal("user-123", roles=frozenset({"analyst"}))


protected_lookup = protect_callable(
    lookup_report,  # Your existing function
    policy=report_policy,
    principal_resolver=current_principal,
    action="read",
    resource_resolver=lambda report_id: f"report:{report_id}",
)

# Authorization is checked before the protected function executes.
report = protected_lookup("123")
```

For multi-user applications, resolve identity from authenticated request context; do not capture one user's identity in a process-wide shared tool. Resolver logic and policy configuration are security-sensitive application code.

## Optional agent middleware

Install the `langchain-agents` extra and add the authorization middleware to a supported LangChain agent:

```python
from langgraph_secure_agents.middleware import create_authorization_middleware

authorization_middleware = create_authorization_middleware(
    policy,
    principal_resolver=resolve_principal,
)
```

Pass `authorization_middleware` to the agent's middleware configuration. `resolve_principal` must construct a `Principal` from trusted runtime context. By default, the policy action is `execute` and the resource is the tool name; custom resolvers can map tool calls to domain-specific actions and resources. A denied call returns an error tool message without invoking the tool handler.

For sensitive actions, a policy can use `Effect.REQUIRE_APPROVAL` to pause execution for a human decision. This requires LangGraph 1.2 or newer with an active checkpointer. The host application must authenticate the reviewer, secure the resume endpoint, and enforce one-time approval consumption for side-effecting operations. An approval fingerprint alone is not proof of reviewer identity or a one-time token.

## Security responsibilities

Integrators must:

- Authenticate callers and derive principals and roles from trusted, validated server-side data.
- Apply guards to every path that can invoke a sensitive operation.
- Ensure each resource resolver matches the exact resource and tenant used by the protected operation.
- Keep downstream services and data stores' own authorization controls enabled.
- Configure and operate durable audit storage when audit persistence is required.

This library does **not** provide authentication, automatic database-level tenant isolation, prompt-injection prevention, secrets management, rate limiting, or a human-reviewer service. Read the [threat model](docs/threat-model.md) and [security policy](SECURITY.md) before evaluating it for your use case.

## Run the example

The repository includes a model-free LangGraph workflow using mock payroll records. It needs no model API key:

```bash
python examples/policy_guarded_workflow.py
```

The example shows one allowed HR request and two denied requests: one for an unapproved resource and one from a caller without the required role.

## Development and testing

Install the development dependencies from a source checkout:

```bash
python -m pip install -e ".[dev]"
ruff check .
ruff format --check .
mypy src
pytest --cov=langgraph_secure_agents --cov-report=term-missing --cov-fail-under=98
```

CI tests Python 3.11, 3.12, and 3.13, checks linting, formatting, and types, and enforces a 98% minimum line-coverage threshold. The packaging workflow also validates the wheel and source distribution and smoke-tests the installed package and optional middleware extra.

## Project documentation

- [Threat model](docs/threat-model.md) — trust boundaries, intended mitigations, and remaining application responsibilities.
- [Policy bundles](docs/policy-bundles.md) — declarative format, validation, lint, explanation, and simulation.
- [Audit events](docs/audit-events.md) — structured decision events, privacy controls, and OpenTelemetry integration.
- [Security policy](SECURITY.md) — project status and vulnerability reporting.
- [Changelog](CHANGELOG.md) — user-facing changes by release.
- [Releasing](docs/releasing.md) — maintainer information about automated releases.

## License

MIT. See [LICENSE](LICENSE).
