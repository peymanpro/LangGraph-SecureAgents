# LangGraph-SecureAgents

**Deterministic authorization for LangGraph-powered agents.**

[![PyPI version](https://img.shields.io/pypi/v/langgraph-secure-agents)](https://pypi.org/project/langgraph-secure-agents/)
[![Python versions](https://img.shields.io/pypi/pyversions/langgraph-secure-agents)](https://pypi.org/project/langgraph-secure-agents/)
[![CI](https://img.shields.io/github/actions/workflow/status/peymanpro/LangGraph-SecureAgents/ci.yml?branch=main&label=CI)](https://github.com/peymanpro/LangGraph-SecureAgents/actions/workflows/ci.yml)
[![Latest GitHub release](https://img.shields.io/github/v/release/peymanpro/LangGraph-SecureAgents)](https://github.com/peymanpro/LangGraph-SecureAgents/releases)
[![MIT License](https://img.shields.io/github/license/peymanpro/LangGraph-SecureAgents)](LICENSE)

LangGraph-SecureAgents evaluates authorization in trusted application code and enforces decisions immediately before protected Python callables, agent tools, and—when the optional MCP adapter is installed—explicitly decorated MCP server tool handlers execute. LangGraph can orchestrate the agent; **an LLM cannot grant itself permissions**.

**Security model:** Authorization is enforced at the callable and agent-tool boundaries you configure. The integrating application remains responsible for authenticating callers, constructing principals from trusted context, mapping each request to the actual resource being accessed, decorating every sensitive MCP tool handler, and retaining downstream access controls. See the [threat model](docs/threat-model.md) for the trust boundaries and deployment guidance.

## What it provides

- **Deterministic policy evaluation** with default-deny behavior and explicit-deny rules taking precedence over allow rules.
- **Role- and attribute-based access control (RBAC/ABAC)**, including conditions over trusted principal, resource, and request-context attributes.
- **Versioned policy bundles** that load declarative JSON/YAML rules, lint risky scopes, explain decisions, and simulate proposed changes against a baseline. An in-process policy registry adds atomic publication, generation checks, and rollback.
- **Structured authorization audit events** with privacy-conscious serialization, an optional OpenTelemetry adapter, and a durable SQLite sink with a verifiable hash chain.
- **Callable protection** with `protect_callable`, so authorization is checked immediately before execution.
- **Optional LangGraph node guard** via `protect_node`, which authorizes selected sensitive graph nodes using trusted runtime context before the original node executes.
- **Optional LangChain agent middleware** that checks tool calls before the tool handler runs.
- **Optional MCP server tool decorator** that evaluates policies inside each registered MCP handler, without relying on the MCP SDK's provisional generic middleware hook.
- **Human-approval interrupts** for selected sensitive agent actions, with SQLite-backed expiring approval tokens that are bound to a reviewer and consumed once.
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

For the optional LangGraph node guard:

```bash
python -m pip install "langgraph-secure-agents[langgraph]"
```

For the optional MCP server tool adapter:

```bash
python -m pip install "langgraph-secure-agents[mcp]"
```

For the optional OpenTelemetry audit adapter:

```bash
python -m pip install "langgraph-secure-agents[opentelemetry]"
```

The core policy engine does not require an LLM provider, the optional agent middleware, MCP SDK, or telemetry dependencies.

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

### Atomic policy rollout with `PolicyRegistry`

`PolicyRegistry` publishes fully validated policy snapshots atomically within one process. Pass the registry itself to a guard or middleware so each invocation captures one consistent policy and its matching metadata:

```python
from langgraph_secure_agents import PolicyBundle, PolicyRegistry

registry = PolicyRegistry(PolicyBundle.from_file("policies/payroll.yaml"))
current = registry.snapshot()

deployed = registry.reload(
    "policies/payroll-v2.yaml",
    expected_generation=current.generation,
)
# If a rollout needs to be reversed, rollback publishes the prior snapshot
# as a new generation: registry.rollback(expected_generation=deployed.generation)
```

The registry is process-local: it does not persist history or synchronize workers. Coordinate rollouts across processes and reload trusted policy files after restart. Generation checks prevent stale updates within the registry, but do not authenticate deployers or sign policy bundles. See the [policy bundle guide](docs/policy-bundles.md).

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

For approval-required tool calls, the middleware records the policy's `approval_required` decision before interrupting. After resume, it emits a second event for the final `human_approved`, `approval_denied`, or `approval_invalid` outcome. This distinguishes the policy decision from the human-review result. For synchronous durable recording, pass a `SQLiteAuditSink` as `audit_event_callback`; persistence errors fail closed. It does not create a background retry queue or retention policy. See the [audit guide](docs/audit-events.md).

See the [audit event guide](docs/audit-events.md) for the event schema, redaction contract, callback behavior, and operational guidance.

### Durable SQLite audit storage

When an audit record must be committed before protected code runs, use `SQLiteAuditSink` as the structured callback:

```python
from langgraph_secure_agents import SQLiteAuditSink
from langgraph_secure_agents.middleware import create_authorization_middleware

audit_sink = SQLiteAuditSink("authorization-audit.sqlite3")
authorization_middleware = create_authorization_middleware(
    policy,
    principal_resolver=resolve_principal,
    audit_event_callback=audit_sink,
)

# Check the integrity of the retained hash chain when operationally appropriate.
integrity = audit_sink.verify_integrity()
```

Writes are synchronous; a persistence error propagates and prevents the protected handler from running. The hash chain can reveal individual record edits, deletion, or reordering, but it is not tamper-proof if someone can rewrite the entire database and recompute the chain. The sink has no automatic retention, archive, or retry queue. Restrict database access, back it up, monitor capacity, define retention procedures, and consider anchoring chain heads in a separately controlled system. See the [audit guide](docs/audit-events.md).

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

## Optional LangGraph node protection

Use `protect_node` when a sensitive operation is implemented as a LangGraph node and you want a policy check immediately before that node's body runs. This is a separate integration from the LangChain agent middleware, which protects tool calls.

```python
from collections.abc import Mapping
from typing import TypedDict

from langgraph.runtime import Runtime
from langgraph_secure_agents import PolicyEngine, Principal
from langgraph_secure_agents.langgraph import protect_node

class RequestContext(TypedDict):
    user_id: str
    roles: list[str]


def resolve_principal(context: object) -> Principal:
    # The host must populate this context from authenticated server-side data.
    if not isinstance(context, Mapping):
        raise TypeError("expected trusted runtime context")
    return Principal(str(context["user_id"]), roles=frozenset(context["roles"]))


def refund_node(state: dict[str, str], runtime: Runtime[RequestContext]) -> dict[str, bool]:
    # Call the actual domain operation here.
    return {"completed": True}


protected_node = protect_node(
    refund_node,
    policy=policy,
    principal_resolver=resolve_principal,
    action="refund",
    resource_resolver=lambda state: f"order:{state['order_id']}",
)
builder.add_node("refund", protected_node)
```

The node must declare a LangGraph `Runtime` parameter (for example `runtime: Runtime[RequestContext]`), and the host should pass trusted identity through `graph.invoke(..., context=...)`. The resource resolver must identify the same order the protected operation actually modifies; graph state and model-generated arguments are not trusted identity or authorization evidence.

Only explicitly wrapped nodes are guarded. A deny, missing allow rule, resolver error, or configured audit callback failure stops the original node from running. `Effect.REQUIRE_APPROVAL` is not an allow: this node guard denies it before execution rather than creating an interrupt. Use the existing checkpointed tool approval flow for human review of protected agent tool calls. See the [LangGraph integration guide](docs/langgraph-integration.md) and [threat model](docs/threat-model.md).

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

For sensitive actions, a policy can use `Effect.REQUIRE_APPROVAL` to pause execution for a human decision. This requires LangGraph 1.2 or newer with an active checkpointer. The host must still authenticate the reviewer and secure the resume endpoint. Configure `SQLiteApprovalStore` and `approval_reviewer_resolver` to require a short-lived opaque token bound to the exact request fingerprint and trusted reviewer identity. The token is consumed atomically before the handler runs. See the [approval-store guide](docs/approval-store.md).

### Configure durable, one-time approval grants

```python
from langgraph_secure_agents import SQLiteApprovalStore
from langgraph_secure_agents.middleware import create_authorization_middleware

approval_store = SQLiteApprovalStore("authorization-approvals.sqlite3")
authorization_middleware = create_authorization_middleware(
    policy,
    principal_resolver=resolve_principal,
    approval_store=approval_store,
    approval_reviewer_resolver=resolve_trusted_reviewer,
)
```

`resolve_trusted_reviewer` must derive the reviewer from authenticated, server-side state—not from model output or the approval payload. The host must verify that the reviewer may approve the exact pending operation before issuing a token. Use a persistent database path when grants must survive restarts, keep token lifetimes short, and never reuse operation IDs or request fingerprints. Expired rows are not deleted automatically; call `approval_store.purge_expired()` according to your retention requirements. The store binds and consumes grants, but does not authenticate reviewers or protect the resume endpoint.

## Optional MCP tool authorization

For an MCP server built with MCP Python SDK v2, apply `protect_mcp_tool` inside the server's tool decorator. The adapter enforces the policy before the original handler runs, preserves the handler signature so the SDK can inject its trusted `Context` object, and emits structured `mcp_tool` audit events when configured.

```python
from mcp.server import MCPServer
from mcp.server.mcpserver import Context

from langgraph_secure_agents import PolicyEngine, Principal
from langgraph_secure_agents.mcp_adapter import protect_mcp_tool

server = MCPServer("Customer service")


@server.tool()
@protect_mcp_tool(
    policy=PolicyEngine(...),
    principal_resolver=principal_from_trusted_auth,
    action="read",
    resource_resolver=lambda args: f"customer:{args['customer_id']}",
    resource_attributes_resolver=load_trusted_customer_attributes,
)
def read_customer(customer_id: str, ctx: Context) -> str:
    return customer_store.read(customer_id)
```

The host must derive identity from trusted authentication state; do not trust model arguments or caller-controlled headers. The adapter fails closed when authorization or configured auditing fails. It does not implement MCP-side human approval interrupts; use the LangGraph approval flow for checkpointed reviewer interactions. See the [MCP integration guide](docs/mcp-integration.md) and [secured MCP server example](examples/mcp_secure_server.py).

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

Run the model-free LangGraph node-guard example as well:

```bash
python examples/langgraph_protected_node.py
```

The example shows one allowed HR request and two denied requests: one for an unapproved resource and one from a caller without the required role.

### End-to-end security workflow

Run the complete model-free scenario:

```bash
python examples/secure_agent_workflow.py
```

The example uses the actual policy engine, LangGraph checkpointed interrupt, SQLite approval store, and SQLite audit sink. It demonstrates that a same-tenant customer read succeeds, a cross-tenant read is denied before the handler runs, a refund pauses until a reviewer-bound one-time grant is issued, and replaying that grant against another execution is rejected. At the end it prints the executed operations, audit decision reasons, and audit-chain integrity result.

The default run uses temporary SQLite files and removes them on exit. To retain the local databases for inspection, pass a directory:

```bash
python examples/secure_agent_workflow.py --data-dir ./.secure-agent-demo
```

The reviewer identity in this example is supplied by a server-side `ContextVar` to model trusted resume-endpoint state. This is a runnable demonstration, not a production authentication service: a real host must authenticate the reviewer, authorize approval of the exact pending action, protect the resume endpoint, and manage database access, backups, and retention.

## Development and testing

Install the development dependencies from a source checkout:

```bash
python -m pip install -e ".[dev]"
ruff check .
ruff format --check .
mypy src
pytest --cov=langgraph_secure_agents --cov-report=term-missing --cov-fail-under=98
```

CI tests Python 3.11, 3.12, and 3.13, checks linting, formatting, and types, and enforces a 98% minimum line-coverage threshold. The packaging workflow also validates the wheel and source distribution and smoke-tests the installed package, optional middleware extra, optional MCP extra, and optional OpenTelemetry extra.

## Project documentation

- [Threat model](docs/threat-model.md) — trust boundaries, intended mitigations, and remaining application responsibilities.
- [LangGraph integration](docs/langgraph-integration.md) — protecting selected graph nodes with trusted runtime context, deterministic authorization, and explicit limits.
- [Policy bundles](docs/policy-bundles.md) — declarative format, validation, lint, simulation, and atomic policy-registry operations.
- [Approval store](docs/approval-store.md) — expiring one-time grants and trusted reviewer binding.
- [End-to-end security workflow](examples/secure_agent_workflow.py) — model-free customer access, human-approved refund, replay rejection, and audit verification.
- [MCP integration](docs/mcp-integration.md) — handler-level authorization, trusted Context, and optional MCP SDK setup.
- [Secured MCP server example](examples/mcp_secure_server.py) — a runnable MCP server with tenant-aware access control.
- [Audit events](docs/audit-events.md) — structured decision events, SQLite persistence, integrity verification, privacy controls, and OpenTelemetry integration.
- [Security policy](SECURITY.md) — project status and vulnerability reporting.
- [Changelog](CHANGELOG.md) — user-facing changes by release.
- [Releasing](docs/releasing.md) — maintainer information about automated releases.

## License

MIT. See [LICENSE](LICENSE).
