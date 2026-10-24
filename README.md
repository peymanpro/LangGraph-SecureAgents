# LangGraph-SecureAgents

**Deterministic access control for LangGraph-powered agents.**

LangGraph-SecureAgents is an experimental Python library for enforcing authorization at agent tool-execution boundaries. Agent orchestration may be handled by LangGraph; authorization decisions are made by trusted application code, never by an LLM.

> **Status:** early development. The policy engine, guarded-callable primitive, and optional agent middleware are implemented, but the API is not stable and has not received an independent security audit. Do not use this project to protect production data yet.

## Security principles

Read the [threat model](docs/threat-model.md) for trust boundaries and deployment guidance, and [SECURITY.md](SECURITY.md) for vulnerability reporting and security limitations.

1. **Default deny:** no matching allow policy means access is denied.
2. **Deny overrides:** an explicit deny rule wins over any matching allow rule.
3. **Deterministic authorization:** model output cannot grant permissions.
4. **Enforce at execution:** evaluate policy immediately before a protected operation.
5. **Trusted identity:** the application must resolve principal identity and roles from authenticated context, never from LLM-controlled tool arguments.
6. **Fail closed:** resolver or configured audit failures prevent protected execution.
7. **Least privilege:** rules specify a principal or role, action, and resource.

## Installation

Requires Python 3.11 or newer.

### Install the published package

After the first PyPI release is available, install the alpha package with its optional agent middleware:

```bash
python -m pip install --pre "langgraph-secure-agents[langchain-agents]"
```

For the core policy engine and callable guard without LangGraph middleware:

```bash
python -m pip install --pre langgraph-secure-agents
```

The `--pre` flag is needed while the latest published version is an alpha pre-release. Until the package is available on PyPI, use the source-install instructions below.

### Install from a source checkout

Clone this repository, then install the core package and development tools:

```bash
python -m pip install -e ".[dev]"
```

Install the optional middleware dependencies from the same checkout:

```bash
python -m pip install -e ".[langchain-agents]"
```

The core policy engine and callable guard do not require LangGraph or an LLM provider.

## Run the model-free LangGraph example

The example uses fake payroll records and a trusted runtime context. It needs no model API key:

```bash
python examples/policy_guarded_workflow.py
```

It demonstrates an allowed HR request, a denied request for an unapproved resource, and a denied request from a user without the required role.

## Quick start: deterministic policy engine

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
            principal_ids=frozenset(),
            roles=frozenset({"analyst"}),
            actions=frozenset({"read"}),
            resources=frozenset({"reports"}),
        )
    ]
)

decision = policy.evaluate(
    AccessRequest(
        principal=Principal("user-123", roles=frozenset({"analyst"})),
        action="read",
        resource="reports",
    )
)

assert decision.allowed
assert decision.reason is DecisionReason.EXPLICIT_ALLOW
```

### Decision outcomes and policy updates

`Decision.reason` is a public `DecisionReason` enum with stable machine-readable values: `explicit_allow`, `explicit_deny`, `default_deny`, `approval_required`, `approval_invalid`, `approval_denied`, and `human_approved`. Use the enum constants in application code rather than comparing free-form strings. `matched_rule_ids` identifies the policy rules responsible for a rule-based outcome; a default-deny decision has no matched rule IDs. `requires_approval` is true only for `approval_required`.

A `PolicyEngine`'s rules cannot be replaced after construction. To deploy a policy change, construct and validate a new engine, then switch the application to it using the application's own configuration/reload mechanism. Do not mutate private state on a live engine. This matters for approval pauses: the request fingerprint binds approval to the matched rule definitions, so a resumed decision must still refer to the policy that produced the interrupt.

## Protect a Python callable

```python
from langgraph_secure_agents import PolicyEngine, Principal, protect_callable

# This resolver must read a trusted, request-scoped identity source.
current_principal = lambda: Principal("user-123", roles=frozenset({"analyst"}))

protected_lookup = protect_callable(
    lookup_report,
    policy=policy,
    principal_resolver=current_principal,
    action="read",
    resource_resolver=lambda report_id: f"report:{report_id}",
)
```

The resource resolver must describe the same resource the wrapped function actually accesses. Resolver callbacks receive detached copies of arguments, and attempts to mutate those copies fail closed before execution. Resolvers must otherwise be trusted, side-effect-free application code. For multi-user applications, the principal resolver must read request-scoped trusted context; do not capture one user's identity in a process-wide shared tool.

## Optional agent middleware

The optional module `langgraph_secure_agents.middleware` provides `create_authorization_middleware` for LangChain agents built on LangGraph. It intercepts tool calls before execution. By default, the policy action is `execute` and the resource is the tool name. Custom resolvers can map tool calls to domain-level actions and resources.

The middleware receives runtime context from the agent invocation. The application must configure a principal resolver that validates this context and creates a `Principal` from trusted identity data. Custom action/resource resolvers receive detached copies of tool arguments; attempts to mutate these copies fail closed. Denied calls return an error tool message and do not invoke the tool handler.

## Human approval for sensitive actions

A policy can explicitly require approval instead of granting access immediately:

```python
approval_policy = PolicyEngine(
    [
        PolicyRule(
            rule_id="approval-required-payroll-read",
            effect=Effect.REQUIRE_APPROVAL,
            actions=frozenset({"read"}),
            resources=frozenset({"payroll:employee-7"}),
            roles=frozenset({"hr"}),
        )
    ]
)
```

When this policy is used with the optional agent middleware, LangGraph pauses at an interrupt before the tool handler executes. The paused payload describes the principal, action, resource, policy rule, tool, and a request fingerprint. After a reviewer makes a decision, the host application resumes the same checkpoint/thread with a value shaped like:

```python
{
    "approved": True,
    "request_fingerprint": fingerprint_from_interrupt_payload,
}
```

The middleware rejects missing, malformed, or mismatched approval responses. The fingerprint binds the response to the current principal, roles, tool call, arguments, action, resource, exact matched policy definitions, and LangGraph execution scope (`thread_id`, `checkpoint_id`, `checkpoint_ns`, and `task_id`). This makes the fingerprint different in another checkpointed execution even when request fields and the tool-call ID are repeated. Approval-required calls need LangGraph 1.2 or newer with an active checkpointer; missing execution metadata fails closed. Fingerprinting rejects non-string JSON object keys, non-finite numbers, cyclic structures, and other non-JSON argument values. **The fingerprint is a deterministic request-binding check, not proof of reviewer identity, permission, or one-time use.** The host application must authenticate the reviewer, authorize who can resume the paused run, and protect the resume endpoint. For side-effecting tools, ensure request IDs are unique per operation and durably consume each approval once. The `approval_validator` callback described below can enforce reviewer validation and atomic consumption at the middleware boundary. An explicit matching deny rule always takes precedence over approval.

For deployments that need enforcement in the library boundary, pass an `approval_validator` callback to `create_authorization_middleware`. It receives the resumed approval mapping, the resolved `AccessRequest`, and the request fingerprint. It should authenticate and authorize the reviewer, then atomically claim/consume the fingerprint in a durable store; return the literal `True` only for a valid first use. A false or non-boolean result rejects the approval, and an exception fails closed by preventing tool execution. Implement this callback with your application's identity provider and transactional storage—do not use an in-memory set for multi-process or persistent workloads. The callback is invoked for validly-shaped approval and rejection responses, so the host can consume either human decision once. If the callback is omitted, the host must enforce these controls outside the library. An explicit matching deny rule always takes precedence over approval.

## Validation

```bash
ruff check .
ruff format --check .
mypy src
pytest
```

GitHub Actions runs these checks across Python 3.11, 3.12, and 3.13 on pull requests and pushes to `main`, with a 98% minimum line-coverage gate. A separate packaging job builds both a wheel and source distribution, validates metadata, smoke-tests the installed wheel in a clean environment, and installs the `langchain-agents` extra in a separate environment to verify the optional middleware dependencies.

After a change is merged into `main`, the automatic release workflow analyzes Conventional Commit messages. If a release-worthy change exists and all release quality checks pass, it updates the version and changelog, creates a version commit and Git tag, builds distributions, creates a GitHub Release, and publishes to PyPI using Trusted Publishing. No manual tag creation is required. See [the release process](docs/releasing.md).

## Roadmap

- [x] Typed package foundation, license, and CI
- [x] Policy models and default-deny evaluation
- [x] Deny-overrides semantics and constrained wildcards
- [x] Guarded callable and fail-closed auditing
- [x] Optional agent tool-call middleware
- [x] Model-free LangGraph workflow example with mock payroll data
- [ ] Example conversational agent using a model provider
- [x] Human-approval interrupt integration for selected sensitive actions
- [x] Initial threat model and security reporting guidance
- [ ] API review and release-readiness checks

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for user-facing changes and release notes.

## License

MIT. See [LICENSE](LICENSE).

## Disclaimer

This project is experimental and is not a substitute for a complete application security review. Integrators remain responsible for authenticating principals, validating trusted context, enforcing tenant boundaries, and protecting downstream resources.
