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

Install the core package and development tools:

```bash
python -m pip install -e ".[dev]"
```

Install the optional middleware for LangChain agents built on LangGraph:

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
```

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

The resource resolver must describe the same resource the wrapped function actually accesses. For multi-user applications, the principal resolver must read request-scoped trusted context; do not capture one user's identity in a process-wide shared tool.

## Optional agent middleware

The optional module `langgraph_secure_agents.middleware` provides `create_authorization_middleware` for LangChain agents built on LangGraph. It intercepts tool calls before execution. By default, the policy action is `execute` and the resource is the tool name. Custom resolvers can map tool calls to domain-level actions and resources.

The middleware receives runtime context from the agent invocation. The application must configure a principal resolver that validates this context and creates a `Principal` from trusted identity data. Denied calls return an error tool message and do not invoke the tool handler.

## Validation

```bash
ruff check .
ruff format --check .
mypy src
pytest
```

GitHub Actions runs these checks across Python 3.11, 3.12, and 3.13 on pull requests and pushes to `main`.

## Roadmap

- [x] Typed package foundation, license, and CI
- [x] Policy models and default-deny evaluation
- [x] Deny-overrides semantics and constrained wildcards
- [x] Guarded callable and fail-closed auditing
- [x] Optional agent tool-call middleware
- [x] Model-free LangGraph workflow example with mock payroll data
- [ ] Example conversational agent using a model provider
- [ ] Human-approval integration for selected sensitive actions
- [x] Initial threat model and security reporting guidance
- [ ] API review and release-readiness checks

## License

MIT. See [LICENSE](LICENSE).

## Disclaimer

This project is experimental and is not a substitute for a complete application security review. Integrators remain responsible for authenticating principals, validating trusted context, enforcing tenant boundaries, and protecting downstream resources.
