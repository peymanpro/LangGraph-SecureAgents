# Threat Model

## Scope

LangGraph-SecureAgents provides deterministic policy evaluation and optional enforcement at Python-callable and LangChain agent tool-call boundaries. It is designed to reduce accidental or model-induced access to tools and resources that the application has explicitly protected.

This document describes the intended trust boundaries. It is not a security audit or a claim that every integration is safe by default.

## Assets

- Business records and other resources accessed by protected tools.
- Integrity of authorization decisions.
- Separation between principals, roles, actions, and resources.
- Availability and integrity of audit records when an audit callback is configured.

## Trust boundaries

### Trusted application identity

The host application authenticates the caller and supplies a Principal from trusted claims. The library does not authenticate users or verify the truth of principal IDs and roles.

For graph integrations, runtime context is separate from graph state, but its values are only trustworthy if the host application constructs them from a trusted source. Passing an unvalidated client-supplied context directly to a graph is not an authentication mechanism.

### Untrusted model output and tool arguments

LLM-generated tool names, arguments, and natural-language claims are untrusted. They must not independently determine principal identity or grant permissions. Middleware should resolve the principal from trusted runtime context and evaluate the policy before delegating to a tool handler.

### Policy configuration

Policy rules are application security configuration. Only trusted operators or code should define and change them. A permissive wildcard rule can intentionally grant broad access, so policy changes require review and regression tests.

### Resolver purity and underlying resource

Action and resource resolvers take part in authorization decisions. Mutating input arguments during scope resolution can cause the policy target to differ from what a protected operation later consumes. The library supplies detached copies to these resolvers and fails closed when it detects input mutation or cannot validate that the copies remain unchanged. Resolver callbacks must still be trusted application code and must not have unrelated side effects.

### Protected operation and underlying resource

A wrapper only guards the callable or tool handler to which it is applied. The configured resource resolver must identify the same tenant and resource that the operation actually accesses. If the resolver checks one resource while the function accesses another, authorization can be bypassed.

Downstream APIs, databases, and storage systems should continue enforcing their own authorization and tenant boundaries.

### Auditing

When an audit callback is configured, callback failure stops protected execution (fail-closed behavior). Without a callback, the library does not persist audit logs. Applications must decide how to secure, retain, and monitor audit events.

## Authorization semantics

- Requests are denied by default when no allow rule matches.
- An explicit matching deny rule overrides matching allow rules.
- Actions and resources use exact matching, except for a standalone wildcard selector.
- When a rule specifies both principal IDs and roles, both constraints must match.
- A REQUIRE_APPROVAL policy returns a non-allowing decision and the optional LangGraph middleware pauses before tool execution. Its request fingerprint covers the principal, roles, tool call, canonical JSON arguments, action, resource, exact matched policy definitions, and LangGraph execution scope (`thread_id`, `checkpoint_id`, `checkpoint_ns`, and `task_id`). Approval-required calls fail closed when execution metadata or an active checkpointer is unavailable. This binds the approval to one checkpointed execution, so an identical request in a different checkpoint receives a different fingerprint. The fingerprint does not authenticate a reviewer or by itself prevent replay of a completely identical request in the same execution. The host application must authenticate reviewers, authorize access to the resume endpoint, ensure per-operation IDs are unique, and durably consume each approval once for side-effecting tools. Applications must not treat a normal allow decision as evidence of human approval.

## In-scope threats

| Threat | Intended mitigation | Remaining responsibility |
|---|---|---|
| A tool is invoked without an allow rule | Default-deny policy evaluation | Define correct policy coverage |
| A deny rule conflicts with an allow rule | Deny-overrides semantics | Review policy changes |
| Model output claims the caller has a role | Identity comes from a trusted resolver | Authenticate users and validate claims |
| A denied tool call would otherwise execute | Enforcement occurs before delegation | Protect every sensitive execution path |
| Audit callback is configured but unavailable | Fail closed on callback failure | Operate a durable, secured audit backend |
| A scope resolver mutates input arguments | Pass detached copies and reject detected mutation | Keep resolver callbacks trusted and side-effect-free |
| An approval response is replayed for a different checkpointed execution | Bind the fingerprint to canonical JSON, exact matched rule definitions, and runtime execution scope | Authenticate reviewers and protect the resume endpoint |
| An approval is reused for an identical side-effecting operation | Fingerprint binds request contents but is not a one-time token | Require unique operation IDs and durable one-time approval consumption |

## Out of scope

This library does not itself provide:

- Authentication, session management, or identity-provider integration.
- Database-level security, tenant isolation, or protection from incorrectly implemented resource resolvers.
- Prevention of prompt injection, model hallucinations, data exfiltration through tools that are not guarded, or unsafe model-generated code.
- Rate limiting, secrets management, encryption, network security, or denial-of-service protection.
- A human reviewer service or proof that an approval came from an authorized reviewer; the host application must supply these.
- Formal verification, certification, or an independent security audit.

## Deployment checklist

- Authenticate the caller before starting an agent run.
- Build principal identity and roles from trusted, validated server-side claims.
- Do not permit untrusted clients to set privileged graph runtime context.
- Prefer explicit action/resource policies; keep wildcard rules rare and reviewed.
- Use resource resolvers that bind the authorization target to the exact resource and tenant used by the protected operation.
- Apply guards to every path that can invoke a sensitive operation.
- Keep downstream authorization enabled.
- Configure an audit callback and handle its failures deliberately.
- Test denied requests, role changes, resource substitution, missing policy matches, and attempted identity spoofing.
- Pin and review dependencies; run the project's CI against the version being deployed.
- Do not deploy this pre-release library as the sole control for production-sensitive resources.
