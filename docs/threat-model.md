# Threat Model

## Scope

LangGraph-SecureAgents provides deterministic policy evaluation and optional enforcement at Python-callable and LangChain agent tool-call boundaries, plus explicitly decorated MCP server tool-handler boundaries when the optional MCP adapter is installed. It is designed to reduce accidental or model-induced access to tools and resources that the application has explicitly protected. The MCP adapter does not automatically protect MCP resources, prompts, or handlers that have not been decorated.

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

Versioned PolicyBundle files provide strict JSON/YAML parsing, immutable in-memory rules, a policy ID/version, a content digest, lint diagnostics, rule explanations, and candidate-versus-baseline simulation. Parsing rejects unknown schema fields and duplicate JSON/YAML keys. Lint results are advisory and do not change enforcement; teams should make lint findings and simulation results part of their own release process.

The SHA-256 bundle digest identifies serialized content; it is not a signature and does not prove origin or authenticity. The optional PolicyRegistry atomically publishes complete snapshots within one process, supports generation checks, and retains a bounded in-memory rollback history. It does not persist registry history, watch files automatically, coordinate multiple worker processes, authenticate deployers, or sign policy delivery. Protect policy files and their deployment pipeline as security-sensitive configuration.

### Resolver purity and underlying resource

Action and resource resolvers take part in authorization decisions. Mutating input arguments during scope resolution can cause the policy target to differ from what a protected operation later consumes. The library supplies detached copies to these resolvers and fails closed when it detects input mutation or cannot validate that the copies remain unchanged. Resolver callbacks must still be trusted application code and must not have unrelated side effects.

### Protected operation and underlying resource

A wrapper only guards the callable or tool handler to which it is applied. The configured resource resolver must identify the same tenant and resource that the operation actually accesses. If the resolver checks one resource while the function accesses another, authorization can be bypassed.

Downstream APIs, databases, and storage systems should continue enforcing their own authorization and tenant boundaries.

### Auditing

The library supports both the legacy request/decision callback and structured AuditEvent callbacks. Structured serializers and the optional OpenTelemetry adapter redact principal/resource identifiers, matched rule IDs, policy digests, and correlation IDs by default. A custom callback receives the full event object, including sensitive identifiers, and must send it only to a trusted sink. Request attribute values and raw tool arguments are not copied into the event.

Configured callbacks run synchronously before a protected callable or tool handler executes. Callback failure stops protected execution (fail-closed behavior). For approval-required middleware calls, the structured callback records the pending policy decision before the interrupt and the final approval outcome after resume. SQLiteAuditSink provides synchronous local persistence and a verifiable hash chain, but the host remains responsible for database access control, backups, retention/archival, capacity monitoring, remote delivery, and external anchoring of chain heads. Without a configured callback, the library does not persist audit logs.

## Authorization semantics

- Requests are denied by default when no allow rule matches.
- An explicit matching deny rule overrides matching allow rules.
- Actions and resources use exact matching, except for a standalone wildcard selector.
- When a rule specifies both principal IDs and roles, both constraints must match.
- A REQUIRE_APPROVAL policy returns a non-allowing decision and the optional LangGraph middleware pauses before tool execution. Its request fingerprint covers the principal and its attributes, roles, tool call, canonical JSON arguments, resource attributes, context attributes, action, resource, matched policy definitions including ABAC conditions, and LangGraph execution scope (`thread_id`, `checkpoint_id`, `checkpoint_ns`, and `task_id`). Approval-required calls fail closed when this metadata or an active checkpointer is unavailable. This makes an identical request in a different checkpoint produce a different fingerprint. The fingerprint does not authenticate a reviewer. The optional SQLiteApprovalStore issues short-lived opaque tokens, stores only a token hash, binds grants to the request fingerprint and reviewer ID, and atomically consumes a grant once before a handler executes. The host must still authenticate reviewers, authorize access to the resume endpoint, derive reviewer identity from trusted server-side state, ensure operation IDs are unique, and issue a grant only after approving that exact pending request. The alternative `approval_validator` callback can implement equivalent controls with another transactional backend. Without either mechanism, the middleware's legacy fingerprint check is not sufficient for side-effecting operations. Applications must not treat a normal allow decision as evidence of human approval.

### Attribute-based authorization

Policy rules may use typed conditions over principal attributes, resource attributes, and request context. Each condition must match; a missing attribute does not satisfy a comparison or membership operator. Only NOT_EXISTS explicitly matches a missing path. Attribute paths are validated and resolved through mapping lookups; the engine never evaluates Python code or arbitrary policy expressions.

The application must populate principal attributes from authenticated, validated identity claims; resource attributes from the actual resource being accessed; and context from trusted server-side request state. In particular, tenant matching only helps prevent cross-tenant access when the supplied resource attributes describe the same tenant and resource that the protected operation actually reads or modifies. This library does not automatically secure database queries or discover resource ownership.

Attribute values are recursively frozen and restricted to JSON-compatible data. Comparisons are type-aware so that values such as boolean true and integer 1 are not treated as equivalent. Unsupported operands fail the condition rather than granting access.

## In-scope threats

| Threat | Intended mitigation | Remaining responsibility |
|---|---|---|
| A tool is invoked without an allow rule | Default-deny policy evaluation | Define correct policy coverage |
| A deny rule conflicts with an allow rule | Deny-overrides semantics | Review policy changes |
| Model output claims the caller has a role | Identity comes from a trusted resolver | Authenticate users and validate claims |
| A denied tool call would otherwise execute | Enforcement occurs before delegation | Protect every sensitive execution path |
| Audit callback is configured but unavailable | Fail closed on callback failure; SQLiteAuditSink commits before returning | Manage access, backups, retention, capacity, and external integrity anchors |
| A scope resolver mutates input arguments | Pass detached copies and reject detected mutation | Keep resolver callbacks trusted and side-effect-free |
| A stale deployer overwrites a newer policy | Registry generation compare-and-swap rejects stale publication | Coordinate deployments across processes |
| An approval response is replayed for a different checkpointed execution | Bind the fingerprint to canonical JSON, exact matched rule definitions, and runtime execution scope | Authenticate reviewers and protect the resume endpoint |
| An approval is reused for an identical side-effecting operation | SQLiteApprovalStore checks fingerprint, reviewer, expiry, and unconsumed status in one transaction | Authenticate the reviewer and secure the resume endpoint |

## Out of scope

This library does not itself provide:

- Authentication, session management, or identity-provider integration.
- Database-level security or automatic tenant isolation. ABAC can compare trusted tenant/resource attributes, but the application must populate them correctly and guard every sensitive execution path.
- Prevention of prompt injection, model hallucinations, data exfiltration through tools that are not guarded, or unsafe model-generated code.
- Rate limiting, secrets management, encryption, network security, or denial-of-service protection.
- A human reviewer service or proof that an approval came from an authorized reviewer; the host application must supply these. The SQLite approval store manages grants, not identity or reviewer authorization.
- Cross-process policy distribution, persistent policy history, signed policy delivery, or automatic filesystem watching.
- Automatic audit retention, asynchronous delivery/retry queues, or protection against an actor who can rewrite the entire SQLite audit database and recompute its hash chain.
- Formal verification, certification, or an independent security audit.

## Deployment checklist

- Authenticate the caller before starting an agent run.
- Build principal identity and roles from trusted, validated server-side claims.
- Do not permit untrusted clients to set privileged graph runtime context.
- Prefer explicit action/resource policies; keep wildcard rules rare and reviewed.
- Populate principal attributes from trusted identity claims and resource attributes from the actual resource being accessed; never trust LLM-produced or client-supplied tenant identifiers.
- Use resource resolvers that bind the authorization target to the exact resource and tenant used by the protected operation.
- Apply guards to every path that can invoke a sensitive operation.
- Keep downstream authorization enabled.
- Configure SQLiteAuditSink or another durable audit callback when audit persistence is required; plan backups, retention, and external integrity anchoring.
- For approval-required side effects, configure SQLiteApprovalStore and derive the reviewer ID from authenticated server-side resume context; do not rely on the fingerprint alone.
- For policy rollout, use PolicyRegistry generation checks and coordinate publication across all worker processes.
- Test denied requests, role changes, resource substitution, missing policy matches, and attempted identity spoofing.
- Review PolicyBundle lint findings and compare candidate policies against representative baseline requests before deployment.
- Record the policy ID, semantic version, and content digest with your own deployment/audit metadata; do not treat the digest as a signature.
- Pin and review dependencies; run the project's CI against the version being deployed.
- Do not deploy this pre-release library as the sole control for production-sensitive resources.
