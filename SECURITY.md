# Security Policy

## Project status

LangGraph-SecureAgents is a pre-1.0 authorization library. It has not received an independent third-party security audit. Its guarantees depend on correct identity resolution, policy configuration, resource mapping, and applying enforcement to every sensitive execution path.

## Reporting a vulnerability

Please do not publish exploitable vulnerability details, credentials, personal data, or sensitive logs in a public issue.

Use GitHub's private vulnerability reporting for this repository if it is enabled. If private reporting is unavailable, contact the maintainer privately through the maintainer's GitHub profile before public disclosure.

When reporting, include the affected commit or version, a concise impact description, reproducible steps, and a minimal proof of concept that does not expose real data.

## Security expectations and limitations

- The application integrating this library remains responsible for authenticating users and deriving Principal objects from trusted identity data.
- Authorization context must not be copied blindly from user-controlled request fields or LLM-generated output.
- Protected tools must enforce authorization against the same resource they actually access; configure resource resolvers carefully.
- Downstream services and data stores should continue to enforce their own access controls.
- The library does not provide authentication, tenant isolation, rate limiting, prompt-injection prevention, secret management, or a human reviewer service. Its optional approval interrupt binds fingerprints to LangGraph checkpoint execution scope and fails closed if the required metadata/checkpointer is unavailable. The fingerprint itself is not a reviewer credential or a one-time token. For side-effecting tools, the host must authenticate reviewers, authorize access to the exact paused run, secure the resume endpoint, use unique per-operation IDs, and derive reviewer identity from trusted server-side state. `SQLiteApprovalStore` supplies expiring, reviewer-bound, atomic one-time grant consumption; alternatively, `approval_validator` can provide an equivalent transactional integration. Do not rely on the fingerprint check alone for side-effecting operations.
- Security behavior should be verified against the exact version and policy configuration being deployed.

Use the library as an authorization enforcement layer within a defense-in-depth design. Keep downstream authorization controls enabled, and review the threat model alongside your application's identity resolution, policy configuration, and resource mapping before deployment.
