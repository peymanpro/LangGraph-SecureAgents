# Security Policy

## Project status

LangGraph-SecureAgents is experimental and has not received an independent security audit. The current pre-release API is not a production security certification.

## Reporting a vulnerability

Please do not publish exploitable vulnerability details, credentials, personal data, or sensitive logs in a public issue.

Use GitHub's private vulnerability reporting for this repository if it is enabled. If private reporting is unavailable, contact the maintainer privately through the maintainer's GitHub profile before public disclosure.

When reporting, include the affected commit or version, a concise impact description, reproducible steps, and a minimal proof of concept that does not expose real data.

## Security expectations and limitations

- The application integrating this library remains responsible for authenticating users and deriving Principal objects from trusted identity data.
- Authorization context must not be copied blindly from user-controlled request fields or LLM-generated output.
- Protected tools must enforce authorization against the same resource they actually access; configure resource resolvers carefully.
- Downstream services and data stores should continue to enforce their own access controls.
- The library does not provide authentication, tenant isolation, rate limiting, prompt-injection prevention, secret management, or a human reviewer service. Its optional approval interrupt binds fingerprints to LangGraph checkpoint execution scope and fails closed if the required metadata/checkpointer is unavailable. The fingerprint itself is not a reviewer credential and is not a one-time token. The host application must authenticate reviewers, authorize access to the exact paused run, secure the resume endpoint, use unique per-operation IDs, and durably consume approvals once for side-effecting tools. The optional `approval_validator` hook can enforce reviewer validation and atomic durable consumption at the middleware boundary; never back it with process-local state for multi-worker deployments.
- Security behavior should be verified against the exact version and policy configuration being deployed.

Do not use this experimental project as the sole security boundary for production or sensitive data.
