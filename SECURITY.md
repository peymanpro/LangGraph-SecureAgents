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
- The library does not currently provide authentication, tenant isolation, rate limiting, prompt-injection prevention, secret management, or built-in human approval.
- Security behavior should be verified against the exact version and policy configuration being deployed.

Do not use this experimental project as the sole security boundary for production or sensitive data.
