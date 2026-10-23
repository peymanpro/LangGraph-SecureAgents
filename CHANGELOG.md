# Changelog

Notable user-facing changes are recorded here. This project follows PEP 440 versioning; pre-release versions may include API changes.

## Unreleased

- Prepare the first public alpha distribution.
- Document deterministic policy evaluation, callable protection, optional LangChain/LangGraph middleware, and checkpoint-bound human-approval handling.
- Explicitly document host-application responsibilities for identity, reviewer authentication, approval consumption, and downstream authorization.

## 0.1.0a0

Initial alpha scope:

- Immutable authorization models and deterministic policy evaluation.
- Default-deny and deny-overrides semantics with constrained wildcard selectors.
- Synchronous and asynchronous Python callable protection.
- Optional LangChain agent middleware for LangGraph tool execution.
- Human-approval interrupts with request fingerprints bound to the execution scope and matched policy definitions.
- Fail-closed behavior for configured audit/resolver errors and malformed approval responses.
- Threat model, security reporting guidance, model-free example, CI, distribution smoke tests, and automated GitHub/PyPI release workflow.

This alpha has not received an independent security audit and is not suitable as the sole security boundary for production or sensitive data.
