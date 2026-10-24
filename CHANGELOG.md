# Changelog

User-facing changes for each published version. New release entries are inserted automatically by Python Semantic Release.

<!-- version list -->

## v0.2.0 (2026-10-24)

### Features

- **abac**: Add attribute-based authorization
  ([`6d78f3b`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/6d78f3b852990194b05819254b42cbdcd7a87adc))


## v0.1.1 (2026-10-24)

### Bug Fixes

- **release**: Publish every project update to PyPI
  ([`0b80b08`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/0b80b08028e595accc12900cfc46fc474868f5d4))

### Documentation

- Polish README for package users
  ([`2c7ad21`](https://github.com/peymanpro/LangGraph-SecureAgents/commit/2c7ad2158dad3f6fad6934a54f61a19db36aa0a6))


## 0.1.0

- Initial public release of the deterministic authorization policy engine.
- Default-deny policy evaluation with deny-overrides semantics and constrained wildcards.
- Synchronous and asynchronous callable protection.
- Optional LangChain/LangGraph agent middleware for tool-call authorization.
- Human-approval interrupts for selected sensitive actions.
- Security guidance covering trusted identity, resource resolution, auditing, and downstream enforcement.
