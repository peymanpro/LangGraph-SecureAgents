# LangGraph-SecureAgents

**Deterministic access control for LangGraph agents.**

LangGraph-SecureAgents is an early-stage Python library project for enforcing authorization at agent tool-execution boundaries. LangGraph orchestrates agent workflows; trusted application code decides whether an operation is allowed.

> **Development status:** scaffolding only. The policy engine and guarded-tool API are not implemented yet. Do not use this project to protect production data.

## Design principles

1. **Default deny:** no matching allow policy means access is denied.
2. **Deterministic authorization:** an LLM response cannot grant permissions.
3. **Enforce at execution:** evaluate authorization immediately before a protected operation.
4. **Least privilege:** decisions consider the principal, action, and resource.
5. **Framework-independent core:** the policy engine should be testable without LangGraph or a model provider.
6. **Auditable decisions:** expose decision outcomes and reasons without logging sensitive payloads by default.

## Planned capabilities

- Framework-independent policy engine with explicit allow/deny decisions.
- Guarded wrappers for Python callables and LangGraph-compatible tools.
- Deny-overrides policy evaluation and default-deny behavior.
- Optional human approval workflows for selected operations.
- Security-focused tests and a runnable example.

## Development setup

Requires Python 3.11 or newer.

```bash
python -m pip install -e ".[dev]"
ruff check .
ruff format --check .
mypy src
pytest
```

Install the optional LangGraph integration dependencies when needed:

```bash
python -m pip install -e ".[langgraph]"
```

## Project structure

```text
src/langgraph_secure_agents/  # Installable library
tests/                        # Automated tests
.github/workflows/ci.yml      # CI quality checks
```

## Roadmap

- [x] Package metadata, typed package marker, license, and CI foundation
- [ ] Policy models and deterministic evaluation
- [ ] Guarded tool execution
- [ ] Optional LangGraph integration
- [ ] Security-focused tests and practical example
- [ ] Packaging and release-readiness review

## License

MIT. See [LICENSE](LICENSE).

## Disclaimer

This project is experimental and is not a substitute for a complete application security review. Integrators remain responsible for authenticating principals, validating trusted policy inputs, and protecting downstream resources.
