# Release process

This project is distributed as a Python library. A release consists of validated wheel and source-distribution artifacts, a GitHub Release, and publication to PyPI through Trusted Publishing. Do not create a release tag until the checklist below is complete.

## Versioning

The canonical package version is `project.version` in `pyproject.toml` and must match `src/langgraph_secure_agents/__init__.py` (`__version__`). The release tag must be exactly that version with a leading `v` (for example, `v0.1.0a0`). The workflow rejects a mismatched tag before building.

Follow PEP 440. Alpha versions such as `0.1.0a0` are pre-releases and are not stable production releases. Breaking changes may occur before the first stable release.

## First-release checklist

Before enabling the first automatic release, verify each item against the current `main` branch:

- [ ] Public API names, signatures, behavior, and documented examples have been reviewed against the implementation.
- [ ] README describes the project as a reusable library and accurately documents installation, optional dependencies, quick start, limitations, and supported Python versions.
- [ ] Threat model and security policy accurately state the trust boundaries and what the library does not provide.
- [ ] Full CI passes, including lint, formatting, strict typing, coverage threshold, distribution build, clean-wheel smoke test, and optional middleware-extra smoke test.
- [ ] Wheel and source distribution build successfully and pass `twine check`.
- [ ] `pyproject.toml` and package `__version__` match.
- [ ] A release note/changelog entry describes the shipped API and known limitations.
- [ ] PyPI Trusted Publishing is configured for this repository, workflow file `.github/workflows/release.yml`, and GitHub environment `pypi`.
- [ ] The GitHub `pypi` environment exists and has no required reviewer gate, so publication can complete automatically after CI and PyPI Trusted Publishing succeed.
- [ ] The package name `langgraph-secure-agents` is available or its PyPI project/pending publisher is configured for this owner.
- [ ] The maintainer has reviewed the final tag and understands that publishing to PyPI is irreversible for that version.

Do not mark the checklist complete just because CI is green. CI verifies the configured automated checks; it is not an independent security audit.

## Automated release workflow

The release workflow runs on pushes to `main` and can also be started manually for diagnosis. It first runs the quality gate across Python 3.11, 3.12, and 3.13, then builds both distributions, validates them with Twine, installs the wheel in a clean environment, and smoke-tests the core API and optional middleware extra.

Only after those checks pass does Python Semantic Release inspect Conventional Commit messages. When a release is warranted, it synchronizes the version in `pyproject.toml` and the package `__version__`, updates `CHANGELOG.md`, creates the version commit/tag, and creates a GitHub Release. The workflow then builds and validates the exact distributions, attaches them to that release, and publishes them to PyPI.

The PyPI job is separate from the versioning job and receives only `id-token: write`; the versioning job does not receive OIDC permission. No permanent PyPI API token is used. Publication requires the one-time Trusted Publisher configuration and a GitHub environment named `pypi` with no required manual reviewer if the desired behavior is fully automatic.

## Automatic versioning

Do not create version tags manually. Merge release-worthy changes into `main` with Conventional Commit messages. The workflow creates the version commit and tag only after the release quality gate passes.

Before enabling automatic publication, configure PyPI Trusted Publishing and the GitHub `pypi` environment once. The release workflow uses OIDC and does not require a permanent PyPI token. If the PyPI publisher or environment is not configured, publication cannot complete; configure them before expecting the first release to succeed.

## After release

- Confirm both the GitHub Release and PyPI project page show the expected version.
- Download and install the published package in a clean virtual environment.
- Test the documented core install and the `langchain-agents` extra from the published distribution.
- Record the release URL, version, and artifact hashes in the project release notes.
- Update the README installation section if any release-specific caveat remains.

## Security and support status

An alpha release is a real distributable package, not a claim of production readiness. This project has not received an independent security audit. Do not use it as the sole security boundary for production or sensitive data.
