# Release process

Every merged project update should be reflected in a new package release on PyPI. Pushes to `main` run the release workflow; a validated, Conventional Commit message determines the version increment. Do not create version tags or upload packages manually.

## Versioning policy

The canonical version is `project.version` in `pyproject.toml`. The package's `__version__` is read from installed distribution metadata, so it follows the version of the wheel/sdist instead of maintaining a second hard-coded number. From an uninstalled source checkout, it reports `0+unknown`.

The release workflow uses these increments:

- `feat:` produces a minor release.
- `fix:`, `perf:`, `build:`, `chore:`, `ci:`, `docs:`, `style:`, `refactor:`, and `test:` produce a patch release.
- A breaking-change marker such as `feat!:` or a `BREAKING CHANGE:` footer increments the minor version while the project remains on `0.x`, as configured by `major_on_zero = false`.

Use one of these Conventional Commit types for every change intended to update the published package. In particular, documentation-only changes produce a new patch release so the README shown on PyPI stays synchronized with the repository.

## Automated release workflow

On a push to `main`, GitHub Actions:

1. Runs lint, formatting, strict typing, and the test suite on Python 3.11, 3.12, and 3.13, enforcing the configured minimum coverage.
2. Builds the wheel and source distribution, validates distribution metadata, and smoke-tests the installed package and optional agent middleware.
3. Uses Python Semantic Release to determine the next version, update `pyproject.toml` and `CHANGELOG.md`, create the version commit and Git tag, and create the GitHub Release.
4. Builds and validates the versioned distribution artifacts, attaches them to the GitHub Release, and publishes those same artifacts to PyPI via Trusted Publishing (GitHub OIDC).

The PyPI publishing job runs only after the release job succeeds. It receives `id-token: write` but no repository-content permission; no permanent PyPI API token is used. The PyPI Trusted Publisher must be configured for owner `peymanpro`, repository `LangGraph-SecureAgents`, workflow `.github/workflows/release.yml`, and the GitHub environment `pypi`. The environment must not require a manual reviewer when fully automatic publishing is desired.

The workflow's version commit is tagged as the release itself. A subsequent merge triggers the next version analysis; no manual tag creation is required.

## Verification after each release

Check that the [GitHub Releases](https://github.com/peymanpro/LangGraph-SecureAgents/releases) and [PyPI project page](https://pypi.org/project/langgraph-secure-agents/) show the same version. Install that version in a clean virtual environment and verify both the core package and the `langchain-agents` extra. The package metadata includes the README, so publishing a new version also refreshes the project description displayed on PyPI.

CI verifies the automated checks listed above. It is not a substitute for reviewing application-specific authentication, policy rules, resource resolvers, approval handling, and downstream authorization controls; see the [threat model](threat-model.md).
