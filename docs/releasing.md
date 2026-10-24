# Release process

A push to `main` always starts the release workflow's validation jobs. A package release is created only if those jobs pass **and** Python Semantic Release finds at least one release-triggering commit since the last release tag. A workflow run is not itself a release. Changes that use only no-release commit types can pass CI without creating a version commit, Git tag, GitHub Release, or PyPI publication. Do not create version tags or upload packages manually.

## Versioning policy

The canonical version is `project.version` in `pyproject.toml`. The package's `__version__` is read from installed distribution metadata, so it follows the version of the wheel/sdist instead of maintaining a second hard-coded number. From an uninstalled source checkout, it reports `0+unknown`.

The policy is configured in `pyproject.toml` and tested against the same pinned `python-semantic-release==10.7.0` implementation used by the release workflow:

- `feat:` produces a minor release.
- `fix:` and `perf:` produce a patch release.
- `build:` produces a patch release when the change affects the package build, installation, or distribution. Routine workflow and maintainer-tooling changes should use `ci:` or `chore:` instead.
- `docs:`, `test:`, `ci:`, `style:`, `refactor:`, and `chore:` are allowed, but do not trigger a release by themselves.
- Breaking changes marked with `!` (for example, `feat!:`) or a `BREAKING CHANGE:` footer take precedence over the normal type. Because `allow_zero_version = true` and `major_on_zero = false`, a breaking change while the package remains on `0.x` increments the minor version (for example, `0.8.0` to `0.9.0`). Once the package reaches `1.x`, a breaking change increments the major version.
- When a set of commits contains multiple eligible changes, the highest applicable bump wins.

Use Conventional Commit types to describe the impact on package consumers, not merely the files changed. For example, a README-only change should use `docs:` and must not publish a release by itself; fixing a wheel's install metadata can use `build:` and trigger a patch release.

## Automated release workflow

On a push to `main`, GitHub Actions:

1. Runs lint, formatting, strict typing, and the test suite on Python 3.11, 3.12, and 3.13, enforcing the configured minimum coverage.
2. Builds the wheel and source distribution and validates distribution metadata.
3. Installs the built wheel in a clean environment and smoke-tests the core API.
4. Installs and smoke-tests the optional LangGraph node-guard, LangChain middleware, OpenTelemetry audit, and MCP tool integrations in separate clean environments.
5. Uses Python Semantic Release to determine the next version, update `pyproject.toml` and `CHANGELOG.md`, create the version commit and Git tag, and create the GitHub Release.
6. Builds and validates the versioned distribution artifacts, attaches them to the GitHub Release, and publishes those same artifacts to PyPI via Trusted Publishing (GitHub OIDC).

The PyPI publishing job runs only after the release job succeeds. It receives `id-token: write` but no repository-content permission; no permanent PyPI API token is used. The PyPI Trusted Publisher must be configured for owner `peymanpro`, repository `LangGraph-SecureAgents`, workflow `.github/workflows/release.yml`, and the GitHub environment `pypi`. The environment must not require a manual reviewer when fully automatic publishing is desired.

The workflow's version commit is tagged as the release itself. Subsequent pushes to `main` trigger validation and version analysis, but only eligible commit types can create the next release; no manual tag creation is required.

## Verification after each release

Check that the [GitHub Releases](https://github.com/peymanpro/LangGraph-SecureAgents/releases) and [PyPI project page](https://pypi.org/project/langgraph-secure-agents/) show the same version. Install that exact version in a clean virtual environment and smoke-test the core API. Separately install and verify the `langgraph`, `langchain-agents`, `opentelemetry`, and `mcp` extras; CI exercises each optional integration in its own clean environment. The package metadata includes the README, so publishing a new version also refreshes the project description displayed on PyPI.

CI verifies the automated checks listed above. It is not a substitute for reviewing application-specific authentication, policy rules, resource resolvers, approval handling, and downstream authorization controls; see the [threat model](threat-model.md).
