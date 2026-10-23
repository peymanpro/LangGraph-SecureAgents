# Release process

This project is distributed as a Python library. A release consists of validated wheel and source-distribution artifacts, a GitHub Release, and publication to PyPI through Trusted Publishing. Do not create a release tag until the checklist below is complete.

## Versioning

The canonical package version is `project.version` in `pyproject.toml` and must match `src/langgraph_secure_agents/__init__.py` (`__version__`). The release tag must be exactly that version with a leading `v` (for example, `v0.1.0a0`). The workflow rejects a mismatched tag before building.

Follow PEP 440. Alpha versions such as `0.1.0a0` are pre-releases and are not stable production releases. Breaking changes may occur before the first stable release.

## First-release checklist

Before tagging, verify each item against the exact commit to be released:

- [ ] Public API names, signatures, behavior, and documented examples have been reviewed against the implementation.
- [ ] README describes the project as a reusable library and accurately documents installation, optional dependencies, quick start, limitations, and supported Python versions.
- [ ] Threat model and security policy accurately state the trust boundaries and what the library does not provide.
- [ ] Full CI passes, including lint, formatting, strict typing, coverage threshold, distribution build, clean-wheel smoke test, and optional middleware-extra smoke test.
- [ ] Wheel and source distribution build successfully and pass `twine check`.
- [ ] `pyproject.toml` and package `__version__` match.
- [ ] A release note/changelog entry describes the shipped API and known limitations.
- [ ] PyPI Trusted Publishing is configured for this repository, workflow file `.github/workflows/release.yml`, and GitHub environment `pypi`.
- [ ] The package name `langgraph-secure-agents` is available or its PyPI project/pending publisher is configured for this owner.
- [ ] The maintainer has reviewed the final tag and understands that publishing to PyPI is irreversible for that version.

Do not mark the checklist complete just because CI is green. CI verifies the configured automated checks; it is not an independent security audit.

## Automated release workflow

Pushing a tag matching `v*` triggers the release workflow:

1. Verify the tag matches the version in `pyproject.toml`.
2. Build a wheel and source distribution.
3. Validate distribution metadata with Twine.
4. Publish the same validated artifacts to a GitHub Release.
5. Publish those artifacts to PyPI using GitHub OIDC Trusted Publishing.

The GitHub Release and PyPI jobs run independently after the validated build. PyPI publication requires the one-time Trusted Publisher configuration described above. The publishing job has only `id-token: write`; build and test jobs do not receive that permission. The workflow does not use a long-lived PyPI API token.

## Prepare and push a release tag

Run locally from the reviewed release commit only after the checklist is complete:

```bash
git checkout main
git pull --ff-only
python -c "import tomllib; print(tomllib.load(open('pyproject.toml', 'rb'))['project']['version'])"
```

Use the exact version printed by the command. For the current configured version, the tag would be:

```bash
git tag -a v0.1.0a0 -m "Release v0.1.0a0"
git push origin v0.1.0a0
```

If the version changes before release, replace the example tag accordingly. Never reuse a published version or create a tag from an unreviewed commit.

## After release

- Confirm both the GitHub Release and PyPI project page show the expected version.
- Download and install the published package in a clean virtual environment.
- Test the documented core install and the `langchain-agents` extra from the published distribution.
- Record the release URL, version, and artifact hashes in the project release notes.
- Update the README installation section if any release-specific caveat remains.

## Security and support status

An alpha release is a real distributable package, not a claim of production readiness. This project has not received an independent security audit. Do not use it as the sole security boundary for production or sensitive data.
