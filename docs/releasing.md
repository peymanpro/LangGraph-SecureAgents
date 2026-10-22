# Release process

## Versioning

The canonical package version is the `project.version` value in `pyproject.toml`. The release tag must match it exactly with a leading `v` (for example, `v0.1.0a0`). The workflow fails before building if the tag and package version differ.

## Before tagging

1. Merge the release candidate to `main` only after all CI jobs pass.
2. Review the change log / generated GitHub release notes and update package version if needed.
3. Check the security policy, threat model, public API, and the tested Python versions.
4. Create and push the matching tag only when the commit is ready to publish.

Example commands, run locally from the intended release commit:

```bash
git checkout main
git pull --ff-only
git tag -a v0.1.0a0 -m "Release v0.1.0a0"
git push origin v0.1.0a0
```

Replace the example tag with the exact version in `pyproject.toml`. Do not create a tag from an unreviewed commit.

## Automated workflow

The `Release` workflow runs on version tags. It validates the tag, builds a wheel and source distribution, checks the metadata with Twine, and attaches both files to a GitHub Release. Pre-release status is inferred from the Python package version.

The normal CI workflow also builds and smoke-tests the wheel in a clean environment on pull requests and pushes to `main`.

## PyPI publication

This workflow publishes GitHub Release artifacts only. It does not upload the package to PyPI. PyPI publication should be added only after a PyPI Trusted Publisher has been configured for this repository and the publishing workflow has been reviewed. Do not add long-lived PyPI tokens to the repository to shortcut that setup.
