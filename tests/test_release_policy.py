"""Regression tests for the repository's Python Semantic Release policy.

These tests use the same python-semantic-release version as release.yml. They
exercise the real Conventional Commit parser and version-bump implementation
without creating Git tags, GitHub Releases, or publishing to PyPI.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Final

import pytest
from semantic_release.commit_parser.conventional.options import (
    ConventionalCommitParserOptions,
)
from semantic_release.commit_parser.conventional.parser import ConventionalCommitParser
from semantic_release.enums import LevelBump
from semantic_release.version.algorithm import _increment_version
from semantic_release.version.version import Version

ROOT: Final = Path(__file__).resolve().parents[1]
PROJECT_CONFIG: Final = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
RELEASE_CONFIG: Final = PROJECT_CONFIG["tool"]["semantic_release"]
PARSER_CONFIG: Final = RELEASE_CONFIG["commit_parser_options"]


def configured_parser() -> ConventionalCommitParser:
    """Build the official parser from the checked-in release-policy settings."""
    options = ConventionalCommitParserOptions(
        minor_tags=tuple(PARSER_CONFIG["minor_tags"]),
        patch_tags=tuple(PARSER_CONFIG["patch_tags"]),
        other_allowed_tags=tuple(PARSER_CONFIG["other_allowed_tags"]),
        parse_squash_commits=PARSER_CONFIG["parse_squash_commits"],
        ignore_merge_commits=PARSER_CONFIG["ignore_merge_commits"],
    )
    return ConventionalCommitParser(options)


def next_0_x_version(bump: LevelBump) -> str:
    """Apply PSR's pinned 0.x version algorithm to the current 0.8.0 release."""
    current = Version.parse("0.8.0")
    # Use PSR 10.7.0's version algorithm so major_on_zero is verified as behavior.
    return str(
        _increment_version(
            latest_version=current,
            latest_full_version=current,
            level_bump=bump,
            prerelease=False,
            prerelease_token="rc",
            major_on_zero=RELEASE_CONFIG["major_on_zero"],
            allow_zero_version=RELEASE_CONFIG["allow_zero_version"],
        )
    )


@pytest.mark.parametrize(
    ("message", "expected_bump", "expected_version"),
    [
        ("docs: clarify the README", LevelBump.NO_RELEASE, None),
        ("test: cover the release parser", LevelBump.NO_RELEASE, None),
        ("ci: validate workflow permissions", LevelBump.NO_RELEASE, None),
        ("refactor: simplify an internal helper", LevelBump.NO_RELEASE, None),
        ("style: normalize whitespace", LevelBump.NO_RELEASE, None),
        ("chore: update maintainer tooling", LevelBump.NO_RELEASE, None),
        ("fix: correct an authorization edge case", LevelBump.PATCH, "0.8.1"),
        ("perf: reduce policy evaluation overhead", LevelBump.PATCH, "0.8.1"),
        ("build: fix package metadata in the wheel", LevelBump.PATCH, "0.8.1"),
        ("feat: add policy simulation", LevelBump.MINOR, "0.9.0"),
        ("feat!: change the public policy API", LevelBump.MAJOR, "0.9.0"),
    ],
)
def test_commit_types_have_expected_release_impact(
    message: str,
    expected_bump: LevelBump,
    expected_version: str | None,
) -> None:
    """Only package-impacting commit types should increase the version."""
    parsed = configured_parser().parse_message(message)

    assert parsed is not None
    assert parsed.bump == expected_bump

    if expected_version is None:
        assert expected_bump == LevelBump.NO_RELEASE
        return

    assert next_0_x_version(expected_bump) == expected_version


def test_breaking_change_footer_increments_minor_during_0_x() -> None:
    parsed = configured_parser().parse_message(
        "fix: remove the legacy authorization fallback\n\n"
        "BREAKING CHANGE: callers must provide a trusted principal."
    )

    assert parsed is not None
    assert parsed.bump == LevelBump.MAJOR
    assert RELEASE_CONFIG["allow_zero_version"] is True
    assert RELEASE_CONFIG["major_on_zero"] is False
    assert next_0_x_version(parsed.bump) == "0.9.0"


def test_build_is_patch_only_not_an_internal_default() -> None:
    """Build is retained as patch for distribution-impacting work only."""
    assert "build" in PARSER_CONFIG["patch_tags"]
    assert "build" not in PARSER_CONFIG["other_allowed_tags"]
