"""Tests for release tag selection."""

from scripts.release_info import next_tag


def test_first_tag_starts_prerelease_series() -> None:
    assert next_tag([]) == "v0.1.0"


def test_next_tag_uses_highest_semantic_version() -> None:
    assert next_tag(["v0.1.9", "v0.1.10", "v0.2.0"]) == "v0.2.1"


def test_non_release_tags_are_ignored() -> None:
    assert next_tag(["v0.1.1-rc1", "v0.1.2", "draft", "v3.1"]) == "v0.1.3"
