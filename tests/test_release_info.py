"""Tests for release tag selection."""

import pytest
from scripts.release_info import select_tag, tag_for_commit


def test_first_commit_starts_prerelease_series() -> None:
    assert tag_for_commit(1) == "v0.1.0"


def test_distinct_commits_get_distinct_tags() -> None:
    assert tag_for_commit(10) == "v0.1.9"
    assert tag_for_commit(11) == "v0.1.10"


def test_commit_count_must_be_positive() -> None:
    with pytest.raises(ValueError, match="positive"):
        tag_for_commit(0)


def test_rerun_reuses_tag_on_current_commit() -> None:
    assert select_tag(["v0.1.2"], ["v0.1.2"], 3) == ("v0.1.2", False)


def test_new_commit_creates_next_tag() -> None:
    assert select_tag([], ["v0.1.2"], 4) == ("v0.1.3", True)


def test_existing_tag_for_other_commit_is_rejected() -> None:
    with pytest.raises(ValueError, match="different commit"):
        select_tag([], ["v0.1.3"], 4)
