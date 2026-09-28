"""Tests for release tag selection."""

import subprocess
from pathlib import Path

import pytest
from scripts.release_info import main, select_tag, tag_for_commit


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


def test_main_emits_new_tag_and_reuses_it_on_rerun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

    git("init", "-b", "master")
    git("config", "user.email", "test@example.com")
    git("config", "user.name", "Test")
    git("commit", "--allow-empty", "-m", "bootstrap")
    output = tmp_path / "github-output"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))

    main()
    assert output.read_text(encoding="utf-8") == "tag=v0.1.0\ncreate_tag=true\n"

    git("tag", "v0.1.0")
    output.write_text("", encoding="utf-8")
    main()
    assert output.read_text(encoding="utf-8") == "tag=v0.1.0\ncreate_tag=false\n"
