"""Tests for beta release tag selection."""

import subprocess
from pathlib import Path

import pytest
from scripts.release_info import main, next_patch, resolve_release


def test_first_release_starts_project_beta_series() -> None:
    assert next_patch(None) == "v0.1.0"


def test_new_master_merges_increment_latest_patch() -> None:
    assert next_patch("v0.1.8") == "v0.1.9"


def test_next_patch_rejects_invalid_tags() -> None:
    with pytest.raises(ValueError, match="version tag"):
        next_patch("nightly")


def test_master_rerun_reuses_tag_already_on_head() -> None:
    assert resolve_release("push", "refs/heads/master", False, ["v0.1.4"], ["v0.1.4"]) == (
        False,
        False,
        "v0.1.4",
    )


def test_failed_master_build_retry_reuses_tag_already_on_head() -> None:
    assert resolve_release(
        "push", "refs/heads/master", False, ["v0.1.4"], ["v0.1.4"], retry_failed=True
    ) == (True, False, "v0.1.4")


def test_master_merge_allocates_next_tag() -> None:
    assert resolve_release("push", "refs/heads/master", False, [], ["v0.1.4"]) == (
        True,
        True,
        "v0.1.5",
    )


def test_tag_push_rebuilds_that_version() -> None:
    assert resolve_release("push", "refs/tags/v0.1.4", False, [], []) == (
        True,
        False,
        "v0.1.4",
    )


def test_pull_request_and_manual_default_do_not_release() -> None:
    assert resolve_release("pull_request", "refs/pull/4/merge", False, [], []) == (
        False,
        False,
        "",
    )
    assert resolve_release("workflow_dispatch", "refs/heads/master", False, [], []) == (
        False,
        False,
        "",
    )


def test_main_emits_release_decision(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

    git("init", "-b", "master")
    git("config", "user.email", "test@example.com")
    git("config", "user.name", "Test")
    git("commit", "--allow-empty", "-m", "bootstrap")
    output = tmp_path / "github-output"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("EVENT_NAME", "push")
    monkeypatch.setenv("REF", "refs/heads/master")

    main()

    assert output.read_text(encoding="utf-8") == (
        "is_release=true\ncreate_tag=true\ntag_name=v0.1.0\n"
    )

    git("tag", "v0.1.0")
    output.write_text("", encoding="utf-8")
    main()
    assert output.read_text(encoding="utf-8") == (
        "is_release=false\ncreate_tag=false\ntag_name=v0.1.0\n"
    )

    monkeypatch.setenv("RETRY_FAILED_RELEASE", "true")
    output.write_text("", encoding="utf-8")
    main()
    assert output.read_text(encoding="utf-8") == (
        "is_release=true\ncreate_tag=false\ntag_name=v0.1.0\n"
    )
    monkeypatch.delenv("RETRY_FAILED_RELEASE")

    git("commit", "--allow-empty", "-m", "next merge")
    output.write_text("", encoding="utf-8")
    main()
    assert output.read_text(encoding="utf-8") == (
        "is_release=true\ncreate_tag=true\ntag_name=v0.1.1\n"
    )


def test_main_uses_synthetic_pr_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    output = tmp_path / "github-output"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("EVENT_NAME", "pull_request")
    monkeypatch.setenv("REF", "refs/pull/7/merge")
    monkeypatch.setenv("GITHUB_SHA", "0123456789abcdef")

    main()

    assert output.read_text(encoding="utf-8") == (
        "is_release=false\ncreate_tag=false\ntag_name=0.0.0+0123456789ab\n"
    )
