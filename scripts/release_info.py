"""Calculate the next patch tag after a successful master build."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

TAG_PATTERN = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


def tag_for_commit(commit_count: int) -> str:
    """Give each master commit a stable, unique prerelease patch number."""
    if commit_count < 1:
        raise ValueError("commit count must be positive")
    return f"v0.1.{commit_count - 1}"


def select_tag(head_tags: list[str], all_tags: list[str], commit_count: int) -> tuple[str, bool]:
    """Reuse a tag on rerun, or select a new tag for an untagged commit."""
    release_tags = [tag for tag in head_tags if TAG_PATTERN.fullmatch(tag)]
    if release_tags:
        return max(release_tags, key=lambda tag: tuple(map(int, tag[1:].split(".")))), False
    tag = tag_for_commit(commit_count)
    if tag in all_tags:
        raise ValueError(f"{tag} already names a different commit")
    return tag, True


def main() -> None:
    """Emit a release tag for the current master commit."""
    head_tags = subprocess.run(
        ["git", "tag", "--points-at", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    tags = subprocess.run(
        ["git", "tag", "--list", "v*"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    commit_count = int(
        subprocess.run(
            ["git", "rev-list", "--first-parent", "--count", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    tag, create_tag = select_tag(head_tags, tags, commit_count)
    if output := os.environ.get("GITHUB_OUTPUT"):
        with Path(output).open("a", encoding="utf-8") as handle:
            handle.write(f"tag={tag}\n")
            handle.write(f"create_tag={str(create_tag).lower()}\n")
    print(tag)


if __name__ == "__main__":
    main()
