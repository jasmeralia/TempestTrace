"""Calculate the next patch tag after a successful master build."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

TAG_PATTERN = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


def next_tag(tags: list[str]) -> str:
    """Return the next patch tag; start the prerelease series at v0.1.0."""
    versions = [
        tuple(int(part) for part in match.groups())
        for tag in tags
        if (match := TAG_PATTERN.fullmatch(tag)) is not None
    ]
    if not versions:
        return "v0.1.0"
    major, minor, patch = max(versions)
    return f"v{major}.{minor}.{patch + 1}"


def select_tag(head_tags: list[str], all_tags: list[str]) -> tuple[str, bool]:
    """Reuse a tag on rerun, or select a new tag for an untagged commit."""
    release_tags = [tag for tag in head_tags if TAG_PATTERN.fullmatch(tag)]
    if release_tags:
        return max(release_tags, key=lambda tag: tuple(map(int, tag[1:].split(".")))), False
    return next_tag(all_tags), True


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
    tag, create_tag = select_tag(head_tags, tags)
    if output := os.environ.get("GITHUB_OUTPUT"):
        with Path(output).open("a", encoding="utf-8") as handle:
            handle.write(f"tag={tag}\n")
            handle.write(f"create_tag={str(create_tag).lower()}\n")
    print(tag)


if __name__ == "__main__":
    main()
