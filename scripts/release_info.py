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


def main() -> None:
    """Emit a release tag for the current untagged master commit."""
    head_tags = subprocess.run(
        ["git", "tag", "--points-at", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    if any(TAG_PATTERN.fullmatch(tag) for tag in head_tags):
        raise SystemExit("HEAD already has a release tag; refusing a duplicate release")

    tags = subprocess.run(
        ["git", "tag", "--list", "v*"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    tag = next_tag(tags)
    if output := os.environ.get("GITHUB_OUTPUT"):
        with Path(output).open("a", encoding="utf-8") as handle:
            handle.write(f"tag={tag}\n")
    print(tag)


if __name__ == "__main__":
    main()
