"""Resolve a serialized beta release version for the current workflow event."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

TAG_PATTERN = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


def _version_key(tag: str) -> tuple[int, int, int]:
    match = TAG_PATTERN.fullmatch(tag)
    if match is None:
        raise ValueError(f"invalid version tag: {tag!r}")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def next_patch(latest: str | None) -> str:
    """Increment the patch of the latest project beta tag, starting at v0.1.0."""
    if latest is None:
        return "v0.1.0"
    major, minor, patch = _version_key(latest)
    return f"v{major}.{minor}.{patch + 1}"


def resolve_release(
    event: str,
    ref: str,
    dispatch_release: bool,
    head_tags: list[str],
    all_tags: list[str],
) -> tuple[bool, bool, str]:
    """Return whether to release, whether to create a tag, and the build version."""
    if event == "pull_request":
        return False, False, ""
    if event == "workflow_dispatch":
        if not dispatch_release:
            return False, False, ""
        if not (ref == "refs/heads/master" or ref.startswith("refs/tags/")):
            raise ValueError("release dispatch requires master or an existing vX.Y.Z tag")
        event = "push"
    if event == "push" and ref.startswith("refs/tags/"):
        tag = ref.removeprefix("refs/tags/")
        _version_key(tag)
        return True, False, tag
    if event == "push" and ref == "refs/heads/master":
        head_release_tags = [tag for tag in head_tags if TAG_PATTERN.fullmatch(tag)]
        if head_release_tags:
            tag = max(head_release_tags, key=_version_key)
            return False, False, tag
        valid_tags = [tag for tag in all_tags if TAG_PATTERN.fullmatch(tag)]
        latest = max(valid_tags, key=_version_key) if valid_tags else None
        tag = next_patch(latest)
        if tag in all_tags:
            raise ValueError(f"version tag {tag} already exists on another commit")
        return True, True, tag
    raise ValueError(f"unsupported release event/ref: {event!r} {ref!r}")


def _git_tags(*args: str) -> list[str]:
    return subprocess.run(
        ["git", "tag", *args], check=True, capture_output=True, text=True
    ).stdout.splitlines()


def main() -> None:
    """Resolve event version data and write it to GitHub Actions outputs."""
    event = os.environ.get("EVENT_NAME", "")
    ref = os.environ.get("REF", "")
    dispatch_release = os.environ.get("DISPATCH_RELEASE", "").casefold() == "true"
    if event == "pull_request" or (event == "workflow_dispatch" and not dispatch_release):
        tag = f"0.0.0+{os.environ.get('GITHUB_SHA', 'local')[:12]}"
        is_release, create_tag = False, False
    else:
        head_tags = _git_tags("--points-at", "HEAD")
        all_tags = _git_tags("--list", "v*")
        is_release, create_tag, tag = resolve_release(
            event, ref, dispatch_release, head_tags, all_tags
        )
    values = {
        "is_release": str(is_release).lower(),
        "create_tag": str(create_tag).lower(),
        "tag_name": tag,
    }
    rendered = "\n".join(f"{key}={value}" for key, value in values.items())
    if output := os.environ.get("GITHUB_OUTPUT"):
        with Path(output).open("a", encoding="utf-8") as handle:
            handle.write(rendered + "\n")
    print(rendered)


if __name__ == "__main__":
    main()
