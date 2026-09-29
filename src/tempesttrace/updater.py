"""Pure GitHub release selection and verified package download helpers."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from functools import total_ordering
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, cast

SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
MAX_DOWNLOAD_SIZE = 1024 * 1024 * 1024
READ_CHUNK_SIZE = 64 * 1024


@total_ordering
@dataclass(frozen=True)
class SemVer:
    """A strict semantic version with optional v prefix."""

    major: int
    minor: int
    patch: int
    prerelease: tuple[str, ...] = ()
    build: tuple[str, ...] = ()

    @classmethod
    def parse(cls, value: str) -> SemVer:
        """Parse a semantic version, allowing the common Git tag ``v`` prefix."""
        match = re.fullmatch(
            r"v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
            r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
            r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?",
            value,
        )
        if match is None:
            raise ValueError(f"invalid semantic version: {value!r}")
        prerelease = tuple(match.group(4).split(".")) if match.group(4) else ()
        if any(part.isdigit() and len(part) > 1 and part.startswith("0") for part in prerelease):
            raise ValueError(f"invalid semantic version: {value!r}")
        build = tuple(match.group(5).split(".")) if match.group(5) else ()
        return cls(int(match.group(1)), int(match.group(2)), int(match.group(3)), prerelease, build)

    @property
    def is_prerelease(self) -> bool:
        return bool(self.prerelease)

    def __str__(self) -> str:
        result = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            result += "-" + ".".join(self.prerelease)
        if self.build:
            result += "+" + ".".join(self.build)
        return result

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SemVer):
            return NotImplemented
        return (self.major, self.minor, self.patch, self.prerelease) == (
            other.major,
            other.minor,
            other.patch,
            other.prerelease,
        )

    def __hash__(self) -> int:
        return hash((self.major, self.minor, self.patch, self.prerelease))

    def _sort_key(self) -> tuple[object, ...]:
        prerelease_key = tuple(
            (0, int(part)) if part.isdigit() else (1, part) for part in self.prerelease
        )
        return (
            self.major,
            self.minor,
            self.patch,
            int(not self.prerelease),
            prerelease_key,
        )

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, SemVer):
            return NotImplemented
        return self._sort_key() < other._sort_key()


@dataclass(frozen=True)
class ReleaseAsset:
    """One GitHub release asset selected for this installation."""

    name: str
    url: str
    size: int
    sha256: str


@dataclass(frozen=True)
class UpdateOffer:
    """Release metadata and verified asset details presented to the user."""

    version: str
    is_beta: bool
    notes: str
    release_url: str
    asset: ReleaseAsset


def _normal_platform(value: str) -> str:
    normalized = value.casefold()
    if normalized in {"windows", "win", "win32", "nt"}:
        return "windows"
    if normalized in {"linux", "linux2"}:
        return "linux"
    raise ValueError(f"unsupported update platform: {value!r}")


def _normal_architecture(value: str) -> str:
    normalized = value.casefold().replace("-", "_")
    if normalized in {"amd64", "x86_64", "x64"}:
        return "amd64"
    if normalized in {"arm64", "aarch64"}:
        return "arm64"
    raise ValueError(f"unsupported update architecture: {value!r}")


def _normal_package(value: str) -> str:
    normalized = value.casefold().lstrip(".")
    aliases = {"exe": "nsis", "installer": "nsis", "appimage": "appimage"}
    normalized = aliases.get(normalized, normalized)
    if normalized not in {"nsis", "deb", "rpm", "appimage", "flatpak", "snap"}:
        raise ValueError(f"unsupported update package type: {value!r}")
    return normalized


def asset_name(tag: str, platform: str, architecture: str, package_type: str) -> str:
    """Return TempestTrace's canonical release asset name for a target."""
    os_name = _normal_platform(platform)
    arch = _normal_architecture(architecture)
    package = _normal_package(package_type)
    version = str(SemVer.parse(tag))
    tag_version = f"v{version}"
    if os_name == "windows":
        if package != "nsis" or arch != "amd64":
            raise ValueError("Windows updates require the x64 NSIS installer")
        return f"TempestTrace-Setup-{tag_version}.exe"
    if package == "nsis":
        raise ValueError("NSIS is a Windows package")
    suffixes = {
        "deb": "deb",
        "rpm": "rpm",
        "appimage": "AppImage",
        "flatpak": "flatpak",
        "snap": "snap",
    }
    suffix = suffixes[package]
    return f"TempestTrace-{tag_version}-linux-{arch}.{suffix}"


def _asset_name_matches(
    name: str, tag: str, platform: str, architecture: str, package_type: str
) -> bool:
    """Match canonical names and common package-manager filename conventions."""
    expected = asset_name(tag, platform, architecture, package_type)
    if name.casefold() == expected.casefold():
        return True
    os_name = _normal_platform(platform)
    arch = _normal_architecture(architecture)
    package = _normal_package(package_type)
    if os_name == "windows":
        return False
    suffixes = {
        "deb": ".deb",
        "rpm": ".rpm",
        "appimage": ".appimage",
        "flatpak": ".flatpak",
        "snap": ".snap",
    }
    if not name.casefold().endswith(suffixes[package]):
        return False
    stem = name.casefold()[: -len(suffixes[package])]
    tokens = re.split(r"[^a-z0-9]+", stem)
    has_project = "tempesttrace" in tokens
    arch_tokens = {"amd64": {"amd64", "x86_64", "x64"}, "arm64": {"arm64", "aarch64"}}[arch]
    version = str(SemVer.parse(tag)).casefold()
    has_version = re.search(rf"(?<![0-9.])v?{re.escape(version)}(?![0-9.])", stem) is not None
    has_arch = bool(arch_tokens.intersection(tokens))
    has_platform = "linux" in tokens or package in {"deb", "rpm", "snap"}
    return has_project and has_version and has_arch and has_platform


def parse_sha256sums(contents: str) -> dict[str, str]:
    """Parse GNU ``sha256sum`` and BSD ``shasum`` manifest lines."""
    result: dict[str, str] = {}
    for line in contents.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        bsd = re.fullmatch(r"SHA256 \((.+)\) = ([0-9a-fA-F]{64})", stripped)
        if bsd:
            name, digest = bsd.groups()
        else:
            match = re.fullmatch(r"([0-9a-fA-F]{64}) [ *](.+)", stripped)
            if match is None:
                raise ValueError("malformed SHA-256 manifest line")
            digest, name = match.groups()
        filename = Path(name).name
        if filename in result:
            raise ValueError(f"duplicate SHA-256 entry for {filename}")
        result[filename] = digest.lower()
    return result


def _release_checksums(release: Mapping[str, Any]) -> dict[str, str]:
    raw = release.get("checksums", {})
    if not isinstance(raw, Mapping):
        return {}
    result: dict[str, str] = {}
    for name, digest in raw.items():
        if isinstance(name, str) and isinstance(digest, str) and SHA256_PATTERN.fullmatch(digest):
            result[Path(name).name] = digest.lower()
    return result


def check_for_update(  # noqa: PLR0912, PLR0913, PLR0917
    current_version: str | None,
    releases: Sequence[Mapping[str, Any]],
    platform: str,
    architecture: str,
    package_type: str,
    include_beta: bool,
) -> UpdateOffer | None:
    """Select the highest compatible verified GitHub release newer than current."""
    if not current_version or current_version == "0.0.0":
        return None
    current = SemVer.parse(current_version.removeprefix("v"))
    os_name = _normal_platform(platform)
    arch = _normal_architecture(architecture)
    package = _normal_package(package_type)
    beta_allowed = include_beta
    candidates: list[tuple[SemVer, UpdateOffer]] = []
    for release in releases:
        if release.get("draft", False):
            continue
        tag = release.get("tag_name")
        if not isinstance(tag, str):
            continue
        try:
            version = SemVer.parse(tag)
        except ValueError:
            continue
        is_beta = bool(release.get("prerelease", False)) or version.is_prerelease
        if is_beta and not beta_allowed:
            continue
        if version <= current:
            continue
        raw_assets = release.get("assets", [])
        if not isinstance(raw_assets, list):
            continue
        matching: Mapping[str, Any] | None = None
        for raw_asset in raw_assets:
            if not isinstance(raw_asset, Mapping):
                continue
            name = raw_asset.get("name")
            if isinstance(name, str) and _asset_name_matches(name, tag, os_name, arch, package):
                matching = raw_asset
                break
        if matching is None:
            continue
        name = matching.get("name")
        url = matching.get("browser_download_url")
        size = matching.get("size")
        digest = _release_checksums(release).get(str(name))
        if (
            not isinstance(name, str)
            or not isinstance(url, str)
            or not url.startswith("https://")
            or not isinstance(size, int)
            or size <= 0
            or size > MAX_DOWNLOAD_SIZE
            or digest is None
        ):
            continue
        offer = UpdateOffer(
            version=str(version),
            is_beta=is_beta,
            notes=str(release.get("body") or ""),
            release_url=str(release.get("html_url") or ""),
            asset=ReleaseAsset(name, url, size, digest),
        )
        candidates.append((version, offer))
    return max(candidates, key=lambda item: item[0])[1] if candidates else None


def _read_url_with_headers(opener: Callable[[str], Any], url: str) -> tuple[bytes, str | None]:
    response = opener(url)
    close = getattr(response, "close", None)
    try:
        data = cast(bytes, response.read(MAX_DOWNLOAD_SIZE + 1))
        headers = getattr(response, "headers", {})
        link_header = headers.get("Link") if hasattr(headers, "get") else None
    finally:
        if callable(close):
            close()
    if len(data) > MAX_DOWNLOAD_SIZE:
        raise ValueError("release metadata exceeds size limit")
    return data, cast(str | None, link_header)


def _read_url(opener: Callable[[str], Any], url: str) -> bytes:
    data, _ = _read_url_with_headers(opener, url)
    return data


def _next_page_url(link_header: str | None) -> str | None:
    if link_header is None:
        return None
    for entry in link_header.split(","):
        match = re.fullmatch(r'\s*<([^>]+)>\s*;\s*rel="next"\s*', entry)
        if match:
            next_url = match.group(1)
            if not next_url.startswith("https://"):
                raise ValueError("release feed pagination must use HTTPS")
            return next_url
    return None


def fetch_release_feed(  # noqa: PLR0912
    url: str = "https://api.github.com/repos/jasmeralia/TempestTrace/releases",
    opener: Callable[[str], Any] | None = None,
) -> list[dict[str, Any]]:
    """Fetch GitHub releases and attach hashes parsed from each release manifest."""
    open_url = opener or (lambda target: urllib.request.urlopen(target, timeout=20))
    if not url.startswith("https://"):
        raise ValueError("release feed must use HTTPS")
    parsed: list[dict[str, Any]] = []
    page_url: str | None = url
    visited_pages: set[str] = set()
    while page_url is not None:
        if page_url in visited_pages:
            raise ValueError("release feed pagination loop detected")
        visited_pages.add(page_url)
        page_data, link_header = _read_url_with_headers(open_url, page_url)
        raw = json.loads(page_data)
        if not isinstance(raw, list):
            raise ValueError("release feed response must be a list")
        for item in raw:
            if not isinstance(item, dict):
                continue
            release = dict(item)
            checksums: dict[str, str] = {}
            assets = item.get("assets", [])
            if isinstance(assets, list):
                manifest_assets = [
                    asset
                    for asset in assets
                    if isinstance(asset, dict)
                    and isinstance(asset.get("name"), str)
                    and asset["name"].casefold() in {"sha256sums", "sha256sums.txt"}
                ]
                for manifest in manifest_assets[:1]:
                    manifest_url = manifest.get("browser_download_url")
                    if isinstance(manifest_url, str) and manifest_url.startswith("https://"):
                        manifest_text = _read_url(open_url, manifest_url).decode("utf-8")
                        checksums.update(parse_sha256sums(manifest_text))
                for sidecar in assets:
                    if not isinstance(sidecar, dict):
                        continue
                    sidecar_name = sidecar.get("name")
                    sidecar_url = sidecar.get("browser_download_url")
                    if (
                        isinstance(sidecar_name, str)
                        and sidecar_name.endswith(".sha256")
                        and isinstance(sidecar_url, str)
                        and sidecar_url.startswith("https://")
                    ):
                        target_name = sidecar_name[:-7]
                        text = _read_url(open_url, sidecar_url).decode("ascii").strip()
                        match = re.fullmatch(r"([0-9a-fA-F]{64})(?:\s+\*?(.+))?", text)
                        if match and (
                            match.group(2) is None or Path(match.group(2)).name == target_name
                        ):
                            checksums[target_name] = match.group(1).lower()
            release["checksums"] = checksums
            parsed.append(release)
        page_url = _next_page_url(link_header)
    return parsed


def verify_download(  # noqa: PLR0913
    url: str,
    expected_size: int,
    expected_sha256: str,
    destination: str | Path,
    opener: Callable[[str], Any] | None = None,
    *,
    max_size: int = MAX_DOWNLOAD_SIZE,
) -> Path:
    """Stream an HTTPS asset to a temporary sibling, verify it, then publish it."""
    if not url.startswith("https://"):
        raise ValueError("update downloads must use HTTPS")
    if expected_size <= 0 or expected_size > max_size or max_size > MAX_DOWNLOAD_SIZE:
        raise ValueError("download size is outside the allowed limit")
    if not SHA256_PATTERN.fullmatch(expected_sha256):
        raise ValueError("invalid expected SHA-256 digest")
    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise FileExistsError(target)
    open_url = opener or (lambda target_url: urllib.request.urlopen(target_url, timeout=30))
    temporary_path: Path | None = None
    response = open_url(url)
    try:
        digest = hashlib.sha256()
        size = 0
        with tempfile.NamedTemporaryFile(
            prefix=f".{target.name}.", suffix=".part", dir=target.parent, delete=False
        ) as output:
            temporary_path = Path(output.name)
            while chunk := response.read(READ_CHUNK_SIZE):
                size += len(chunk)
                if size > expected_size or size > max_size:
                    raise ValueError("download exceeded the expected size limit")
                digest.update(chunk)
                output.write(chunk)
        if size != expected_size:
            raise ValueError("download size does not match release metadata")
        if digest.hexdigest() != expected_sha256.casefold():
            raise ValueError("download SHA-256 does not match release metadata")
        if target.exists():
            raise FileExistsError(target)
        temporary_path.replace(target)
        return target
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def write_appimage_update_helper(
    current_path: str | Path,
    downloaded_path: str | Path,
    helper_path: str | Path,
    *,
    process_id: int,
) -> Path:
    """Write a detached Linux helper that replaces an AppImage after exit.

    The new image is staged beside the running image so both renames stay on one
    filesystem. The helper retains the old image until the replacement survives
    a short launch check, restoring it if the replacement cannot start.
    """
    current = Path(current_path).absolute()
    downloaded = Path(downloaded_path).absolute()
    helper = Path(helper_path).absolute()
    if process_id <= 0:
        raise ValueError("process id must be positive")
    if current.is_symlink() or not current.is_file():
        raise ValueError("current AppImage must be a regular file")
    if downloaded.is_symlink() or not downloaded.is_file():
        raise ValueError("downloaded AppImage must be a regular file")
    if helper.parent != downloaded.parent:
        raise ValueError("update helper must be stored beside the staged AppImage")
    if current.stat().st_dev != downloaded.stat().st_dev:
        raise ValueError("staged AppImage must be on the current image filesystem")
    if current in (downloaded, helper) or downloaded == helper:
        raise ValueError("AppImage update paths must be distinct")
    if helper.exists():
        raise FileExistsError(helper)

    current_q = shlex.quote(str(current))
    downloaded_q = shlex.quote(str(downloaded))
    helper_q = shlex.quote(str(helper))
    pid_q = f"'{process_id}'"
    script = f"""#!/bin/sh
set -eu
current={current_q}
downloaded={downloaded_q}
helper={helper_q}
while kill -0 {pid_q} 2>/dev/null; do sleep 1; done
rollback=$(mktemp "${{current}}.tempesttrace-rollback.XXXXXX")
rm -f -- "$rollback"
mv -- "$current" "$rollback"
restore() {{
    if [ -e "$rollback" ]; then
        rm -f -- "$current"
        mv -- "$rollback" "$current"
    fi
}}
trap restore EXIT
trap 'exit 1' HUP INT TERM
if ! mv -- "$downloaded" "$current"; then
    restore
    exit 1
fi
if ! chmod +x -- "$current"; then
    restore
    exit 1
fi
"$current" >/dev/null 2>&1 &
new_pid=$!
sleep 10
if ! kill -0 "$new_pid" 2>/dev/null; then
    restore
    exit 1
fi
rm -f -- "$helper"
rm -f -- "$rollback"
trap - EXIT HUP INT TERM
"""
    helper.parent.mkdir(parents=True, exist_ok=True)
    with helper.open("x", encoding="utf-8", newline="\n") as output:
        output.write(script)
    helper.chmod(0o700)
    return helper


def installed_version(build_version: str | None = None) -> str | None:
    """Return the embedded or installed version, excluding the source placeholder."""
    value = build_version
    if value is None and getattr(sys, "frozen", False):
        try:
            module = importlib.import_module("tempesttrace._build_info")
            candidate = getattr(module, "VERSION", None)
            value = candidate if isinstance(candidate, str) else None
        except ImportError:
            value = None
    if value is None:
        try:
            value = version("tempesttrace")
        except PackageNotFoundError:
            value = None
    if value is None:
        return None
    try:
        parsed = SemVer.parse(value)
    except ValueError:
        return None
    if parsed == SemVer(0, 0, 0):
        return None
    return str(parsed)


def detect_package_type(  # noqa: PLR0911
    platform: str | None = None,
    environ: Mapping[str, str] | None = None,
    executable: str | Path | None = None,
) -> str | None:
    """Detect the current Linux package; explicit runtime markers take precedence."""
    os_name = _normal_platform(platform or sys.platform)
    if os_name == "windows":
        return "nsis"
    env = os.environ if environ is None else environ
    if env.get("APPIMAGE"):
        return "appimage"
    if (
        env.get("FLATPAK_ID")
        or env.get("container") == "flatpak"
        or Path("/.flatpak-info").exists()
    ):
        return "flatpak"
    if env.get("SNAP"):
        return "snap"
    executable_path = Path(executable or sys.executable).resolve()
    if shutil.which("dpkg-query"):
        result = subprocess.run(
            ["dpkg-query", "-S", str(executable_path)], capture_output=True, text=True, check=False
        )
        if result.returncode == 0 and "tempesttrace" in result.stdout.casefold():
            return "deb"
    if shutil.which("rpm"):
        result = subprocess.run(
            ["rpm", "-qf", str(executable_path)], capture_output=True, text=True, check=False
        )
        if result.returncode == 0 and "tempesttrace" in result.stdout.casefold():
            return "rpm"
    return None
