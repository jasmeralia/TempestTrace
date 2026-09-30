"""Synthetic tests for release selection and verified update downloads."""

from __future__ import annotations

import hashlib
import io
import json
import shlex
import subprocess
import sys
import time
import types
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from tempesttrace import updater
from tempesttrace.updater import (
    HTTPSRedirectHandler,
    SemVer,
    asset_name,
    check_for_update,
    detect_package_type,
    fetch_release_feed,
    installed_version,
    parse_sha256sums,
    verify_download,
    write_appimage_update_helper,
)


def release(
    tag: str,
    *,
    prerelease: bool = False,
    draft: bool = False,
    assets: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    result = {
        "tag_name": tag,
        "name": f"TempestTrace {tag}",
        "body": "Synthetic release notes",
        "prerelease": prerelease,
        "draft": draft,
        "html_url": f"https://example.invalid/releases/{tag}",
        "assets": assets or [],
    }
    result["checksums"] = {item["name"]: "a" * 64 for item in assets or []}
    return result


def asset(name: str, size: int = 42) -> dict[str, Any]:
    return {
        "name": name,
        "size": size,
        "browser_download_url": f"https://example.invalid/download/{name}",
    }


def test_release_selection_uses_semver_and_matching_windows_asset() -> None:
    releases = [
        release("v0.1.9", assets=[asset("TempestTrace-Setup-v0.1.9.exe")]),
        release("v0.1.10", assets=[asset("TempestTrace-Setup-v0.1.10.exe")]),
    ]
    offer = check_for_update("0.1.8", releases, "windows", "x86_64", "nsis", False)
    assert offer is not None
    assert offer.version == "0.1.10"
    assert offer.asset.name == "TempestTrace-Setup-v0.1.10.exe"


def test_https_redirect_handler_rejects_http_and_accepts_https() -> None:
    handler = HTTPSRedirectHandler()
    request = urllib.request.Request("https://example.test/start")
    with pytest.raises(urllib.error.HTTPError):
        handler.redirect_request(request, None, 302, "Found", {}, "http://example.test/target")
    redirected = handler.redirect_request(
        request, None, 302, "Found", {}, "https://example.test/target"
    )
    assert redirected is not None
    assert redirected.full_url == "https://example.test/target"


def test_semver_orders_numeric_prerelease_identifiers_before_stable() -> None:
    versions = [
        SemVer.parse("1.0.0"),
        SemVer.parse("1.0.0-rc.10"),
        SemVer.parse("1.0.0-beta.2"),
        SemVer.parse("1.0.0-beta.11"),
    ]
    assert sorted(versions) == [
        SemVer.parse("1.0.0-beta.2"),
        SemVer.parse("1.0.0-beta.11"),
        SemVer.parse("1.0.0-rc.10"),
        SemVer.parse("1.0.0"),
    ]


def test_stable_install_skips_beta_by_default_and_can_include_it() -> None:
    releases = [
        release(
            "v0.2.0-beta.2", prerelease=True, assets=[asset("TempestTrace-Setup-v0.2.0-beta.2.exe")]
        ),
        release("v0.1.9", assets=[asset("TempestTrace-Setup-v0.1.9.exe")]),
    ]
    stable = check_for_update("0.1.8", releases, "windows", "amd64", "nsis", False)
    beta = check_for_update("0.1.8", releases, "windows", "amd64", "nsis", True)
    assert stable is not None and stable.version == "0.1.9"
    assert beta is not None and beta.version == "0.2.0-beta.2"


def test_beta_install_skips_beta_unless_explicitly_opted_in() -> None:
    releases = [
        release(
            "v0.2.0-beta.2", prerelease=True, assets=[asset("TempestTrace-Setup-v0.2.0-beta.2.exe")]
        ),
        release("v0.1.9", assets=[asset("TempestTrace-Setup-v0.1.9.exe")]),
    ]
    default = check_for_update("0.2.0-beta.1", releases, "windows", "amd64", "nsis", False)
    opted_in = check_for_update("0.2.0-beta.1", releases, "windows", "amd64", "nsis", True)
    assert default is None
    assert opted_in is not None and opted_in.version == "0.2.0-beta.2"


def test_drafts_and_wrong_platform_architecture_or_package_are_ignored() -> None:
    releases = [
        release("v2.0.0", draft=True, assets=[asset("TempestTrace-Setup-v2.0.0.exe")]),
        release("v1.9.0", assets=[asset("TempestTrace-Setup-v1.9.0.exe")]),
        release(
            "v1.8.0",
            assets=[
                asset("TempestTrace-v1.8.0-linux-arm64.deb"),
                asset("TempestTrace-v1.8.0-linux-amd64.rpm"),
            ],
        ),
    ]
    offer = check_for_update("1.7.0", releases, "linux", "amd64", "deb", False)
    assert offer is None


def test_fallback_asset_match_rejects_unrelated_project() -> None:
    item = release(
        "v1.8.0",
        assets=[asset("OtherProject-v1.8.0-linux-amd64.deb")],
    )
    assert check_for_update("1.7.0", [item], "linux", "amd64", "deb", False) is None


def test_release_without_valid_asset_checksum_is_rejected() -> None:
    item = release("v1.0.0", assets=[asset("TempestTrace-Setup-v1.0.0.exe")])
    item["checksums"] = {"TempestTrace-Setup-v1.0.0.exe": "not-a-hash"}
    assert check_for_update("0.9.0", [item], "windows", "amd64", "nsis", False) is None


def test_linux_asset_matching_requires_os_arch_and_package() -> None:
    name = asset_name("v1.2.3", "linux", "arm64", "flatpak")
    assert name == "TempestTrace-v1.2.3-linux-arm64.flatpak"
    releases = [
        release(
            "v1.2.3",
            assets=[
                asset("TempestTrace-v1.2.3-linux-amd64.flatpak"),
                asset("TempestTrace-v1.2.3-linux-arm64.deb"),
                asset(name),
            ],
        )
    ]
    offer = check_for_update("1.2.2", releases, "linux", "aarch64", "flatpak", False)
    assert offer is not None and offer.asset.name == name


def test_linux_x86_64_appimage_asset_is_selected() -> None:
    name = "TempestTrace-v1.2.3-linux-x86_64.AppImage"
    releases = [release("v1.2.3", assets=[asset(name)])]

    offer = check_for_update("1.2.2", releases, "linux", "amd64", "appimage", False)

    assert offer is not None and offer.asset.name == name


def test_asset_with_conflicting_architecture_tokens_is_rejected() -> None:
    name = "TempestTrace-v1.2.3-linux-arm64-x64.deb"
    releases = [release("v1.2.3", assets=[asset(name)])]

    amd64 = check_for_update("1.2.2", releases, "linux", "amd64", "deb", False)
    arm64 = check_for_update("1.2.2", releases, "linux", "arm64", "deb", False)

    assert amd64 is None
    assert arm64 is None


def test_parse_sha256sums_handles_gnu_and_bsd_lines() -> None:
    digest = "a" * 64
    sums = parse_sha256sums(f"{digest}  one.deb\nSHA256 (two.rpm) = {'b' * 64}\n")
    assert sums == {"one.deb": digest, "two.rpm": "b" * 64}


def test_verified_download_streams_to_destination(tmp_path: Path) -> None:
    payload = b"synthetic package bytes"
    calls: list[str] = []

    def opener(url: str) -> io.BytesIO:
        calls.append(url)
        return io.BytesIO(payload)

    destination = tmp_path / "update.part"
    result = verify_download(
        "https://example.invalid/package",
        len(payload),
        hashlib.sha256(payload).hexdigest(),
        destination,
        opener=opener,
    )
    assert calls == ["https://example.invalid/package"]
    assert result == destination
    assert destination.read_bytes() == payload


@pytest.mark.parametrize(
    ("size", "digest"),
    [(99, hashlib.sha256(b"wrong").hexdigest()), (5, "0" * 64)],
)
def test_verified_download_rejects_size_or_hash_mismatch(
    tmp_path: Path, size: int, digest: str
) -> None:
    with pytest.raises(ValueError):
        verify_download(
            "https://example.invalid/package",
            size,
            digest,
            tmp_path / "update.part",
            opener=lambda _url: io.BytesIO(b"wrong"),
        )
    assert not (tmp_path / "update.part").exists()


def test_verified_download_enforces_size_ceiling(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="limit"):
        verify_download(
            "https://example.invalid/package",
            5,
            hashlib.sha256(b"12345").hexdigest(),
            tmp_path / "update.part",
            opener=lambda _url: io.BytesIO(b"12345"),
            max_size=4,
        )


def test_source_version_placeholder_is_not_an_installed_release() -> None:
    assert installed_version("0.0.0") is None
    assert installed_version("v1.2.3") == "1.2.3"


def test_package_detection_prefers_explicit_runtime_markers() -> None:
    assert detect_package_type("linux", {"APPIMAGE": "/tmp/app.AppImage"}) == "appimage"
    assert detect_package_type("linux", {"FLATPAK_ID": "io.github.example"}) == "flatpak"
    assert detect_package_type("linux", {"SNAP": "/snap/tempesttrace/current"}) == "snap"
    assert detect_package_type("windows", {}) == "nsis"


def test_semver_orders_numeric_prerelease_identifiers_and_rejects_bad_versions() -> None:
    assert SemVer.parse("v1.2.3-beta.2") < SemVer.parse("1.2.3-beta.10")
    assert SemVer.parse("1.2.3-beta") < SemVer.parse("1.2.3")
    with pytest.raises(ValueError):
        SemVer.parse("01.2.3")


def test_fetch_release_feed_reads_checksums_and_sha256_sidecars() -> None:
    filename = "TempestTrace-Setup-v1.2.3.exe"
    feed = [
        {
            "tag_name": "v1.2.3",
            "assets": [
                {"name": filename, "browser_download_url": "https://x/package"},
                {"name": "SHA256SUMS", "browser_download_url": "https://x/SHA256SUMS"},
                {
                    "name": f"{filename}.sha256",
                    "browser_download_url": "https://x/package.sha256",
                },
            ],
        }
    ]
    bodies = {
        "https://api.example.test/releases": json.dumps(feed).encode(),
        "https://x/SHA256SUMS": f"{'a' * 64}  {filename}\n".encode(),
        "https://x/package.sha256": f"{'b' * 64}  {filename}\n".encode(),
    }
    parsed = fetch_release_feed(
        "https://api.example.test/releases", lambda url: io.BytesIO(bodies[url])
    )
    assert parsed[0]["checksums"] == {filename: "b" * 64}


def test_fetch_release_feed_follows_pagination_for_later_stable_releases() -> None:
    filename = "TempestTrace-Setup-v1.3.0.exe"
    page_two_release = {
        "tag_name": "v1.3.0",
        "prerelease": False,
        "assets": [
            asset(filename),
            {
                "name": "SHA256SUMS",
                "browser_download_url": "https://assets.example.test/SHA256SUMS",
            },
        ],
    }
    page_urls: list[str] = []

    class PageResponse(io.BytesIO):
        def __init__(self, body: bytes, link: str | None = None) -> None:
            super().__init__(body)
            self.headers = {"Link": link} if link else {}

    responses = {
        "https://api.example.test/releases": PageResponse(
            b"[]", '<https://api.example.test/releases?page=2>; rel="next"'
        ),
        "https://api.example.test/releases?page=2": PageResponse(
            json.dumps([page_two_release]).encode()
        ),
        "https://assets.example.test/SHA256SUMS": PageResponse(
            f"{'c' * 64}  {filename}\n".encode()
        ),
    }

    def opener(url: str) -> PageResponse:
        page_urls.append(url)
        return responses[url]

    releases = fetch_release_feed("https://api.example.test/releases", opener)
    offer = check_for_update("1.2.0", releases, "windows", "amd64", "nsis", False)
    assert page_urls[:2] == [
        "https://api.example.test/releases",
        "https://api.example.test/releases?page=2",
    ]
    assert offer is not None and offer.version == "1.3.0"


def test_fetch_release_feed_ignores_old_unavailable_checksum_assets() -> None:
    old_asset_name = "TempestTrace-Setup-v1.0.0.exe"
    new_asset_name = "TempestTrace-Setup-v1.1.0.exe"
    feed = [
        {
            "tag_name": "v1.1.0",
            "prerelease": False,
            "assets": [
                asset(new_asset_name),
                {
                    "name": "SHA256SUMS",
                    "browser_download_url": "https://assets.example.test/new-sums",
                },
            ],
        },
        {
            "tag_name": "v1.0.0",
            "prerelease": False,
            "assets": [
                asset(old_asset_name),
                {
                    "name": "SHA256SUMS",
                    "browser_download_url": "https://assets.example.test/old-sums",
                },
            ],
        },
    ]
    requested: list[str] = []

    def opener(url: str) -> io.BytesIO:
        requested.append(url)
        if url == "https://api.example.test/releases":
            return io.BytesIO(json.dumps(feed).encode())
        if url == "https://assets.example.test/new-sums":
            return io.BytesIO(f"{'d' * 64}  {new_asset_name}\n".encode())
        raise OSError("historical checksum asset is unavailable")

    releases = fetch_release_feed("https://api.example.test/releases", opener)
    offer = check_for_update("0.9.0", releases, "windows", "amd64", "nsis", False)
    assert offer is not None and offer.version == "1.1.0"
    assert "https://assets.example.test/old-sums" not in requested


def test_fetch_release_feed_falls_back_after_unavailable_newest_checksum() -> None:
    newest = "TempestTrace-Setup-v1.2.0.exe"
    fallback = "TempestTrace-Setup-v1.1.0.exe"
    feed = [
        {
            "tag_name": "v1.2.0",
            "prerelease": False,
            "assets": [
                asset(newest),
                {
                    "name": "SHA256SUMS",
                    "browser_download_url": "https://assets.example.test/newest-sums",
                },
            ],
        },
        {
            "tag_name": "v1.1.0",
            "prerelease": False,
            "assets": [
                asset(fallback),
                {
                    "name": "SHA256SUMS",
                    "browser_download_url": "https://assets.example.test/fallback-sums",
                },
            ],
        },
    ]

    def opener(url: str) -> io.BytesIO:
        if url == "https://api.example.test/releases":
            return io.BytesIO(json.dumps(feed).encode())
        if url.endswith("newest-sums"):
            return io.BytesIO(b"not a SHA256SUMS manifest\n")
        if url.endswith("fallback-sums"):
            return io.BytesIO(f"{'f' * 64}  {fallback}\n".encode())
        raise AssertionError(url)

    releases = fetch_release_feed("https://api.example.test/releases", opener)
    offer = check_for_update("1.0.0", releases, "windows", "amd64", "nsis", False)
    assert offer is not None and offer.version == "1.1.0"


def test_fetch_release_feed_skips_bad_candidate_checksum_and_preserves_channels() -> None:
    release_data = [
        {
            "tag_name": "v1.3.0-beta.1",
            "prerelease": True,
            "assets": [
                asset("TempestTrace-Setup-v1.3.0-beta.1.exe"),
                {
                    "name": "SHA256SUMS",
                    "browser_download_url": "https://assets.example.test/beta-sums",
                },
            ],
        },
        {
            "tag_name": "v1.2.0",
            "prerelease": False,
            "assets": [
                asset("TempestTrace-Setup-v1.2.0.exe"),
                {
                    "name": "SHA256SUMS",
                    "browser_download_url": "https://assets.example.test/stable-sums",
                },
            ],
        },
    ]

    def opener(url: str) -> io.BytesIO:
        if url == "https://api.example.test/releases":
            return io.BytesIO(json.dumps(release_data).encode())
        if url.endswith("beta-sums"):
            raise OSError("bad beta checksum endpoint")
        if url.endswith("stable-sums"):
            return io.BytesIO(f"{'e' * 64}  TempestTrace-Setup-v1.2.0.exe\n".encode())
        raise AssertionError(url)

    releases = fetch_release_feed("https://api.example.test/releases", opener)
    stable = check_for_update("1.1.0", releases, "windows", "amd64", "nsis", False)
    beta = check_for_update("1.1.0", releases, "windows", "amd64", "nsis", True)
    assert stable is not None and stable.version == "1.2.0"
    assert beta is not None and beta.version == "1.2.0"


@pytest.mark.parametrize(
    ("url", "body", "message"),
    [
        ("http://api.example.test/releases", b"[]", "HTTPS"),
        ("https://api.example.test/releases", b"{", "Expecting"),
        ("https://api.example.test/releases", b"{}", "must be a list"),
    ],
)
def test_release_feed_rejects_invalid_responses(url: str, body: bytes, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        fetch_release_feed(url, lambda _url: io.BytesIO(body))


def test_update_selection_requires_https_asset_and_checksum() -> None:
    filename = "TempestTrace-Setup-v1.2.3.exe"
    releases = [release("v1.2.3", assets=[asset(filename)])]
    releases[0]["checksums"] = {}
    assert check_for_update("1.2.2", releases, "windows", "amd64", "nsis", False) is None
    releases[0]["checksums"] = {filename: "a" * 64}
    releases[0]["assets"][0]["browser_download_url"] = "http://example.test/package"
    assert check_for_update("1.2.2", releases, "windows", "amd64", "nsis", False) is None


def test_installed_version_reads_embedded_build_info(monkeypatch) -> None:
    build_info = types.ModuleType("tempesttrace._build_info")
    build_info.VERSION = "v4.5.6"
    monkeypatch.setattr(updater.sys, "frozen", True, raising=False)
    monkeypatch.setitem(sys.modules, "tempesttrace._build_info", build_info)
    assert installed_version() == "4.5.6"


@pytest.mark.parametrize(
    ("tool", "results", "expected"),
    [("dpkg-query", [0], "deb"), ("rpm", [0], "rpm")],
)
def test_package_detection_uses_installed_package_ownership(
    monkeypatch, tool: str, results: list[int], expected: str
) -> None:
    monkeypatch.setattr(updater.Path, "exists", lambda _path: False)
    monkeypatch.setattr(updater.shutil, "which", lambda name: tool if name == tool else None)
    returned = iter(results)

    def run(*args, **kwargs):
        code = next(returned)
        return types.SimpleNamespace(returncode=code, stdout="tempesttrace: installed")

    monkeypatch.setattr(updater.subprocess, "run", run)
    assert detect_package_type("linux", {}, "/usr/bin/tempesttrace") == expected


def test_appimage_update_helper_waits_replaces_and_keeps_rollback(tmp_path: Path) -> None:
    current = tmp_path / "current AppImage"
    current.write_bytes(b"old")
    stage = tmp_path / ".stage"
    stage.mkdir()
    downloaded = stage / "new AppImage"
    downloaded.write_bytes(b"new")
    helper = stage / "apply-update.sh"
    result = write_appimage_update_helper(current, downloaded, helper, process_id=4321)
    script = result.read_text(encoding="utf-8")
    assert "kill -0 '4321'" in script
    assert "tempesttrace-rollback" in script
    assert "rollback=$(mktemp" in script
    assert 'rm -f -- "$rollback"' in script
    assert 'rmdir "$rollback"' not in script
    assert "mv" in script and "chmod +x" in script
    assert '"$current" --smoke-test' in script
    assert "sleep 10" not in script
    assert 'nohup env PYINSTALLER_RESET_ENVIRONMENT=1 "$current"' in script
    assert script.index('rm -f -- "$rollback"') < script.index("trap - EXIT HUP INT TERM")
    assert script.index("trap - EXIT HUP INT TERM") < script.index(
        "nohup env PYINSTALLER_RESET_ENVIRONMENT=1"
    )
    assert "current AppImage" in script and "new AppImage" in script


@pytest.mark.parametrize(("smoke_exit", "expected_exit"), [(0, 0), (9, 1)])
def test_appimage_helper_uses_smoke_test_and_rolls_back_only_on_failure(
    tmp_path: Path, smoke_exit: int, expected_exit: int
) -> None:
    current = tmp_path / "TempestTrace.AppImage"
    current.write_bytes(b"old")
    stage = tmp_path / "stage"
    stage.mkdir()
    downloaded = stage / "TempestTrace.new.AppImage"
    events = tmp_path / "app-events.log"
    events_q = shlex.quote(str(events))
    new_payload = (
        "#!/bin/sh\n"
        f"events={events_q}\n"
        'if [ "${1-}" = --smoke-test ]; then\n'
        '    echo smoke >> "$events"\n'
        f"    exit {smoke_exit}\n"
        "fi\n"
        'echo "launch:${PYINSTALLER_RESET_ENVIRONMENT:-missing}" >> "$events"\n'
    )
    downloaded.write_text(new_payload, encoding="utf-8")
    downloaded.chmod(0o700)
    helper = stage / "apply-update.sh"
    write_appimage_update_helper(current, downloaded, helper, process_id=2**30)

    result = subprocess.run(["/bin/sh", str(helper)], check=False, capture_output=True)

    assert result.returncode == expected_exit
    assert current.read_bytes() == (new_payload.encode() if smoke_exit == 0 else b"old")
    assert not list(tmp_path.glob("*.tempesttrace-rollback.*"))
    deadline = time.monotonic() + 2
    while smoke_exit == 0 and time.monotonic() < deadline:
        if events.exists() and "launch:1" in events.read_text(encoding="utf-8"):
            break
        time.sleep(0.01)
    event_text = events.read_text(encoding="utf-8") if events.exists() else ""
    if smoke_exit == 0:
        assert event_text.splitlines() == ["smoke", "launch:1"]
    else:
        assert event_text.splitlines() == ["smoke"]
