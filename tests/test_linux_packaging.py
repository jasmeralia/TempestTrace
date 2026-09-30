from pathlib import Path


def test_flatpak_only_gets_read_only_obs_configuration_access() -> None:
    script = Path("packaging/linux/build-packages.sh").read_text(encoding="utf-8")

    assert "--filesystem=home \\" not in script
    assert "--filesystem=home:ro" in script
    assert "--filesystem=xdg-config/obs-studio:ro" in script
    assert "--filesystem='~/.var/app/com.obsproject.Studio/config/obs-studio:ro'" in script
    assert "--filesystem='~/.dropbox:ro'" in script
    assert "--filesystem='~/Dropbox:rw'" in script


def test_workflow_pins_and_checksums_appimagetool_before_execution() -> None:
    workflow = Path(".github/workflows/linux-packages.yml").read_text(encoding="utf-8")
    readme = Path("packaging/linux/README.md").read_text(encoding="utf-8")
    assert "name: Install pinned appimagetool" in workflow
    assert "https://github.com/AppImage/appimagetool/releases/download/1.9.1" in workflow
    assert "AppImageKit" not in workflow + readme
    assert "ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0" in workflow
    assert "f0837e7448a0c1e4e650a93bb3e85802546e60654ef287576f46c71c126a9158" in workflow
    assert "sha256sum --check --strict -" in workflow
    assert workflow.index("sha256sum --check --strict -") < workflow.index(
        "chmod +x /tmp/appimagetool"
    )


def test_linux_workflow_targets_ubuntu_2404_and_glibc_239() -> None:
    workflow = Path(".github/workflows/linux-packages.yml").read_text(encoding="utf-8")
    script = Path("packaging/linux/build-packages.sh").read_text(encoding="utf-8")

    assert "ubuntu-22.04" not in workflow
    assert "runner: ubuntu-24.04" in workflow
    assert "runner: ubuntu-24.04-arm" in workflow
    assert "libfuse2t64" in workflow
    assert "libc6 (>= 2.39)" in script
    assert "glibc >= 2.39" in script


def test_flatpak_permissions_are_checked_as_exact_tokens() -> None:
    workflow = Path(".github/workflows/linux-packages.yml").read_text(encoding="utf-8")
    script = Path("packaging/linux/build-packages.sh").read_text(encoding="utf-8")

    assert "filesystems_line" in workflow
    assert "IFS=';'" in workflow
    assert "has_filesystem '~/Dropbox'" in workflow
    assert "has_filesystem '~/Dropbox:rw'" in workflow
    for token in (
        "has_filesystem 'home:ro'",
        "has_filesystem 'xdg-config/obs-studio:ro'",
        "has_filesystem '~/.dropbox:ro'",
        "has_filesystem '~/.var/app/com.obsproject.Studio/config/obs-studio:ro'",
    ):
        assert token in workflow
    assert "--runtime-repo=https://dl.flathub.org/repo/flathub.flatpakrepo" in script


def test_appimage_build_requires_and_passes_pinned_runtime() -> None:
    workflow = Path(".github/workflows/linux-packages.yml").read_text(encoding="utf-8")
    script = Path("packaging/linux/build-packages.sh").read_text(encoding="utf-8")
    readme = Path("packaging/linux/README.md").read_text(encoding="utf-8")

    x86_digest = "2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d"
    arm_digest = "00cbdfcf917cc6c0ff6d3347d59e0ca1f7f45a6df1a428a0d6d8a78664d87444"
    assert x86_digest in workflow
    assert arm_digest in workflow
    runtime_step = workflow.index("name: Install pinned AppImage runtime")
    checksum = workflow.index("sha256sum --check --strict -", runtime_step)
    assert checksum < workflow.index("APPIMAGE_RUNTIME_FILE=/tmp/appimage-runtime")
    assert 'APPIMAGE_RUNTIME_FILE"' in script
    assert '--runtime-file "$APPIMAGE_RUNTIME_FILE"' in script
    assert "APPIMAGE_RUNTIME_FILE" in readme


def test_release_workflow_includes_supported_platform_notes() -> None:
    workflow = Path(".github/workflows/release.yml").read_text(encoding="utf-8")

    assert "--notes-file" in workflow
    for note in (
        "Windows 10/11 x64 NSIS installer",
        "Ubuntu 24.04",
        "glibc 2.39",
        "Fedora 42",
        "sudo snap connect tempesttrace:obs-config",
        "sideloaded",
    ):
        assert note in workflow
