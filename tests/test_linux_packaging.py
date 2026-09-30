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
