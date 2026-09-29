from pathlib import Path


def test_flatpak_only_gets_read_only_obs_configuration_access() -> None:
    script = Path("packaging/linux/build-packages.sh").read_text(encoding="utf-8")

    assert "--filesystem=home \\" not in script
    assert "--filesystem=home:ro" in script
    assert "--filesystem=xdg-config/obs-studio:ro" in script
    assert "--filesystem='~/.var/app/com.obsproject.Studio/config/obs-studio:ro'" in script
    assert "--filesystem='~/.dropbox:ro'" in script
    assert "--filesystem='~/Dropbox:rw'" in script
