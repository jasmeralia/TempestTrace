from pathlib import Path

from tempesttrace.paths import discover_dropbox, discover_obs


def test_windows_paths_and_dropbox_location(tmp_path: Path) -> None:
    roaming = tmp_path / "roaming"
    local = tmp_path / "local"
    native = roaming / "obs-studio"
    native.mkdir(parents=True)
    drop = tmp_path / "DropboxRoot"
    drop.mkdir()
    (local / "Dropbox").mkdir(parents=True)
    (local / "Dropbox" / "info.json").write_text(
        '{"personal": {"path": "' + str(drop).replace("\\", "\\\\") + '"}}',
        encoding="utf-8",
    )
    assert discover_obs("Windows", {"APPDATA": str(roaming)}) == [native]
    assert discover_dropbox("Windows", {"LOCALAPPDATA": str(local)}) == drop


def test_linux_native_and_flatpak_candidates_ignore_sandbox_xdg(tmp_path: Path) -> None:
    host_config = tmp_path / "host-config"
    native = host_config / "obs-studio"
    flatpak = tmp_path / ".var/app/com.obsproject.Studio/config/obs-studio"
    native.mkdir(parents=True)
    flatpak.mkdir(parents=True)
    candidates = discover_obs(
        "Linux",
        {
            "HOME": str(tmp_path),
            "XDG_CONFIG_HOME": str(tmp_path / "sandbox"),
            "HOST_XDG_CONFIG_HOME": str(host_config),
        },
    )
    assert candidates == [native, flatpak]


def test_linux_native_obs_uses_custom_xdg_config_home(tmp_path: Path) -> None:
    custom_config = tmp_path / "custom-config"
    native = custom_config / "obs-studio"
    native.mkdir(parents=True)
    assert discover_obs(
        "Linux", {"HOME": str(tmp_path), "XDG_CONFIG_HOME": str(custom_config)}
    ) == [native]


def test_flatpak_obs_falls_back_to_host_default_config_home(tmp_path: Path) -> None:
    native = tmp_path / ".config/obs-studio"
    native.mkdir(parents=True)
    assert discover_obs(
        "Linux",
        {
            "HOME": str(tmp_path),
            "FLATPAK_ID": "io.github.jasmeralia.TempestTrace",
            "XDG_CONFIG_HOME": str(tmp_path / ".var/app/io.github.jasmeralia.TempestTrace/config"),
        },
    ) == [native]


def test_linux_dropbox_metadata_resolves_relocated_folder(tmp_path: Path) -> None:
    relocated = tmp_path / "Synced/Dropbox"
    relocated.mkdir(parents=True)
    info = tmp_path / ".dropbox/info.json"
    info.parent.mkdir()
    info.write_text('{"personal": {"path": "' + str(relocated) + '"}}', encoding="utf-8")
    assert discover_dropbox("Linux", {"HOME": str(tmp_path)}) == relocated


def test_snap_real_home_discovers_host_obs_and_dropbox(tmp_path: Path) -> None:
    snap_home = tmp_path / "snap-home"
    host_config = snap_home / ".config/obs-studio"
    host_config.mkdir(parents=True)
    dropbox = tmp_path / "Dropbox"
    dropbox.mkdir()
    metadata = snap_home / ".dropbox/info.json"
    metadata.parent.mkdir(parents=True)
    metadata.write_text(
        '{"personal": {"path": "' + str(dropbox).replace("\\", "\\\\") + '"}}',
        encoding="utf-8",
    )
    env = {"HOME": str(tmp_path / "snap/current"), "SNAP_REAL_HOME": str(snap_home)}

    assert discover_obs("Linux", env) == [host_config]
    assert discover_dropbox("Linux", env) == dropbox
