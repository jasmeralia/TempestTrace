"""Operating-system-specific OBS and Dropbox path discovery."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from pathlib import Path


def _home(env: Mapping[str, str]) -> Path:
    return Path(env.get("HOME") or env.get("USERPROFILE") or Path.home()).expanduser()


def discover_obs(platform: str | None = None, env: Mapping[str, str] | None = None) -> list[Path]:
    """Return existing standard OBS configuration roots, in preference order."""
    values = os.environ if env is None else env
    system = (platform or sys.platform).lower()
    candidates: list[Path] = []
    if system.startswith("win") or system == "windows":
        if values.get("APPDATA"):
            candidates.append(Path(values["APPDATA"]) / "obs-studio")
    else:
        home = _home(values)
        real_home = (
            Path(values["SNAP_REAL_HOME"]).expanduser() if values.get("SNAP_REAL_HOME") else None
        )
        sandboxed = bool(
            values.get("FLATPAK_ID")
            or values.get("SNAP")
            or values.get("container") == "flatpak"
            or Path("/.flatpak-info").exists()
        )
        if values.get("HOST_XDG_CONFIG_HOME"):
            host_config = Path(values["HOST_XDG_CONFIG_HOME"])
        elif real_home is not None:
            host_config = real_home / ".config"
        elif values.get("XDG_CONFIG_HOME") and not sandboxed:
            host_config = Path(values["XDG_CONFIG_HOME"])
        else:
            host_config = home / ".config"
        candidates.extend((host_config / "obs-studio",))
        if real_home is not None:
            candidates.append(real_home / ".var/app/com.obsproject.Studio/config/obs-studio")
        candidates.append(home / ".var/app/com.obsproject.Studio/config/obs-studio")
    return list(dict.fromkeys(path for path in candidates if path.is_dir()))


def discover_dropbox(
    platform: str | None = None, env: Mapping[str, str] | None = None
) -> Path | None:
    """Resolve the configured Dropbox root from its local info.json metadata."""
    values = os.environ if env is None else env
    system = (platform or sys.platform).lower()
    if system.startswith("win") or system == "windows":
        candidates = [
            Path(values[key]) / "Dropbox/info.json"
            for key in ("APPDATA", "LOCALAPPDATA")
            if values.get(key)
        ]
    else:
        homes = (
            [Path(values["SNAP_REAL_HOME"]).expanduser()] if values.get("SNAP_REAL_HOME") else []
        )
        homes.append(_home(values))
        candidates = [home / ".dropbox/info.json" for home in homes]
    for info in candidates:
        try:
            data = json.loads(info.read_text(encoding="utf-8"))
        except OSError, UnicodeError, json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        for account in data.values():
            if isinstance(account, dict) and isinstance(account.get("path"), str):
                root = Path(account["path"]).expanduser()
                if root.is_dir():
                    return root
    return None
