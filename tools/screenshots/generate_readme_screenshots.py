#!/usr/bin/env python3
"""Capture README screenshots from TempestTrace with synthetic OBS data.

The real PyQt window runs offscreen against a disposable profile, log, and
destination. No host OBS configuration or user settings are read or changed.

Usage:
    python tools/screenshots/generate_readme_screenshots.py

Re-run after UI changes to regenerate the images embedded by README.md.
"""

# Set the isolated HOME and Qt platform before importing Qt or app modules.
# ruff: noqa: E402

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path

_SCRATCH_HOME = Path(tempfile.mkdtemp(prefix="tempesttrace-readme-home-"))
os.environ["HOME"] = str(_SCRATCH_HOME)
os.environ["XDG_CONFIG_HOME"] = str(_SCRATCH_HOME / ".config")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from PyQt6.QtWidgets import QApplication

from tempesttrace import ui
from tempesttrace.ui import MainWindow

OUT_DIR = REPO_ROOT / "docs" / "images"


def _create_sample_obs(root: Path) -> Path:
    profile = root / "basic" / "profiles" / "Sample Profile"
    scenes = root / "basic" / "scenes"
    logs = root / "logs"
    profile.mkdir(parents=True)
    scenes.mkdir(parents=True)
    logs.mkdir(parents=True)

    (profile / "service.json").write_text(
        json.dumps(
            {
                "type": "rtmp_custom",
                "settings": {
                    "server": "rtmp://stream.example.test/app",
                    "streamKey": "SYNTHETIC_STREAM_SECRET",
                },
            }
        ),
        encoding="utf-8",
    )
    (scenes / "Sample Scene.json").write_text(
        json.dumps({"name": "Sample Scene", "sources": []}), encoding="utf-8"
    )
    (root / "global.ini").write_text("[General]\nName=Sample OBS Setup\n", encoding="utf-8")
    (logs / "2026-09-28.txt").write_text(
        "Starting stream token=SYNTHETIC_LOG_SECRET\nhotkey binding key=F9\n",
        encoding="utf-8",
    )
    return root


def _capture(window: MainWindow, name: str) -> None:
    QApplication.processEvents()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    output = OUT_DIR / name
    if not window.grab().save(str(output), "PNG"):
        raise RuntimeError(f"Could not save screenshot: {output}")
    print(f"Wrote {output} ({window.width()}x{window.height()})")


def _wait_for_backup(app: QApplication, window: MainWindow) -> None:
    deadline = time.monotonic() + 15
    while window.worker_thread is not None and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.02)
    app.processEvents()
    if window.worker_thread is not None or window.last_result is None:
        raise RuntimeError("Synthetic backup did not finish successfully")


def main() -> None:
    try:
        app = QApplication(sys.argv)
        app.setApplicationName("TempestTrace README screenshot capture")

        source = _create_sample_obs(_SCRATCH_HOME / "obs-studio")
        dropbox = _SCRATCH_HOME / "Dropbox"
        destination = dropbox / "TempestTrace Sample Backups" / "obs logs"
        destination.mkdir(parents=True)

        # Patch discovery at the GUI boundary; all file contents and paths are synthetic.
        ui.discover_obs = lambda: [source]
        ui.discover_dropbox = lambda: dropbox

        window = MainWindow(enable_updates=False)
        window.resize(860, 500)
        window.obs_combo.setItemText(0, "~/Documents/OBS Studio/Sample Profile")
        window.destination = destination
        window.destination_label.setText("~/Dropbox/TempestTrace Sample Backups/obs logs")
        window.show()
        app.processEvents()

        _capture(window, "main-window.png")

        window._start_backup()
        _wait_for_backup(app, window)
        assert window.last_result is not None
        actual_archive = window.last_result.archive
        screenshot_archive = Path(
            "~/Dropbox/TempestTrace Sample Backups/obs logs/TempestTrace-2026-09-29-120000.zip"
        )
        window.last_result = replace(window.last_result, archive=screenshot_archive)
        window.detail.setText(
            window.detail.text().replace(str(actual_archive), str(screenshot_archive))
        )
        window.status_bar.showMessage("Backup complete", 5000)
        _capture(window, "backup-complete.png")
        window.close()
    finally:
        shutil.rmtree(_SCRATCH_HOME, ignore_errors=True)


if __name__ == "__main__":
    main()
