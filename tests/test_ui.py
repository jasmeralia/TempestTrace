from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import cast

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QThread
from PyQt6.QtGui import QCloseEvent, QDesktopServices
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QFileDialog, QMessageBox

from tempesttrace.backup import BackupResult
from tempesttrace.ui import BackupWorker, MainWindow, UpdateDownloadWorker, main
from tempesttrace.updater import ReleaseAsset, UpdateOffer


def test_window_initializes_discovered_locations_and_completion_actions(
    tmp_path: Path, monkeypatch
) -> None:
    app = QApplication.instance() or QApplication([])
    obs = tmp_path / "obs"
    proposed = tmp_path / "Dropbox/Jasmeralia and Rin/obs logs"
    obs.mkdir()
    proposed.mkdir(parents=True)
    monkeypatch.setattr("tempesttrace.ui.discover_obs", lambda: [obs])
    monkeypatch.setattr("tempesttrace.ui.discover_dropbox", lambda: proposed.parents[1])

    window = MainWindow(enable_updates=False)
    assert window.obs_combo.count() == 1
    assert window.obs_combo.currentData() == obs
    assert window.destination == proposed

    archive = proposed / "backup.zip"
    result = BackupResult(archive, 3, 1, {"credential_field": 2}, ())
    window._on_finished(result)
    assert not window.open_zip_button.isHidden()
    assert not window.open_dir_button.isHidden()
    assert "credential_field: 2" in window.detail.text()
    window.close()
    assert app is not None


def test_window_keeps_proposed_dropbox_destination_when_not_created_yet(
    tmp_path: Path, monkeypatch
) -> None:
    app = QApplication.instance() or QApplication([])
    obs = tmp_path / "obs"
    dropbox = tmp_path / "Dropbox"
    obs.mkdir()
    dropbox.mkdir()
    proposed = dropbox / "Jasmeralia and Rin/obs logs"
    monkeypatch.setattr("tempesttrace.ui.discover_obs", lambda: [obs])
    monkeypatch.setattr("tempesttrace.ui.discover_dropbox", lambda: dropbox)

    window = MainWindow(enable_updates=False)

    assert window.destination == proposed
    assert not proposed.exists()
    assert window.destination_label.text() == str(proposed)
    window.close()
    assert app is not None


def test_close_waits_for_backup_and_update_workers(monkeypatch: pytest.MonkeyPatch) -> None:
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr("tempesttrace.ui.discover_obs", lambda: [])
    monkeypatch.setattr("tempesttrace.ui.discover_dropbox", lambda: None)
    window = MainWindow(enable_updates=False)

    class RunningThread:
        running = True

        def isRunning(self) -> bool:
            return self.running

    backup_thread = RunningThread()
    update_thread = RunningThread()
    window.worker_thread = cast(QThread, backup_thread)
    window.update_thread = cast(QThread, update_thread)
    window.cancel_event = threading.Event()

    close_event = QCloseEvent()
    window.closeEvent(close_event)
    assert not close_event.isAccepted()
    assert window._close_requested
    assert window.cancel_event.is_set()

    backup_thread.running = False
    window._finish_deferred_close()
    assert not window._allow_close

    update_thread.running = False
    window._finish_deferred_close()
    assert window._allow_close
    assert app is not None


def test_incomplete_output_can_be_removed_after_cancel_or_failure(
    tmp_path: Path, monkeypatch
) -> None:
    app = QApplication.instance() or QApplication([])
    obs = tmp_path / "obs"
    obs.mkdir()
    monkeypatch.setattr("tempesttrace.ui.discover_obs", lambda: [obs])
    monkeypatch.setattr("tempesttrace.ui.discover_dropbox", lambda: None)
    window = MainWindow(enable_updates=False)
    output = tmp_path / "out"
    output.mkdir()
    window.destination = output
    partial = output / ".TempestTrace-2026-09-28.incomplete-stage"
    partial.mkdir()
    window._output_before = set()
    window._worker_stopped()
    assert not window.cleanup_button.isHidden()
    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *args, **kwargs: QMessageBox.StandardButton.Yes,
    )
    window._remove_incomplete()
    assert not partial.exists()
    assert window.cleanup_button.isHidden()
    window.close()
    assert app is not None


def test_incomplete_zip_is_included_in_cleanup(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    obs = tmp_path / "obs"
    obs.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    monkeypatch.setattr("tempesttrace.ui.discover_obs", lambda: [obs])
    monkeypatch.setattr("tempesttrace.ui.discover_dropbox", lambda: None)
    window = MainWindow()
    window.destination = output
    partial = output / "TempestTrace-2026-09-28_12-00-00.incomplete.zip"
    partial.write_bytes(b"partial")
    window._incomplete_outputs = [partial]
    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *args, **kwargs: QMessageBox.StandardButton.Yes,
    )

    window._remove_incomplete()

    assert not partial.exists()
    assert window.cleanup_button.isHidden()
    window.close()
    assert app is not None


def test_worker_stopped_handles_disappearing_destination(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    obs = tmp_path / "obs"
    obs.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    monkeypatch.setattr("tempesttrace.ui.discover_obs", lambda: [obs])
    monkeypatch.setattr("tempesttrace.ui.discover_dropbox", lambda: None)
    window = MainWindow()
    window.destination = output
    output.rmdir()

    window._worker_stopped()

    assert window._incomplete_outputs == []
    assert window.cleanup_button.isHidden()
    assert window.run_button.isEnabled()
    window.close()
    assert app is not None


def test_smoke_test_mode_opens_window_without_network_updates(monkeypatch) -> None:
    app = cast(QApplication, QApplication.instance() or QApplication([]))
    existing_windows = {id(window) for window in app.topLevelWidgets()}
    lifecycle: list[str] = []
    monkeypatch.setattr("tempesttrace.ui.discover_obs", lambda: [])
    monkeypatch.setattr("tempesttrace.ui.discover_dropbox", lambda: None)
    original_show = MainWindow.show
    original_close = MainWindow.close
    original_process_events = QApplication.processEvents

    def record_show(window: MainWindow) -> None:
        lifecycle.append("show")
        original_show(window)

    def record_close(window: MainWindow) -> bool:
        lifecycle.append("close")
        return original_close(window)

    def record_process_events(*args: object) -> None:
        lifecycle.append("processEvents")
        original_process_events(*args)

    monkeypatch.setattr(MainWindow, "show", record_show)
    monkeypatch.setattr(MainWindow, "close", record_close)
    monkeypatch.setattr(QApplication, "processEvents", staticmethod(record_process_events))

    def unexpected_network_call(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("smoke test must not contact update services")

    monkeypatch.setattr("tempesttrace.ui.fetch_release_feed", unexpected_network_call)
    monkeypatch.setattr("tempesttrace.ui.check_for_update", unexpected_network_call)
    monkeypatch.setattr("sys.argv", ["tempesttrace", "--smoke-test"])

    assert main() == 0

    created_windows = [
        window
        for window in app.topLevelWidgets()
        if isinstance(window, MainWindow) and id(window) not in existing_windows
    ]
    assert len(created_windows) == 1
    assert not created_windows[0].isVisible()
    assert not created_windows[0].updates_enabled
    assert created_windows[0].update_thread is None
    assert lifecycle == ["show", "processEvents", "close", "processEvents"]


def test_window_folder_actions_progress_and_cancel(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    obs = tmp_path / "obs"
    obs.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    monkeypatch.setattr("tempesttrace.ui.discover_obs", lambda: [])
    monkeypatch.setattr("tempesttrace.ui.discover_dropbox", lambda: None)
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *args: str(obs))
    window = MainWindow()
    window._choose_obs()
    assert window.obs_combo.currentData() == obs
    monkeypatch.setattr(QFileDialog, "getExistingDirectory", lambda *args: str(output))
    window._choose_destination()
    assert window.destination == output
    window._on_progress("copying", 1, 2)
    assert window.progress.value() == 1
    window.cancel_event = __import__("threading").Event()
    window._cancel_backup()
    assert window.cancel_event.is_set()
    window._on_failed("safe generic message", "ValueError")
    window._on_cancelled()
    window.close()
    assert app is not None


def test_worker_reports_success_and_sanitized_failure(tmp_path: Path) -> None:
    obs = tmp_path / "obs"
    (obs / "basic/profiles/default").mkdir(parents=True)
    (obs / "basic/profiles/default/service.json").write_text('{"key":"secret"}', encoding="utf-8")
    output = tmp_path / "out"
    output.mkdir()
    event = __import__("threading").Event()
    worker = BackupWorker(obs, output, event)
    successes: list[object] = []
    worker.finished.connect(successes.append)
    worker.run()
    assert isinstance(successes[0], BackupResult)

    bad_worker = BackupWorker(obs, obs / "missing", event)
    failures: list[tuple[str, str]] = []
    bad_worker.failed.connect(lambda text, kind: failures.append((text, kind)))
    bad_worker.run()
    assert failures == [
        ("The selected OBS or backup folder is no longer available.", "FileNotFoundError")
    ]


def test_window_runs_worker_and_offers_result_actions(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    obs = tmp_path / "obs"
    obs.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    monkeypatch.setattr("tempesttrace.ui.discover_obs", lambda: [obs])
    monkeypatch.setattr("tempesttrace.ui.discover_dropbox", lambda: None)
    window = MainWindow()
    window.destination = output
    archive = output / "made.zip"
    monkeypatch.setattr(
        "tempesttrace.ui.create_backup",
        lambda source, destination, **kwargs: BackupResult(archive, 1, 0, {}, ()),
    )
    window._start_backup()
    thread = window.worker_thread
    assert thread is not None
    QTest.qWait(100)
    app.processEvents()
    assert thread.isFinished()
    assert window.last_result is not None
    assert window.run_button.isEnabled()
    opened: list[object] = []

    def record_open(url: object) -> None:
        opened.append(url)

    monkeypatch.setattr(QDesktopServices, "openUrl", record_open)
    window._open_folder()
    window._open_zip()
    assert len(opened) == 2
    window._copy_path()
    assert app.clipboard().text() == str(archive)
    monkeypatch.setattr(QMessageBox, "about", lambda *args: None)
    window._about()
    window.close()


def test_start_rejects_missing_source_and_destination(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr("tempesttrace.ui.discover_obs", lambda: [])
    monkeypatch.setattr("tempesttrace.ui.discover_dropbox", lambda: None)
    window = MainWindow()
    prompts: list[str] = []
    monkeypatch.setattr(QMessageBox, "warning", lambda *args: prompts.append(args[1]))
    window._start_backup()
    assert prompts == ["Choose OBS"]
    obs = tmp_path / "obs"
    obs.mkdir()
    window.obs_combo.addItem(str(obs), obs)
    window._start_backup()
    assert prompts[-1] == "Choose destination"
    window.close()
    assert app is not None


def test_start_backup_waits_until_update_worker_stops(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    obs = tmp_path / "obs"
    obs.mkdir()
    monkeypatch.setattr("tempesttrace.ui.discover_obs", lambda: [obs])
    monkeypatch.setattr("tempesttrace.ui.discover_dropbox", lambda: None)
    warnings: list[str] = []
    monkeypatch.setattr(QMessageBox, "warning", lambda _w, title, *_args: warnings.append(title))
    window = MainWindow(enable_updates=False)
    window.destination = tmp_path / "backup"

    class RunningThread:
        def isRunning(self) -> bool:
            return True

    window.update_thread = cast(QThread, RunningThread())
    window._start_backup()

    assert warnings == ["Update in progress"]
    assert not window.destination.exists()
    window.update_thread = None
    window.close()
    assert app is not None


def test_manual_update_check_waits_until_backup_stops(monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr("tempesttrace.ui.discover_obs", lambda: [])
    monkeypatch.setattr("tempesttrace.ui.discover_dropbox", lambda: None)
    warnings: list[str] = []
    monkeypatch.setattr(
        QMessageBox, "information", lambda _w, title, *_args: warnings.append(title)
    )
    window = MainWindow()

    class RunningThread:
        def isRunning(self) -> bool:
            return True

    window.worker_thread = cast(QThread, RunningThread())
    window._check_for_updates(manual=True)

    assert warnings == ["Backup in progress"]
    assert window.update_thread is None
    window.worker_thread = None
    window.close()
    assert app is not None


def test_automatic_update_check_is_deferred_until_backup_stops(monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr("tempesttrace.ui.discover_obs", lambda: [])
    monkeypatch.setattr("tempesttrace.ui.discover_dropbox", lambda: None)
    window = MainWindow(enable_updates=False)

    class RunningThread:
        running = True

        def isRunning(self) -> bool:
            return self.running

    backup_thread = RunningThread()
    window.worker_thread = cast(QThread, backup_thread)
    checks: list[bool] = []
    monkeypatch.setattr(window, "_check_for_updates", lambda *, manual: checks.append(manual))
    window._automatic_update_check()

    assert checks == []
    assert window._automatic_update_pending
    backup_thread.running = False
    window._worker_stopped()

    assert checks == [False]
    assert not window._automatic_update_pending
    window.close()
    assert app is not None


def test_update_preferences_and_manual_source_build_check(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr("tempesttrace.ui.discover_obs", lambda: [])
    monkeypatch.setattr("tempesttrace.ui.discover_dropbox", lambda: None)
    monkeypatch.setattr("tempesttrace.ui.installed_version", lambda: None)
    monkeypatch.setattr("tempesttrace.ui.detect_package_type", lambda: None)
    monkeypatch.setattr("tempesttrace.ui.VERSION", "0.2.0-beta.1")
    monkeypatch.setattr(QMessageBox, "information", lambda *args: None)
    window = MainWindow()
    assert not window.include_beta_action.isChecked()

    class Preferences:
        def __init__(self) -> None:
            self.values: dict[str, object] = {}

        def setValue(self, key: str, value: object) -> None:
            self.values[key] = value

        def contains(self, key: str) -> bool:
            return key in self.values

    prefs = Preferences()
    window.settings = prefs
    window._save_auto_update_preference(False)
    window._save_beta_preference(True)
    assert prefs.values == {"updates/automatic": False, "updates/include_beta": True}
    prefs.values.pop("updates/include_beta")
    window.auto_update_action.setChecked(False)
    window._automatic_update_check()
    assert window.update_thread is None
    window._on_update_found((None, False))
    assert not window.include_beta_action.isChecked()
    window._check_for_updates(manual=True)
    thread = window.update_thread
    assert thread is not None
    QTest.qWait(100)
    app.processEvents()
    assert thread.isFinished()
    assert window.update_thread is None
    window.close()


def test_update_error_states_keep_collection_available(monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr("tempesttrace.ui.discover_obs", lambda: [])
    monkeypatch.setattr("tempesttrace.ui.discover_dropbox", lambda: None)
    prompts: list[str] = []
    warning_text: list[str] = []
    monkeypatch.setattr(QMessageBox, "information", lambda _w, title, *_args: prompts.append(title))

    def record_warning(_window, title: str, message: str) -> None:
        prompts.append(title)
        warning_text.append(message)

    monkeypatch.setattr(QMessageBox, "warning", record_warning)
    window = MainWindow()
    window._manual_update_check = True
    window._on_update_failed()
    window._on_update_download_failed()
    window._on_update_downloaded(object())
    assert prompts == [
        "Update check unavailable",
        "Update download failed",
        "Update",
    ]
    assert "could not be downloaded or verified" in warning_text[0]
    assert "size or SHA-256 check" not in warning_text[0]
    window.close()
    assert app is not None


def test_sandboxed_package_update_downloads_to_host_visible_folder(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr("tempesttrace.ui.Path.home", lambda: tmp_path)
    monkeypatch.setattr("tempesttrace.ui.detect_package_type", lambda: "flatpak")

    def fake_download(_url, _size, _digest, destination):
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b"verified")
        return destination

    monkeypatch.setattr("tempesttrace.ui.verify_download", fake_download)
    offer = UpdateOffer(
        "1.2.3",
        False,
        "",
        "",
        ReleaseAsset("TempestTrace.flatpak", "https://example.test/pkg", 8, "a" * 64),
    )
    worker = UpdateDownloadWorker(offer)
    downloaded: list[object] = []
    worker.finished.connect(downloaded.append)
    worker.run()

    assert len(downloaded) == 1
    path = downloaded[0]
    assert isinstance(path, Path)
    assert path.is_relative_to(tmp_path / "Downloads")


def test_update_download_removes_temporary_folder_after_failure(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr("tempesttrace.ui.Path.home", lambda: tmp_path)
    monkeypatch.setattr("tempesttrace.ui.detect_package_type", lambda: "flatpak")

    def fail_download(*_args):
        raise OSError("download failed")

    monkeypatch.setattr("tempesttrace.ui.verify_download", fail_download)
    offer = UpdateOffer(
        "1.2.3",
        False,
        "",
        "",
        ReleaseAsset("TempestTrace.flatpak", "https://example.test/pkg", 8, "a" * 64),
    )
    worker = UpdateDownloadWorker(offer)
    failures: list[bool] = []
    worker.failed.connect(lambda: failures.append(True))

    worker.run()

    assert failures == [True]
    assert list((tmp_path / "Downloads").iterdir()) == []


def test_windows_update_handoff_resets_pyinstaller_environment(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr("tempesttrace.ui.discover_obs", lambda: [])
    monkeypatch.setattr("tempesttrace.ui.discover_dropbox", lambda: None)
    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *_args, **_kwargs: QMessageBox.StandardButton.Yes,
    )
    monkeypatch.setattr(QApplication, "quit", lambda: None)
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
    monkeypatch.setattr(
        "tempesttrace.ui.subprocess.Popen",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    package = tmp_path / "setup.exe"
    package.write_bytes(b"installer")
    window = MainWindow(enable_updates=False)

    window._handoff_windows_installer(package)

    assert calls[0][1]["env"]["PYINSTALLER_RESET_ENVIRONMENT"] == "1"
    window.close()
    assert app is not None


def test_windows_update_handoff_is_rejected_while_backup_is_running(
    tmp_path: Path, monkeypatch
) -> None:
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr("tempesttrace.ui.discover_obs", lambda: [])
    monkeypatch.setattr("tempesttrace.ui.discover_dropbox", lambda: None)
    launched: list[object] = []
    warnings: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *_args, **_kwargs: QMessageBox.StandardButton.Yes,
    )
    monkeypatch.setattr(
        "tempesttrace.ui.subprocess.Popen", lambda *args, **kwargs: launched.append(args)
    )
    monkeypatch.setattr(QMessageBox, "warning", lambda *args: warnings.append(args))
    package = tmp_path / "setup.exe"
    package.write_bytes(b"installer")
    window = MainWindow(enable_updates=False)

    class RunningThread:
        def isRunning(self) -> bool:
            return True

    window.worker_thread = cast(QThread, RunningThread())
    window._handoff_windows_installer(package)

    assert not launched
    assert warnings
    window.worker_thread = None
    window.close()
    assert app is not None


def test_appimage_update_handoff_resets_pyinstaller_environment(
    tmp_path: Path, monkeypatch
) -> None:
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr("tempesttrace.ui.discover_obs", lambda: [])
    monkeypatch.setattr("tempesttrace.ui.discover_dropbox", lambda: None)
    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *_args, **_kwargs: QMessageBox.StandardButton.Yes,
    )
    monkeypatch.setattr(QApplication, "quit", lambda: None)
    current = tmp_path / "current.AppImage"
    current.write_bytes(b"current image")
    monkeypatch.setenv("APPIMAGE", str(current))
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
    monkeypatch.setattr(
        "tempesttrace.ui.subprocess.Popen",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    package = tmp_path / "update.AppImage"
    package.write_bytes(b"new image")
    window = MainWindow(enable_updates=False)

    window._handoff_appimage(package)

    assert calls[0][1]["env"]["PYINSTALLER_RESET_ENVIRONMENT"] == "1"
    window.close()
    assert app is not None


def test_appimage_update_handoff_is_rejected_while_backup_is_running(
    tmp_path: Path, monkeypatch
) -> None:
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr("tempesttrace.ui.discover_obs", lambda: [])
    monkeypatch.setattr("tempesttrace.ui.discover_dropbox", lambda: None)
    monkeypatch.setenv("APPIMAGE", str(tmp_path / "current.AppImage"))
    prompts: list[str] = []
    launches: list[object] = []
    monkeypatch.setattr(QMessageBox, "warning", lambda _w, title, *_args: prompts.append(title))
    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *_args, **_kwargs: QMessageBox.StandardButton.Yes,
    )
    monkeypatch.setattr(
        "tempesttrace.ui.subprocess.Popen", lambda *args, **kwargs: launches.append(args)
    )
    package = tmp_path / "update.AppImage"
    package.write_bytes(b"verified update")
    window = MainWindow(enable_updates=False)

    class RunningThread:
        def isRunning(self) -> bool:
            return True

    window.worker_thread = cast(QThread, RunningThread())
    window._handoff_appimage(package)

    assert prompts == ["Backup in progress"]
    assert launches == []
    window.worker_thread = None
    window.close()
    assert app is not None


@pytest.mark.parametrize(
    ("package_type", "suffix", "expected_command"),
    [
        ("flatpak", "flatpak", "flatpak install --user --bundle --or-update"),
        ("snap", "snap", "sudo snap install --dangerous"),
    ],
)
def test_linux_update_handoff_shows_copyable_local_install_command(
    tmp_path: Path, monkeypatch, package_type: str, suffix: str, expected_command: str
) -> None:
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr("tempesttrace.ui.discover_obs", lambda: [])
    monkeypatch.setattr("tempesttrace.ui.discover_dropbox", lambda: None)
    window = MainWindow()
    package = tmp_path / f"TempestTrace update.{suffix}"
    package.write_bytes(b"verified")
    real_message_box = QMessageBox

    class FakeMessageBox:
        ButtonRole = real_message_box.ButtonRole
        StandardButton = real_message_box.StandardButton
        picked: object

        def __init__(self, *_args) -> None:
            self.buttons: list[str] = []

        def setWindowTitle(self, _text: str) -> None:
            pass

        def setText(self, _text: str) -> None:
            pass

        def setInformativeText(self, _text: str) -> None:
            pass

        def addButton(self, text: object, *_args) -> object:
            button = str(text)
            self.buttons.append(button)
            if button == "Copy install command":
                self.picked = button
            return button

        def exec(self) -> None:
            pass

        def clickedButton(self) -> object:
            return self.picked

    monkeypatch.setattr("tempesttrace.ui.QMessageBox", FakeMessageBox)
    window._handoff_verified_update(package, package_type)
    assert app.clipboard().text() == (f"{expected_command} '{package}'")
    window.close()
