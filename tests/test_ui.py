from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtGui import QDesktopServices
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

    window = MainWindow()
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


def test_incomplete_output_can_be_removed_after_cancel_or_failure(
    tmp_path: Path, monkeypatch
) -> None:
    app = QApplication.instance() or QApplication([])
    obs = tmp_path / "obs"
    obs.mkdir()
    monkeypatch.setattr("tempesttrace.ui.discover_obs", lambda: [obs])
    monkeypatch.setattr("tempesttrace.ui.discover_dropbox", lambda: None)
    window = MainWindow()
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


def test_smoke_test_mode_does_not_open_a_window(monkeypatch) -> None:
    monkeypatch.setattr("sys.argv", ["tempesttrace", "--smoke-test"])
    assert main() == 0


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
