"""PyQt desktop flow for selecting OBS data and creating a diagnostic ZIP."""

from __future__ import annotations

import os
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import cast

from PyQt6.QtCore import QObject, QSettings, Qt, QThread, QTimer, QUrl, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QAction, QCloseEvent, QDesktopServices, QIcon
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

from tempesttrace.backup import BackupCancelled, BackupResult, create_backup
from tempesttrace.paths import discover_dropbox, discover_obs
from tempesttrace.theme import apply_theme
from tempesttrace.updater import (
    UpdateOffer,
    check_for_update,
    detect_package_type,
    fetch_release_feed,
    installed_version,
    verify_download,
    write_appimage_update_helper,
)

VERSION = installed_version() or os.environ.get("TEMPESTTRACE_VERSION", "0.0.0")


class UpdateCheckWorker(QObject):
    found = pyqtSignal(object)
    failed = pyqtSignal()

    def __init__(self, include_beta: bool | None) -> None:
        super().__init__()
        self.include_beta = include_beta

    @pyqtSlot()
    def run(self) -> None:
        current = installed_version()
        package = detect_package_type()
        if current is None or package is None:
            self.found.emit(None)
            return
        try:
            releases = fetch_release_feed()
            include_beta = bool(self.include_beta)
            offer = check_for_update(
                current,
                releases,
                platform.system(),
                platform.machine(),
                package,
                include_beta,
            )
        except Exception:
            self.failed.emit()
        else:
            self.found.emit((offer, include_beta))


class UpdateDownloadWorker(QObject):
    finished = pyqtSignal(object)
    failed = pyqtSignal()

    def __init__(self, offer: UpdateOffer) -> None:
        super().__init__()
        self.offer = offer

    @pyqtSlot()
    def run(self) -> None:
        folder: Path | None = None
        try:
            package = detect_package_type()
            if package == "appimage":
                current = Path(os.environ["APPIMAGE"]).absolute()
                folder = Path(tempfile.mkdtemp(prefix=".TempestTrace-update-", dir=current.parent))
            elif package in {"deb", "rpm", "flatpak", "snap"}:
                if package == "flatpak":
                    cache_home = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
                    downloads = cache_home / "TempestTrace" / "updates"
                else:
                    downloads = Path.home() / "Downloads"
                downloads.mkdir(parents=True, exist_ok=True)
                folder = Path(tempfile.mkdtemp(prefix="TempestTrace-update-", dir=downloads))
            else:
                folder = Path(tempfile.mkdtemp(prefix="TempestTrace-update-"))
            path = verify_download(
                self.offer.asset.url,
                self.offer.asset.size,
                self.offer.asset.sha256,
                folder / self.offer.asset.name,
            )
            if package == "appimage":
                path.chmod(path.stat().st_mode | 0o111)
        except Exception:
            if folder is not None:
                shutil.rmtree(folder, ignore_errors=True)
            self.failed.emit()
        else:
            self.finished.emit(path)


class BackupWorker(QObject):
    progress = pyqtSignal(str, int, int)
    finished = pyqtSignal(object)
    failed = pyqtSignal(str, str)
    cancelled = pyqtSignal()

    def __init__(self, source: Path, destination: Path, event: threading.Event) -> None:
        super().__init__()
        self.source = source
        self.destination = destination
        self.cancel_token = event

    @pyqtSlot()
    def run(self) -> None:
        try:
            result = create_backup(
                self.source,
                self.destination,
                progress=self.progress.emit,
                cancelled=self.cancel_token.is_set,
            )
        except BackupCancelled:
            self.cancelled.emit()
        except Exception as exc:
            # Do not display exception text: file contents may appear in parser errors.
            if isinstance(exc, PermissionError):
                message = "The backup folder is not writable. Choose another folder."
            elif isinstance(exc, FileNotFoundError):
                message = "The selected OBS or backup folder is no longer available."
            elif isinstance(exc, ValueError):
                message = str(exc)
            else:
                message = "Backup could not be completed."
            self.failed.emit(message, type(exc).__name__)
        else:
            self.finished.emit(result)


class MainWindow(QMainWindow):
    def __init__(self, *, enable_updates: bool = True) -> None:  # noqa: PLR0915
        super().__init__()
        application = QApplication.instance()
        if application is not None:
            apply_theme(cast(QApplication, application), self)
        self.updates_enabled = enable_updates
        self.setWindowTitle("TempestTrace")
        self.setMinimumWidth(610)
        self.setWindowIcon(self._brand_icon())
        self.worker_thread: QThread | None = None
        self.worker: BackupWorker | None = None
        self.cancel_event: threading.Event | None = None
        self.last_result: BackupResult | None = None
        self.incomplete_dir: Path | None = None
        self._output_before: set[Path] = set()
        self._incomplete_outputs: list[Path] = []
        self.settings = QSettings("WindsOfStorm", "TempestTrace")
        self.update_thread: QThread | None = None
        self.update_worker: UpdateCheckWorker | UpdateDownloadWorker | None = None
        self._manual_update_check = False
        self._automatic_update_pending = False
        self._pending_offer: UpdateOffer | None = None
        self._close_requested = False
        self._allow_close = False
        menu_bar = self.menuBar()
        help_menu = menu_bar.addMenu("Help") if menu_bar is not None else None
        settings_menu = menu_bar.addMenu("Settings") if menu_bar is not None else None
        about_action = QAction("About TempestTrace", self)
        about_action.triggered.connect(self._about)
        if help_menu is not None:
            help_menu.addAction(about_action)
            help_menu.addSeparator()
            update_action = QAction("Check for Updates…", self)
            update_action.setEnabled(enable_updates)
            update_action.triggered.connect(lambda: self._check_for_updates(manual=True))
            help_menu.addAction(update_action)
        self.auto_update_action = QAction("Check for updates automatically", self)
        self.auto_update_action.setCheckable(True)
        self.auto_update_action.setEnabled(enable_updates)
        self.auto_update_action.setChecked(
            self.settings.value("updates/automatic", True, type=bool)
        )
        self.auto_update_action.toggled.connect(self._save_auto_update_preference)
        self.include_beta_action = QAction("Include beta updates", self)
        self.include_beta_action.setCheckable(True)
        self.include_beta_action.setEnabled(enable_updates)
        self.include_beta_action.setChecked(
            self.settings.value("updates/include_beta", False, type=bool)
        )
        self.include_beta_action.toggled.connect(self._save_beta_preference)
        if settings_menu is not None:
            settings_menu.addAction(self.auto_update_action)
            settings_menu.addAction(self.include_beta_action)

        root = QWidget()
        layout = QVBoxLayout(root)
        heading = QLabel("Create an OBS diagnostic backup")
        heading.setObjectName("heading")
        layout.addWidget(heading)
        intro = QLabel(
            "TempestTrace copies OBS profiles, scene collections, global settings, "
            "and recent logs. "
            "It redacts recognized credentials from the copy. OBS can remain open; "
            "its files are never changed."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        selection = QGroupBox("Backup locations")
        grid = QGridLayout(selection)
        grid.addWidget(QLabel("OBS configuration:"), 0, 0)
        self.obs_combo = QComboBox()
        self.obs_combo.setMinimumContentsLength(48)
        grid.addWidget(self.obs_combo, 0, 1)
        choose_obs = QPushButton("Choose…")
        choose_obs.clicked.connect(self._choose_obs)
        grid.addWidget(choose_obs, 0, 2)
        grid.addWidget(QLabel("Dropbox destination:"), 1, 0)
        self.destination_label = QLabel("Dropbox location not found")
        self.destination_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.destination_label.setWordWrap(True)
        grid.addWidget(self.destination_label, 1, 1)
        choose_destination = QPushButton("Choose…")
        choose_destination.clicked.connect(self._choose_destination)
        grid.addWidget(choose_destination, 1, 2)
        layout.addWidget(selection)

        self.detail = QLabel("Review the source and destination, then create the backup.")
        self.detail.setWordWrap(True)
        layout.addWidget(self.detail)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        buttons = QGridLayout()
        self.run_button = QPushButton("Create Backup")
        self.run_button.setDefault(True)
        self.run_button.clicked.connect(self._start_backup)
        buttons.addWidget(self.run_button, 0, 0)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setVisible(False)
        self.cancel_button.clicked.connect(self._cancel_backup)
        buttons.addWidget(self.cancel_button, 0, 1)
        self.open_dir_button = QPushButton("Open containing folder")
        self.open_dir_button.setVisible(False)
        self.open_dir_button.clicked.connect(self._open_folder)
        buttons.addWidget(self.open_dir_button, 1, 0)
        self.open_zip_button = QPushButton("Open ZIP")
        self.open_zip_button.setVisible(False)
        self.open_zip_button.clicked.connect(self._open_zip)
        buttons.addWidget(self.open_zip_button, 1, 1)
        self.copy_button = QPushButton("Copy ZIP path")
        self.copy_button.setVisible(False)
        self.copy_button.clicked.connect(self._copy_path)
        buttons.addWidget(self.copy_button, 1, 2)
        self.cleanup_button = QPushButton("Remove incomplete output…")
        self.cleanup_button.setVisible(False)
        self.cleanup_button.clicked.connect(self._remove_incomplete)
        buttons.addWidget(self.cleanup_button, 2, 0, 1, 3)
        layout.addLayout(buttons)

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.setCentralWidget(root)
        self._load_paths()
        if enable_updates and self.auto_update_action.isChecked():
            QTimer.singleShot(1500, self._automatic_update_check)

    @staticmethod
    def _brand_icon() -> QIcon:
        base = Path(__file__).resolve().parents[2] / "resources/icons"
        if getattr(sys, "frozen", False):
            base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent)) / "resources/icons"
        return QIcon(
            str(base / ("tempesttrace.ico" if sys.platform == "win32" else "tempesttrace.png"))
        )

    def _load_paths(self) -> None:
        for path in discover_obs():
            self.obs_combo.addItem(str(path), path)
        self.dropbox_root = discover_dropbox()
        self.destination: Path | None = None
        if self.dropbox_root:
            proposed = self.dropbox_root / "Jasmeralia and Rin/obs logs"
            self.destination_label.setText(str(proposed))
            self.destination = proposed

    def _choose_obs(self) -> None:
        folder = QFileDialog.getExistingDirectory(self, "Choose OBS configuration folder")
        if folder:
            path = Path(folder)
            index = self.obs_combo.findData(path)
            if index < 0:
                self.obs_combo.addItem(str(path), path)
                index = self.obs_combo.count() - 1
            self.obs_combo.setCurrentIndex(index)

    def _choose_destination(self) -> None:
        start = str(self.destination or self.dropbox_root or Path.home())
        folder = QFileDialog.getExistingDirectory(self, "Choose backup destination", start)
        if folder:
            self.destination = Path(folder)
            self.destination_label.setText(str(self.destination))

    def _start_backup(self) -> None:
        if self.update_thread is not None:
            QMessageBox.warning(
                self,
                "Update in progress",
                "Wait for the current update check or download to finish before creating a backup.",
            )
            return
        source = self.obs_combo.currentData()
        if not isinstance(source, Path) or not source.is_dir():
            QMessageBox.warning(
                self, "Choose OBS", "Choose an existing OBS configuration folder first."
            )
            return
        if self.destination is None:
            QMessageBox.warning(
                self,
                "Choose destination",
                "Choose the Dropbox backup folder before continuing.",
            )
            return
        try:
            self.destination.mkdir(parents=True, exist_ok=True)
        except OSError:
            QMessageBox.warning(
                self,
                "Destination unavailable",
                "That backup folder could not be created. Choose another folder.",
            )
            return
        self.last_result = None
        self._output_before = set(self.destination.iterdir())
        self._incomplete_outputs = []
        self.cleanup_button.setVisible(False)
        self.open_dir_button.setVisible(False)
        self.open_zip_button.setVisible(False)
        self.copy_button.setVisible(False)
        self.run_button.setEnabled(False)
        self.cancel_button.setVisible(True)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self.detail.setText("Scanning the selected OBS configuration…")
        self.cancel_event = threading.Event()
        self.worker_thread = QThread(self)
        worker = BackupWorker(source, self.destination, self.cancel_event)
        self.worker = worker
        worker.moveToThread(self.worker_thread)
        self.worker_thread.started.connect(worker.run)
        worker.progress.connect(self._on_progress)
        worker.finished.connect(self._on_finished)
        worker.failed.connect(self._on_failed)
        worker.cancelled.connect(self._on_cancelled)
        worker.finished.connect(self.worker_thread.quit)
        worker.failed.connect(self.worker_thread.quit)
        worker.cancelled.connect(self.worker_thread.quit)
        self.worker_thread.finished.connect(worker.deleteLater)
        self.worker_thread.finished.connect(self._worker_stopped)
        self.worker_thread.start()

    @pyqtSlot(str, int, int)
    def _on_progress(self, phase: str, current: int, total: int) -> None:
        labels = {
            "scanning": "Scanning OBS files",
            "copying": "Copying files",
            "redacting": "Redacting credentials in copies",
            "verifying": "Verifying sanitized files",
            "packaging": "Packaging ZIP",
            "finishing": "Finishing",
        }
        self.detail.setText(f"{labels.get(phase, phase.title())}…")
        if total:
            self.progress.setRange(0, total)
            self.progress.setValue(current)

    @pyqtSlot(object)
    def _on_finished(self, result: object) -> None:
        if not isinstance(result, BackupResult):
            self._on_failed("Backup could not be completed.", "UnexpectedResult")
            return
        self.last_result = result
        message = (
            f"Completed: {result.archive}\nFiles copied: {result.copied_count}  |  "
            f"Files skipped: {result.skipped_count}\nRedactions: "
            + (
                ", ".join(
                    f"{name}: {count}" for name, count in sorted(result.redaction_counts.items())
                )
                or "none"
            )
        )
        if result.warnings:
            message += "\nWarnings:\n" + "\n".join(f"• {warning}" for warning in result.warnings)
        self.detail.setText(message)
        self.open_dir_button.setVisible(True)
        self.open_zip_button.setVisible(True)
        self.copy_button.setVisible(True)
        self.status_bar.showMessage("Backup complete", 5000)

    @pyqtSlot(str, str)
    def _on_failed(self, message: str, error_type: str) -> None:
        self.detail.setText(
            f"{message} Any incomplete output is marked as incomplete "
            "and was not reported as successful."
        )
        self.status_bar.showMessage(f"Backup stopped ({error_type})", 7000)

    @pyqtSlot()
    def _on_cancelled(self) -> None:
        self.detail.setText(
            "Backup cancelled. Any remaining output is marked incomplete "
            "and is not a usable backup."
        )
        self.status_bar.showMessage("Backup cancelled", 5000)

    @pyqtSlot()
    def _worker_stopped(self) -> None:
        if self.destination is not None:
            try:
                self._incomplete_outputs = [
                    item
                    for item in self.destination.iterdir()
                    if item not in self._output_before
                    and item.name.startswith((".TempestTrace-", "TempestTrace-"))
                    and ("incomplete" in item.name)
                ]
            except OSError:
                self._incomplete_outputs = []
            self.cleanup_button.setVisible(bool(self._incomplete_outputs))
        self.run_button.setEnabled(True)
        self.cancel_button.setEnabled(True)
        self.cancel_button.setVisible(False)
        self.progress.setVisible(False)
        self.worker_thread = None
        self.worker = None
        if self._automatic_update_pending:
            self._automatic_update_pending = False
            if not self._close_requested and self.auto_update_action.isChecked():
                self._check_for_updates(manual=False)
        self._finish_deferred_close()

    def closeEvent(self, event: QCloseEvent | None) -> None:
        if event is None:
            return
        if self._allow_close or not self._has_running_workers():
            event.accept()
            return
        self._close_requested = True
        event.ignore()
        if self.worker_thread is not None and self.worker_thread.isRunning():
            if self.cancel_event is not None:
                self.cancel_event.set()
            self.status_bar.showMessage("Cancelling backup before closing…")
        else:
            self.status_bar.showMessage("Finishing update activity before closing…")

    def _has_running_workers(self) -> bool:
        return any(
            thread is not None and thread.isRunning()
            for thread in (self.worker_thread, self.update_thread)
        )

    def _finish_deferred_close(self) -> None:
        if self._close_requested and not self._has_running_workers():
            self._allow_close = True
            self.close()

    def _remove_incomplete(self) -> None:
        if not self._incomplete_outputs:
            return
        question = "Remove these incomplete TempestTrace items?\n\n" + "\n".join(
            path.name for path in self._incomplete_outputs
        )
        answer = QMessageBox.question(
            self,
            "Remove incomplete output",
            question,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        for path in self._incomplete_outputs:
            if path.parent == self.destination and path.name.startswith(
                (".TempestTrace-", "TempestTrace-")
            ):
                try:
                    if path.is_dir() and not path.is_symlink():
                        shutil.rmtree(path)
                    else:
                        path.unlink(missing_ok=True)
                except FileNotFoundError:
                    pass
        self._incomplete_outputs = []
        self.cleanup_button.setVisible(False)
        self.status_bar.showMessage("Incomplete output removed", 5000)

    def _cancel_backup(self) -> None:
        if self.cancel_event is not None:
            self.cancel_event.set()
            self.cancel_button.setEnabled(False)
            self.detail.setText("Cancelling after the current file…")

    def _open_folder(self) -> None:
        if self.last_result:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.last_result.archive.parent)))

    def _open_zip(self) -> None:
        if self.last_result:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.last_result.archive)))

    def _copy_path(self) -> None:
        if self.last_result:
            clipboard = QApplication.clipboard()
            if clipboard is not None:
                clipboard.setText(str(self.last_result.archive))
            self.status_bar.showMessage("ZIP path copied", 3000)

    def _about(self) -> None:
        QMessageBox.about(
            self,
            "About TempestTrace",
            f"<b>TempestTrace {VERSION}</b><br><br>Safe OBS diagnostic backup utility.<br>"
            "OBS remains open and its configuration is read only.",
        )

    def _save_auto_update_preference(self, checked: bool) -> None:
        self.settings.setValue("updates/automatic", checked)

    def _save_beta_preference(self, checked: bool) -> None:
        self.settings.setValue("updates/include_beta", checked)

    def _automatic_update_check(self) -> None:
        if self.auto_update_action.isChecked():
            if self.worker_thread is not None and self.worker_thread.isRunning():
                self._automatic_update_pending = True
                return
            self._check_for_updates(manual=False)

    def _check_for_updates(self, *, manual: bool) -> None:
        if not self.updates_enabled:
            return
        if self.worker_thread is not None and self.worker_thread.isRunning():
            if manual:
                QMessageBox.information(
                    self,
                    "Backup in progress",
                    "Wait for the current backup to finish before checking for updates.",
                )
            else:
                self._automatic_update_pending = True
            return
        if self.update_thread is not None:
            if manual:
                self.status_bar.showMessage("An update check is already running", 3000)
            return
        self._manual_update_check = manual
        self.status_bar.showMessage("Checking GitHub Releases…")
        self.update_thread = QThread(self)
        beta_preference = (
            self.include_beta_action.isChecked()
            if self.settings.contains("updates/include_beta")
            else None
        )
        worker = UpdateCheckWorker(beta_preference)
        self.update_worker = worker
        worker.moveToThread(self.update_thread)
        self.update_thread.started.connect(worker.run)
        worker.found.connect(self._on_update_found)
        worker.failed.connect(self._on_update_failed)
        worker.found.connect(self.update_thread.quit)
        worker.failed.connect(self.update_thread.quit)
        self.update_thread.finished.connect(worker.deleteLater)
        self.update_thread.finished.connect(self._update_thread_stopped)
        self.update_thread.start()

    @pyqtSlot(object)
    def _on_update_found(self, result: object) -> None:
        self.status_bar.clearMessage()
        if self._close_requested:
            return
        beta_preference: bool | None = None
        if isinstance(result, tuple) and len(result) == 2:
            result, beta_preference = result
            if isinstance(beta_preference, bool) and not self.settings.contains(
                "updates/include_beta"
            ):
                self.include_beta_action.blockSignals(True)
                self.include_beta_action.setChecked(beta_preference)
                self.include_beta_action.blockSignals(False)
        if not isinstance(result, UpdateOffer):
            if self._manual_update_check:
                if installed_version() is None:
                    QMessageBox.information(
                        self,
                        "Updates unavailable",
                        "This source build does not have an installed release version.",
                    )
                else:
                    QMessageBox.information(self, "No updates found", "TempestTrace is up to date.")
            return
        self._pending_offer = result
        beta_label = "Beta" if result.is_beta else "Stable"
        size_mb = result.asset.size / (1024 * 1024)
        notes = result.notes.strip() or "No release notes were provided."
        box = QMessageBox(self)
        box.setWindowTitle("TempestTrace update available")
        box.setText(
            f"Version {result.version} ({beta_label}) is available.\n"
            f"Current version: {VERSION}\n"
            f"Package: {result.asset.name} ({size_mb:.1f} MiB)"
        )
        box.setInformativeText(f"Release notes:\n{notes}")
        download_button = box.addButton("Download and Update", QMessageBox.ButtonRole.AcceptRole)
        release_button = box.addButton("View Release", QMessageBox.ButtonRole.ActionRole)
        box.addButton(QMessageBox.StandardButton.Cancel)
        box.exec()
        if box.clickedButton() == download_button:
            self._download_update(result)
        elif box.clickedButton() == release_button and result.release_url:
            QDesktopServices.openUrl(QUrl(result.release_url))

    @pyqtSlot()
    def _on_update_failed(self) -> None:
        self.status_bar.clearMessage()
        if self._manual_update_check and not self._close_requested:
            QMessageBox.information(
                self,
                "Update check unavailable",
                "GitHub Releases could not be reached. You can still create an OBS backup.",
            )

    @pyqtSlot()
    def _update_thread_stopped(self) -> None:
        self.update_thread = None
        self.update_worker = None
        self._finish_deferred_close()

    def _download_update(self, offer: UpdateOffer) -> None:
        if self.update_thread is not None:
            QMessageBox.information(self, "Update", "Wait for the current update check to finish.")
            return
        self.status_bar.showMessage("Downloading and verifying update…")
        self.update_thread = QThread(self)
        worker = UpdateDownloadWorker(offer)
        self.update_worker = worker
        worker.moveToThread(self.update_thread)
        self.update_thread.started.connect(worker.run)
        worker.finished.connect(self._on_update_downloaded)
        worker.failed.connect(self._on_update_download_failed)
        worker.finished.connect(self.update_thread.quit)
        worker.failed.connect(self.update_thread.quit)
        self.update_thread.finished.connect(worker.deleteLater)
        self.update_thread.finished.connect(self._update_thread_stopped)
        self.update_thread.start()

    @pyqtSlot()
    def _on_update_download_failed(self) -> None:
        self.status_bar.clearMessage()
        if self._close_requested:
            return
        QMessageBox.warning(
            self,
            "Update download failed",
            "The update could not be downloaded or verified. Check your network and available "
            "disk space, then try again. The current version is unchanged.",
        )

    @pyqtSlot(object)
    def _on_update_downloaded(self, result: object) -> None:
        self.status_bar.clearMessage()
        if self._close_requested:
            return
        if not isinstance(result, Path) or self._pending_offer is None:
            QMessageBox.warning(self, "Update", "The verified package could not be located.")
            return
        package = detect_package_type()
        self._handoff_verified_update(result, package)

    def _handoff_verified_update(self, package_path: Path, package_type: str | None) -> None:
        package = package_type or ""
        if package == "nsis":
            self._handoff_windows_installer(package_path)
            return
        if package in {"deb", "rpm"}:
            self._handoff_system_package(package_path)
            return
        if package == "appimage":
            self._handoff_appimage(package_path)
            return
        self._show_linux_package_action(package_path, package)

    def _handoff_windows_installer(self, package_path: Path) -> None:
        if self.worker_thread is not None and self.worker_thread.isRunning():
            QMessageBox.warning(
                self,
                "Backup in progress",
                "Wait for the current backup to finish before running the installer. "
                "The installer was not started.",
            )
            return
        answer = QMessageBox.question(
            self,
            "Run verified installer?",
            "The verified installer will close TempestTrace while it updates. OBS remains open.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(package_path.parent)))
            return
        flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
        try:
            environment = os.environ.copy()
            environment["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
            subprocess.Popen(
                [str(package_path)],
                close_fds=True,
                creationflags=flags,
                env=environment,
            )
        except OSError:
            QMessageBox.warning(
                self,
                "Installer could not start",
                "The verified installer remains in the update folder.",
            )
            return
        QApplication.quit()

    def _handoff_system_package(self, package_path: Path) -> None:
        answer = QMessageBox.question(
            self,
            "Open verified package?",
            "Open this verified local package with your desktop package installer?\n"
            f"{package_path}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer == QMessageBox.StandardButton.Yes:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(package_path)))

    def _handoff_appimage(self, package_path: Path) -> None:
        if self.worker_thread is not None and self.worker_thread.isRunning():
            QMessageBox.warning(
                self,
                "Backup in progress",
                "Wait for the current backup to finish before replacing the AppImage. "
                "The update was not started.",
            )
            return
        current = os.environ.get("APPIMAGE")
        if not current:
            QMessageBox.warning(
                self,
                "AppImage path unavailable",
                "The verified AppImage is ready in its update folder, but the running "
                "AppImage path could not be determined.",
            )
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(package_path.parent)))
            return
        answer = QMessageBox.question(
            self,
            "Replace and restart TempestTrace?",
            "TempestTrace will close, replace its AppImage, and restart. The previous "
            "AppImage is kept until the new version starts successfully; if it fails to "
            "start, the previous version is restored.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(package_path.parent)))
            return
        helper = package_path.parent / "apply-update.sh"
        try:
            write_appimage_update_helper(current, package_path, helper, process_id=os.getpid())
            subprocess.Popen(
                ["/bin/sh", str(helper)],
                cwd=str(package_path.parent),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True,
                env={**os.environ, "PYINSTALLER_RESET_ENVIRONMENT": "1"},
            )
        except OSError, ValueError:
            QMessageBox.warning(
                self,
                "AppImage update could not start",
                "The verified package remains in its update folder, and the current "
                "version is unchanged.",
            )
            return
        QApplication.quit()

    def _show_linux_package_action(self, package_path: Path, package: str) -> None:
        if package == "flatpak":
            command = (
                f"flatpak install --user --bundle --or-update {shlex.quote(str(package_path))}"
            )
            detail = (
                "Install this local bundle to update TempestTrace. This GitHub sideload does not "
                "configure a Flatpak remote or receive updates from flatpak update."
            )
        elif package == "snap":
            command = f"sudo snap install --dangerous {shlex.quote(str(package_path))}"
            detail = (
                "Install this local Snap explicitly; if TempestTrace is already installed, "
                "Snap treats the same-name local install as a refresh. --dangerous trusts this "
                "downloaded file; "
                "Snap Store refreshes do not discover GitHub assets. Strict confinement may "
                "require `sudo snap connect tempesttrace:obs-config` once for OBS config access."
            )
        else:
            command = str(package_path)
            detail = "The verified package is ready for a user-approved local install."
        box = QMessageBox(self)
        box.setWindowTitle("Verified update ready")
        box.setText(detail)
        box.setInformativeText(f"Package: {package_path}\n\nCommand: {command}")
        copy_button = box.addButton("Copy install command", QMessageBox.ButtonRole.ActionRole)
        folder_button = box.addButton("Open package folder", QMessageBox.ButtonRole.ActionRole)
        box.addButton(QMessageBox.StandardButton.Close)
        box.exec()
        if box.clickedButton() == copy_button:
            clipboard = QApplication.clipboard()
            if clipboard is not None:
                clipboard.setText(command)
        elif box.clickedButton() == folder_button:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(package_path.parent)))


def main() -> int:
    """Start the TempestTrace desktop application."""
    if "--smoke-test" in sys.argv:
        app = cast(QApplication, QApplication.instance() or QApplication([]))
        app.setApplicationName("TempestTrace")
        app.setApplicationVersion(VERSION)
        app.setWindowIcon(MainWindow._brand_icon())
        window = MainWindow(enable_updates=False)
        window.show()
        app.processEvents()
        window.close()
        app.processEvents()
        return 0
    app = QApplication(sys.argv)
    app.setApplicationName("TempestTrace")
    app.setApplicationVersion(VERSION)
    app.setWindowIcon(MainWindow._brand_icon())
    window = MainWindow()
    window.show()
    return app.exec()
