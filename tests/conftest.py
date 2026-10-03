"""Shared pytest configuration for the Qt-based tests."""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication


@pytest.fixture(scope="session", autouse=True)
def qt_application() -> Iterator[QApplication]:
    """Keep one QApplication alive for the whole test session.

    Tests historically did ``app = QApplication.instance() or QApplication([])`` with ``app`` a
    local variable. When such a test returned, PyQt destroyed the application, so the next test
    built a brand-new one. Creating and destroying QApplication repeatedly in one process, with
    widgets from earlier tests still being garbage collected, produced intermittent segmentation
    faults (observed in CI inside ``QWidget.insertAction``). Holding a single instance here makes
    ``QApplication.instance()`` return it for every test.
    """
    application = QApplication.instance()
    if not isinstance(application, QApplication):
        application = QApplication([])
    yield application
