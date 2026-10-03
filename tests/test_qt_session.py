"""Regression tests for the shared QApplication session fixture."""

from __future__ import annotations

import gc

from PyQt6.QtWidgets import QApplication


def _create_application_like_a_test_does() -> None:
    """Mimic the old per-test pattern where the application was a local variable."""
    app = QApplication.instance() or QApplication([])
    assert app is not None


def test_application_survives_a_test_style_local_reference(qt_application: QApplication) -> None:
    _create_application_like_a_test_does()
    gc.collect()
    # Before the shared session fixture, the QApplication was destroyed here and the next test
    # created a new one, which crashed intermittently inside Qt.
    assert QApplication.instance() is qt_application


def test_application_instance_is_stable_across_tests(qt_application: QApplication) -> None:
    assert QApplication.instance() is qt_application
