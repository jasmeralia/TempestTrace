from __future__ import annotations

from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QApplication

from tempesttrace import theme, tokens


def test_galefling_palette_is_applied_to_qt_application() -> None:
    app = QApplication.instance() or QApplication([])

    theme.apply_theme(app)

    palette = app.palette()
    assert palette.color(palette.ColorRole.Window) == QColor(tokens.SURFACE)
    assert palette.color(palette.ColorRole.Highlight) == QColor(tokens.ACCENT)
    assert palette.color(palette.ColorRole.HighlightedText) == QColor(tokens.CANVAS)
    assert app.styleSheet() == theme.GLOBAL_QSS
    assert tokens.SURFACE_RAISED in theme.GLOBAL_QSS
    assert tokens.BORDER in theme.GLOBAL_QSS
