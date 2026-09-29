"""Shared dark palette and Qt styles adapted from GaleFling."""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

from PyQt6.QtGui import QColor, QPalette
from PyQt6.QtWidgets import QApplication, QWidget

from tempesttrace import tokens

GLOBAL_QSS = f"""
QWidget {{
    background-color: {tokens.SURFACE};
    color: {tokens.TEXT};
    font-size: {tokens.FONT_BODY[0]}pt;
    font-weight: {tokens.FONT_BODY[1]};
}}

QWidget:disabled {{ color: {tokens.TEXT_MUTED}; }}

QMainWindow {{ background-color: {tokens.SURFACE}; }}

#heading {{
    background: transparent;
    color: {tokens.TEXT};
    font-size: {tokens.FONT_HEADING[0]}pt;
    font-weight: {tokens.FONT_HEADING[1]};
    padding: 8px 0;
}}

QGroupBox {{
    background-color: {tokens.SURFACE};
    border: 1px solid {tokens.BORDER};
    border-radius: 5px;
    margin-top: 10px;
    padding: 12px;
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
}}

QPushButton {{
    background-color: {tokens.SURFACE_RAISED};
    color: {tokens.TEXT};
    border: 1px solid {tokens.BORDER};
    border-radius: 4px;
    padding: 6px 12px;
    font-weight: {tokens.FONT_BODY_STRONG[1]};
}}

QPushButton:hover,
QPushButton:focus {{ border-color: {tokens.ACCENT}; }}

QPushButton:pressed {{
    background-color: {tokens.SURFACE_INSET};
    border-color: {tokens.ACCENT};
}}

QPushButton:disabled {{
    background-color: {tokens.SURFACE};
    color: {tokens.TEXT_MUTED};
    border-color: {tokens.BORDER};
}}

QComboBox,
QProgressBar {{
    background-color: {tokens.SURFACE_INSET};
    color: {tokens.TEXT};
    border: 1px solid {tokens.BORDER};
    border-radius: 4px;
    padding: 5px;
    selection-background-color: {tokens.ACCENT};
    selection-color: {tokens.CANVAS};
}}

QComboBox:focus {{ border-color: {tokens.ACCENT}; }}

QComboBox QAbstractItemView {{
    background-color: {tokens.SURFACE_RAISED};
    color: {tokens.TEXT};
    selection-background-color: {tokens.ACCENT};
    selection-color: {tokens.CANVAS};
    border: 1px solid {tokens.BORDER};
}}

QProgressBar {{ text-align: center; }}
QProgressBar::chunk {{ background-color: {tokens.ACCENT}; border-radius: 3px; }}

QCheckBox {{ color: {tokens.TEXT}; spacing: 6px; }}
QCheckBox:disabled {{ color: {tokens.TEXT_MUTED}; }}
QCheckBox::indicator {{
    width: 14px;
    height: 14px;
    background-color: {tokens.SURFACE_INSET};
    border: 1px solid {tokens.BORDER};
    border-radius: 3px;
}}
QCheckBox::indicator:hover {{ border-color: {tokens.ACCENT}; }}
QCheckBox::indicator:checked {{
    background-color: {tokens.ACCENT};
    border-color: {tokens.ACCENT};
}}

QMenuBar,
QMenu,
QStatusBar {{ background-color: {tokens.SURFACE}; color: {tokens.TEXT}; }}
QMenuBar::item {{ padding: 5px 8px; background: transparent; }}
QMenuBar::item:selected,
QMenu::item:selected {{ background-color: {tokens.SURFACE_RAISED}; color: {tokens.TEXT}; }}
QMenu {{ border: 1px solid {tokens.BORDER}; }}
QMenu::item {{ padding: 5px 24px 5px 8px; }}
QMenu::separator {{ height: 1px; background: {tokens.BORDER}; margin: 4px 6px; }}

QScrollBar:vertical {{ background: {tokens.SURFACE}; width: 8px; margin: 0; }}
QScrollBar:horizontal {{ background: {tokens.SURFACE}; height: 8px; margin: 0; }}
QScrollBar::handle:vertical,
QScrollBar::handle:horizontal {{
    background: {tokens.SURFACE_RAISED};
    border-radius: 4px;
    min-height: 24px;
    min-width: 24px;
}}
QScrollBar::handle:vertical:hover,
QScrollBar::handle:horizontal:hover {{ background: {tokens.BORDER}; }}
QScrollBar::add-line,
QScrollBar::sub-line,
QScrollBar::add-page,
QScrollBar::sub-page {{ background: none; border: none; }}
QToolTip {{
    background-color: {tokens.SURFACE_RAISED};
    color: {tokens.TEXT};
    border: 1px solid {tokens.BORDER};
    padding: 4px;
}}
"""


def _apply_palette(app: QApplication) -> None:
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(tokens.SURFACE))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(tokens.TEXT))
    palette.setColor(QPalette.ColorRole.Base, QColor(tokens.SURFACE_INSET))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(tokens.SURFACE_RAISED))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(tokens.SURFACE_RAISED))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor(tokens.TEXT))
    palette.setColor(QPalette.ColorRole.Text, QColor(tokens.TEXT))
    palette.setColor(QPalette.ColorRole.Button, QColor(tokens.SURFACE_RAISED))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(tokens.TEXT))
    palette.setColor(QPalette.ColorRole.BrightText, QColor(tokens.DANGER))
    palette.setColor(QPalette.ColorRole.Link, QColor(tokens.ACCENT))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(tokens.ACCENT))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(tokens.CANVAS))
    app.setPalette(palette)


def _set_windows_dark_title_bar(window: QWidget) -> None:
    if sys.platform != "win32":
        return
    try:
        value = wintypes.BOOL(1)
        dwmapi = ctypes.WinDLL("dwmapi", use_last_error=True)
        for attribute in (20, 19):
            dwmapi.DwmSetWindowAttribute(
                wintypes.HWND(int(window.winId())),
                wintypes.DWORD(attribute),
                ctypes.byref(value),
                ctypes.sizeof(value),
            )
    except Exception:
        return


def apply_theme(app: QApplication, window: QWidget | None = None) -> None:
    """Apply GaleFling's dark palette and component styling."""
    if app.styleSheet() != GLOBAL_QSS:
        app.setStyle("Fusion")
        _apply_palette(app)
        app.setStyleSheet(GLOBAL_QSS)
    if window is not None:
        _set_windows_dark_title_bar(window)
