"""Tests for the NSIS installer's icon and upgrade-shutdown behavior."""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALLER_SCRIPT = REPO_ROOT / "build" / "installer.nsi"


def test_icon_assets_exist_as_valid_ico_and_png() -> None:
    icon_ico = REPO_ROOT / "resources" / "icons" / "tempesttrace.ico"
    icon_png = REPO_ROOT / "resources" / "icons" / "tempesttrace.png"

    assert icon_ico.read_bytes()[:4] == b"\x00\x00\x01\x00"
    assert icon_png.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"


def test_nsis_script_references_the_icon_asset() -> None:
    script = INSTALLER_SCRIPT.read_text(encoding="utf-8")

    assert '!define MUI_ICON "..\\resources\\icons\\tempesttrace.ico"' in script
    assert '!define MUI_UNICON "..\\resources\\icons\\tempesttrace.ico"' in script


def test_nsis_installer_kills_running_tempesttrace_before_file_operations() -> None:
    script = INSTALLER_SCRIPT.read_text(encoding="utf-8")

    kill_call = script.index("Call KillRunningTempestTrace")
    file_copy = script.index('File "..\\dist\\TempestTrace.exe"')
    function_start = script.index("Function KillRunningTempestTrace")
    function_end = script.index("FunctionEnd", function_start)
    function_body = script[function_start:function_end]

    assert kill_call < file_copy
    assert 'ExecWait \'"$SYSDIR\\taskkill.exe" /IM "TempestTrace.exe" /F /T\' $0' in function_body


def test_nsis_installer_verifies_shutdown_and_aborts_if_still_running() -> None:
    script = INSTALLER_SCRIPT.read_text(encoding="utf-8")
    function_start = script.index("Function KillRunningTempestTrace")
    function_end = script.index("FunctionEnd", function_start)
    function_body = script[function_start:function_end]

    assert 'tasklist /FI "IMAGENAME eq TempestTrace.exe"' in function_body
    assert "findstr" in function_body
    assert "Abort" in function_body
    assert "IntOp $R0 $R0 + 1" in function_body


def test_nsis_uninstaller_kills_running_tempesttrace_before_removing_files() -> None:
    script = INSTALLER_SCRIPT.read_text(encoding="utf-8")

    kill_call = script.index("Call un.KillRunningTempestTrace")
    delete_exe = script.index('Delete "$INSTDIR\\TempestTrace.exe"')
    function_start = script.index("Function un.KillRunningTempestTrace")
    function_end = script.index("FunctionEnd", function_start)
    function_body = script[function_start:function_end]

    assert kill_call < delete_exe
    assert 'ExecWait \'"$SYSDIR\\taskkill.exe" /IM "TempestTrace.exe" /F /T\' $0' in function_body


def test_nsis_uninstaller_verifies_shutdown_and_aborts_if_still_running() -> None:
    script = INSTALLER_SCRIPT.read_text(encoding="utf-8")
    function_start = script.index("Function un.KillRunningTempestTrace")
    function_end = script.index("FunctionEnd", function_start)
    function_body = script[function_start:function_end]

    assert 'tasklist /FI "IMAGENAME eq TempestTrace.exe"' in function_body
    assert "findstr" in function_body
    assert "Abort" in function_body
    assert "IntOp $R0 $R0 + 1" in function_body
