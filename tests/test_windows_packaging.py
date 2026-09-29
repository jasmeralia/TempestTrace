"""Focused checks for Windows packaging inputs and installer recovery behavior."""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SPEC = REPO_ROOT / "build" / "TempestTrace.spec"
INSTALLER = REPO_ROOT / "build" / "installer.nsi"


def test_pyinstaller_spec_collects_icons_and_embeds_build_tag_for_updater() -> None:
    spec = SPEC.read_text(encoding="utf-8")

    assert '(str(root / "resources" / "icons"), "resources/icons")' in spec
    assert "runtime_hooks=[str(runtime_hook)]" in spec
    assert "module.VERSION = {build_tag!r}" in spec
    assert "version=version_resource" in spec
    assert "APP_VERSION" in spec


def test_pyinstaller_windows_version_metadata_uses_release_tag() -> None:
    spec = SPEC.read_text(encoding="utf-8")

    assert 'if sys.platform == "win32":' in spec
    assert 'StringStruct("FileVersion", build_tag)' in spec
    assert 'StringStruct("ProductVersion", build_tag)' in spec
    assert '"Set APP_VERSION to the CI release tag before building Windows"' in spec


def test_installer_backs_up_owned_files_and_restores_them_on_failure() -> None:
    installer = INSTALLER.read_text(encoding="utf-8")

    assert '"$INSTDIR\\.tempesttrace-upgrade-rollback\\${FILENAME}"' in installer
    assert "Function .onInstFailed" in installer
    assert '!insertmacro RestoreOwnedFile "TempestTrace.exe" $R4 EXE' in installer
    assert '!insertmacro RestoreOwnedFile "LICENSE" $R5 LICENSE' in installer
    assert '!insertmacro RestoreOwnedFile "Uninstall.exe" $R6 UNINSTALL' in installer


def test_installer_marks_outputs_for_cleanup_before_writing_them() -> None:
    installer = INSTALLER.read_text(encoding="utf-8")

    assert installer.index('StrCpy $R4 "1"') < installer.index('File "..\\dist\\TempestTrace.exe"')
    assert installer.index('StrCpy $R5 "1"') < installer.index('File "..\\LICENSE"')
    assert installer.index('StrCpy $R6 "1"') < installer.index("WriteUninstaller")


def test_installer_smoke_tests_new_executable_before_committing_upgrade() -> None:
    installer = INSTALLER.read_text(encoding="utf-8")
    smoke_test = installer.index("ExecWait '\"$INSTDIR\\TempestTrace.exe\" --smoke-test' $0")
    rollback_cleanup = installer.index('!insertmacro RemoveRollbackFile "TempestTrace.exe"')

    assert smoke_test < rollback_cleanup
    assert "${If} $0 != 0" in installer[smoke_test:rollback_cleanup]


def test_uninstaller_removes_only_owned_files_and_keeps_nonempty_install_dir() -> None:
    installer = INSTALLER.read_text(encoding="utf-8")
    section_start = installer.index('Section "Uninstall"')
    section_end = installer.index("SectionEnd", section_start)
    uninstall_section = installer[section_start:section_end]

    assert 'Delete "$INSTDIR\\TempestTrace.exe"' in uninstall_section
    assert 'Delete "$INSTDIR\\LICENSE"' in uninstall_section
    assert 'RMDir "$INSTDIR"' in uninstall_section
    assert 'RMDir /r "$INSTDIR"' not in uninstall_section
