# PyInstaller one-file desktop build used by the release jobs.
import os
import re
import sys
from pathlib import Path

root = Path(SPECPATH).parent
build_tag = os.environ.get("APP_VERSION", "").strip()

# The updater imports this module in both source and frozen builds. A runtime
# hook supplies the CI tag before the application imports its update code.
if not build_tag:
    if sys.platform == "win32":
        raise RuntimeError(
            "Set APP_VERSION to the CI release tag before building Windows"
        )
    build_tag = "0.0.0"

runtime_hook = root / "build" / "tmp" / "tempesttrace_build_info.py"
runtime_hook.parent.mkdir(parents=True, exist_ok=True)
runtime_hook.write_text(
    "import sys, types\n"
    "module = types.ModuleType('tempesttrace._build_info')\n"
    f"module.VERSION = {build_tag!r}\n"
    "sys.modules['tempesttrace._build_info'] = module\n",
    encoding="utf-8",
)

version_resource = None
if sys.platform == "win32":
    version_match = re.fullmatch(
        r"v?(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?(?:[-+].*)?", build_tag
    )
    if version_match is None:
        raise RuntimeError(f"APP_VERSION is not a supported version tag: {build_tag!r}")
    file_version = tuple(int(part or 0) for part in version_match.groups())
    from PyInstaller.utils.win32.versioninfo import (
        FixedFileInfo,
        StringFileInfo,
        StringStruct,
        StringTable,
        VSVersionInfo,
        VarFileInfo,
        VarStruct,
    )

    version_resource = VSVersionInfo(
        ffi=FixedFileInfo(
            filevers=file_version,
            prodvers=file_version,
            mask=0x3F,
            flags=0,
            OS=0x40004,
            fileType=0x1,
            subtype=0,
            date=(0, 0),
        ),
        kids=[
            StringFileInfo(
                [
                    StringTable(
                        "040904B0",
                        [
                            StringStruct("CompanyName", "TempestTrace"),
                            StringStruct("FileDescription", "TempestTrace"),
                            StringStruct("FileVersion", build_tag),
                            StringStruct("InternalName", "TempestTrace"),
                            StringStruct("OriginalFilename", "TempestTrace.exe"),
                            StringStruct("ProductName", "TempestTrace"),
                            StringStruct("ProductVersion", build_tag),
                        ],
                    )
                ]
            ),
            VarFileInfo([VarStruct("Translation", [1033, 1200])]),
        ],
    )

a = Analysis(
    [str(root / "src" / "tempesttrace" / "__main__.py")],
    pathex=[str(root / "src")],
    binaries=[],
    datas=[(str(root / "resources" / "icons"), "resources/icons")],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[str(runtime_hook)],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="TempestTrace",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    icon=str(root / "resources" / "icons" / "tempesttrace.ico"),
    version=version_resource,
)
