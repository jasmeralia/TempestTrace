; Compile from the repository root after PyInstaller creates dist/TempestTrace.exe:
; makensis /DAPP_VERSION=v0.1.0 build/installer.nsi
!include "MUI2.nsh"
!include "LogicLib.nsh"

!ifndef APP_VERSION
  !error "Pass /DAPP_VERSION=<release tag> to makensis"
!endif

Unicode True
Name "TempestTrace ${APP_VERSION}"
OutFile "..\dist\TempestTrace-Setup-${APP_VERSION}.exe"
InstallDir "$LOCALAPPDATA\Programs\TempestTrace"
RequestExecutionLevel user
SetCompressor /SOLID lzma

!define MUI_ICON "..\resources\icons\tempesttrace.ico"
!define MUI_UNICON "..\resources\icons\tempesttrace.ico"

!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "TempestTrace" SecMain
  SectionIn RO
  Call KillRunningTempestTrace
  SetOutPath "$INSTDIR"
  File "..\dist\TempestTrace.exe"
  File "..\LICENSE"
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  CreateDirectory "$SMPROGRAMS\TempestTrace"
  CreateShortCut "$SMPROGRAMS\TempestTrace\TempestTrace.lnk" "$INSTDIR\TempestTrace.exe"
  CreateShortCut "$SMPROGRAMS\TempestTrace\Uninstall.lnk" "$INSTDIR\Uninstall.exe"

  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\TempestTrace" \
    "DisplayName" "TempestTrace"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\TempestTrace" \
    "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\TempestTrace" \
    "Publisher" "Morgan Blackthorne"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\TempestTrace" \
    "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\TempestTrace" \
    "UninstallString" '$\"$INSTDIR\Uninstall.exe$\"'
SectionEnd

Section "Uninstall"
  Call un.KillRunningTempestTrace
  Delete "$INSTDIR\TempestTrace.exe"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\TempestTrace\TempestTrace.lnk"
  Delete "$SMPROGRAMS\TempestTrace\Uninstall.lnk"
  RMDir "$SMPROGRAMS\TempestTrace"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\TempestTrace"
SectionEnd

Function KillRunningTempestTrace
  DetailPrint "Closing any running TempestTrace processes before installing..."
  StrCpy $R0 0
  kill_loop_install:
    ExecWait '"$SYSDIR\taskkill.exe" /IM "TempestTrace.exe" /F /T' $0
    Sleep 500
    nsExec::ExecToStack 'cmd /C tasklist /FI "IMAGENAME eq TempestTrace.exe" /NH | findstr /I "TempestTrace.exe"'
    Pop $1
    ${If} $1 == 0
      IntOp $R0 $R0 + 1
      ${If} $R0 >= 5
        MessageBox MB_ICONSTOP "TempestTrace is still running (taskkill exit code $0). Please close it manually and run the installer again."
        Abort
      ${EndIf}
      Sleep 1000
      Goto kill_loop_install
    ${EndIf}
FunctionEnd

Function un.KillRunningTempestTrace
  DetailPrint "Closing any running TempestTrace processes before uninstalling..."
  StrCpy $R0 0
  kill_loop_uninstall:
    ExecWait '"$SYSDIR\taskkill.exe" /IM "TempestTrace.exe" /F /T' $0
    Sleep 500
    nsExec::ExecToStack 'cmd /C tasklist /FI "IMAGENAME eq TempestTrace.exe" /NH | findstr /I "TempestTrace.exe"'
    Pop $1
    ${If} $1 == 0
      IntOp $R0 $R0 + 1
      ${If} $R0 >= 5
        MessageBox MB_ICONSTOP "TempestTrace is still running (taskkill exit code $0). Please close it manually and run the uninstaller again."
        Abort
      ${EndIf}
      Sleep 1000
      Goto kill_loop_uninstall
    ${EndIf}
FunctionEnd
