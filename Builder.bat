@echo off
REM Builder.bat - compile with Nuitka
REM Replace "icon.ico" with the path to your .ico file.

set PYFILE=fastestvpn_checker.py
set ICON=icon.ico
set JOBS=12

REM Basic onefile standalone build (disable console for GUI app)
nuitka --onefile --standalone --enable-plugin=tk-inter --windows-disable-console --windows-icon-from-ico=%ICON% --jobs=%JOBS% --include-package=customtkinter --include-package=httpx %PYFILE%

echo Build finished.
pause
