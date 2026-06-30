@echo off
REM Target: Windows 10, 64-bit. Run this from an ordinary (non-admin) cmd
REM prompt with a 64-bit Python 3.11+ installed (python.org installer,
REM NOT the Microsoft Store version -- the Store version sandboxes file
REM access in ways that break PyInstaller + pywin32 service registration).

setlocal
cd /d "%~dp0\.."

echo === Checking Python architecture ===
python -c "import struct,sys; print(sys.version); exit(0 if struct.calcsize('P')*8==64 else 1)"
if errorlevel 1 (
    echo ERROR: A 64-bit Python interpreter is required for a 64-bit build.
    echo Install 64-bit Python from https://www.python.org/downloads/windows/
    echo ^(choose "Windows installer ^(64-bit^)"^) and make sure it's first on PATH.
    exit /b 1
)

echo === Creating 64-bit virtual environment ===
python -m venv build_venv
call build_venv\Scripts\activate.bat

echo === Installing dependencies ===
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-windows.txt
pip install pyinstaller

echo === Running pywin32 post-install (registers COM/service support) ===
python build_venv\Scripts\pywin32_postinstall.py -install

echo === Building TokenVaultService.exe (64-bit) ===
pyinstaller windows\tokenvault_service.spec --noconfirm --clean

echo === Building TokenVaultReporting.exe (64-bit) ===
pyinstaller windows\tokenvault_reporting.spec --noconfirm --clean

echo === Verifying output architecture ===
where /q dumpbin.exe
if not errorlevel 1 (
    dumpbin /headers dist\TokenVaultService\TokenVaultService.exe | findstr "machine"
    dumpbin /headers dist\TokenVaultReporting\TokenVaultReporting.exe | findstr "machine"
    echo ^(Expect "x64" above -- if you see "x86" your Python was 32-bit despite the check.^)
) else (
    echo dumpbin not found ^(comes with Visual Studio Build Tools^) -- skipping binary architecture check.
)

echo.
echo === Build complete ===
echo Service exe:   dist\TokenVaultService\TokenVaultService.exe
echo Reporting exe: dist\TokenVaultReporting\TokenVaultReporting.exe
echo.
echo === Attempting to compile the installer ===
set ISCC="C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if exist %ISCC% (
    %ISCC% windows\installer.iss
    echo.
    echo Installer built: dist_installer\TokenVaultSetup.exe
) else (
    echo Inno Setup not found at the default path.
    echo Install it from https://jrsoftware.org/isdl.php ^(get the 64-bit-capable
    echo "innosetup-6.x.x.exe" -- Inno Setup itself is a 32-bit tool but produces
    echo installers that correctly install 64-bit apps; that's expected and fine^),
    echo then re-run:
    echo   "C:\Program Files ^(x86^)\Inno Setup 6\ISCC.exe" windows\installer.iss
)

endlocal
