# PyInstaller spec for the TokenVault background service.
# Build (on Windows, inside the venv from requirements-windows.txt):
#   pyinstaller windows/tokenvault_service.spec
#
# NOTE: PyInstaller must be run ON Windows to produce a Windows .exe.
# Cross-compiling a Windows exe from Linux/macOS is not supported by
# PyInstaller -- build this step on a Windows machine or CI runner.

# -*- mode: python ; coding: utf-8 -*-
import os

block_cipher = None
project_root = os.path.abspath(os.path.join(os.path.dirname(SPEC), ".."))

a = Analysis(
    [os.path.join(project_root, "windows", "service_wrapper.py")],
    pathex=[project_root],
    binaries=[],
    datas=[
        (os.path.join(project_root, "main.py"), "."),
        (os.path.join(project_root, "vault"), "vault"),
    ],
    hiddenimports=["win32timezone", "uvicorn.logging", "uvicorn.loops.auto"],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="TokenVaultService",
    console=True,  # Windows services launched via pywin32 need a console subsystem
    icon=None,
)
