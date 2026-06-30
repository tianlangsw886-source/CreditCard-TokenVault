# PyInstaller spec for the TokenVault Reporting desktop app.
# Build (on Windows):
#   pyinstaller windows/tokenvault_reporting.spec
#
# NOTE: Build on Windows -- PyInstaller does not cross-compile.

# -*- mode: python ; coding: utf-8 -*-
import os

block_cipher = None
project_root = os.path.abspath(os.path.join(os.path.dirname(SPEC), ".."))

a = Analysis(
    [os.path.join(project_root, "reporting_app.py")],
    pathex=[project_root],
    binaries=[],
    datas=[
        (os.path.join(project_root, "vault"), "vault"),
        (os.path.join(project_root, "reporting"), "reporting"),
    ],
    hiddenimports=["win32timezone"],
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
    name="TokenVaultReporting",
    console=False,  # GUI app, no console window
    icon=None,
)
