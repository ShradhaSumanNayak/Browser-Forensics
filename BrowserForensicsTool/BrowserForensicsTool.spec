# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules


project_root = Path(".").resolve()

datas = []
datas += collect_data_files("reportlab")
datas += collect_data_files("pandas")
datas += collect_data_files("openpyxl")
datas += collect_data_files("llama_cpp")
datas += collect_data_files("huggingface_hub")
datas += [(str(project_root / "README.md"), ".")]
datas += [(str(project_root / "assets" / "browser_forensics_tool.ico"), "assets")]

hiddenimports = []
for package_name in ["api", "collectors", "gui", "parsers", "reports", "utils", "Cryptodome", "llama_cpp", "huggingface_hub"]:
    hiddenimports += collect_submodules(package_name)


a = Analysis(
    ["main_gui.py"],
    pathex=[str(project_root)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="BrowserForensicsTool",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    icon=str(project_root / "assets" / "browser_forensics_tool.ico"),
    version=str(project_root / "windows_version_info.txt"),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="BrowserForensicsTool",
)
