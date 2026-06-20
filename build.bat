@echo off
echo ============================================================
echo  Browser Forensics Tool - Windows 11 Build Script
echo ============================================================

REM Make sure we're in the right directory
cd /d "%~dp0"

REM Check Python is available
python --version >nul 2>&1 || (echo [ERROR] Python not found in PATH. & pause & exit /b 1)

REM Verify PyInstaller is installed; do not upgrade dependencies automatically.
echo [*] Checking PyInstaller...
python -c "import PyInstaller" >nul 2>&1 || (
    echo [ERROR] PyInstaller is not installed. Install it with: pip install pyinstaller
    pause
    exit /b 1
)

REM Prefer local virtual environment if present
if exist "%~dp0\.venv\Scripts\python.exe" (
    set "PYTHON=%~dp0\.venv\Scripts\python.exe"
) else (
    set "PYTHON=python"
)

REM Build the executable
echo [*] Building executable... this may take 2-4 minutes.
 "%PYTHON%" -m PyInstaller --noconfirm --onefile --windowed ^
    --name="BrowserForensicsTool_v1" ^
    --add-data="BrowserForensicsTool/assets;assets" ^
    --add-data="BrowserForensicsTool/reports;reports" ^
    --add-data="BrowserForensicsTool/parsers;parsers" ^
    --add-data="BrowserForensicsTool/utils;utils" ^
    --add-data="BrowserForensicsTool/gui;gui" ^
    --hidden-import=PyQt5 ^
    --hidden-import=PyQt5.QtWidgets ^
    --hidden-import=PyQt5.QtCore ^
    --hidden-import=PyQt5.QtGui ^
    --hidden-import=sqlite3 ^
    --hidden-import=pandas ^
    --hidden-import=openpyxl ^
    --hidden-import=Cryptodome ^
    --hidden-import=Cryptodome.Cipher.AES ^
    --hidden-import=huggingface_hub ^
    "BrowserForensicsTool/main_gui.py"

if errorlevel 1 (
    echo [ERROR] Build failed! Check the output above for details.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo  [SUCCESS] Executable created at: dist\BrowserForensicsTool_v1.exe
echo ============================================================
echo.
start explorer dist\
pause
