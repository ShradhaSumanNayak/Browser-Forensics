$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonExe = "C:\Users\nayak\AppData\Local\Programs\Python\Python312\python.exe"

if (-not (Test-Path $PythonExe)) {
    throw "Python 3.12 was not found at $PythonExe"
}

Push-Location $ProjectRoot
try {
    & $PythonExe -m PyInstaller --clean --noconfirm BrowserForensicsTool.spec
}
finally {
    Pop-Location
}
