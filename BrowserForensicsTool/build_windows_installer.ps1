$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonExe = "C:\Users\nayak\AppData\Local\Programs\Python\Python312\python.exe"
$SpecPath = Join-Path $ProjectRoot "BrowserForensicsTool.spec"
$InstallerScript = Join-Path $ProjectRoot "installer\BrowserForensicsTool.iss"

if (-not (Test-Path $PythonExe)) {
    throw "Python interpreter not found at $PythonExe"
}

& $PythonExe -m PyInstaller --clean --noconfirm $SpecPath

$InnoCompiler = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
if (-not (Test-Path $InnoCompiler)) {
    $InnoCompiler = "${env:ProgramFiles}\Inno Setup 6\ISCC.exe"
}
if (-not (Test-Path $InnoCompiler)) {
    $InnoCompiler = Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe"
}

if (-not (Test-Path $InnoCompiler)) {
    throw "Inno Setup Compiler not found. Install Inno Setup 6 first."
}

& $InnoCompiler $InstallerScript
