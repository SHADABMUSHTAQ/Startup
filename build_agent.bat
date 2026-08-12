@echo off
setlocal

set "ROOT_DIR=%~dp0"
set "AGENT_DIR=%ROOT_DIR%agent"
set "AGENT_SOURCE=%AGENT_DIR%\windows_agent.py"
set "DIST_DIR=%AGENT_DIR%\dist"
set "BUILD_DIR=%AGENT_DIR%\build"

if not exist "%AGENT_SOURCE%" (
    echo [ERROR] Agent source not found: %AGENT_SOURCE%
    exit /b 1
)

REM -- Resolve the real Python executable path directly --
REM    Avoids broken Windows Store shim / py launcher issues in batch subshells.
set "PYTHON_EXE="

REM Strategy 0: Prefer the repo virtual environment when present
if exist "%ROOT_DIR%.venv\Scripts\python.exe" (
    "%ROOT_DIR%.venv\Scripts\python.exe" -c "import PyInstaller" >nul 2>&1
    if not errorlevel 1 set "PYTHON_EXE=%ROOT_DIR%.venv\Scripts\python.exe"
)

REM Strategy 1: Prefer Python 3.13, which is supported by the pinned
REM PyInstaller/pywin32 agent build toolchain.
if not defined PYTHON_EXE (
    for /f "usebackq delims=" %%P in (`py -3.13 -c "import sys; print(sys.executable)" 2^>nul`) do set "PYTHON_EXE=%%P"
)

REM Strategy 2: Fall back to another registered Python 3 runtime
if not defined PYTHON_EXE (
    for /f "usebackq delims=" %%P in (`py -3 -c "import sys; print(sys.executable)" 2^>nul`) do set "PYTHON_EXE=%%P"
)

REM Strategy 3: Fallback to where python.exe resolves
if not defined PYTHON_EXE (
    for /f "usebackq delims=" %%P in (`where python 2^>nul`) do (
        if not defined PYTHON_EXE set "PYTHON_EXE=%%P"
    )
)

if not defined PYTHON_EXE (
    echo [ERROR] Cannot locate Python. Install Python 3.x and ensure it is on PATH.
    exit /b 1
)

echo [INFO] Using Python: %PYTHON_EXE%

REM Verify PyInstaller is available
"%PYTHON_EXE%" -c "import PyInstaller" 2>nul
if errorlevel 1 (
    echo [ERROR] PyInstaller is not installed for %PYTHON_EXE%
    echo Install it with: "%PYTHON_EXE%" -m pip install pyinstaller
    exit /b 1
)

REM Native Windows telemetry and DPAPI are mandatory agent capabilities.
REM PyInstaller reports missing hidden imports as warnings, so fail before the
REM build instead of producing an installer that cannot collect events.
"%PYTHON_EXE%" -c "import win32evtlog, win32security, win32crypt, pythoncom, pywintypes" 2>nul
if errorlevel 1 (
    echo [ERROR] Mandatory pywin32 modules are unavailable for %PYTHON_EXE%
    echo Install the agent build dependencies with:
    echo   "%PYTHON_EXE%" -m pip install -r "%AGENT_DIR%\requirements-build.txt"
    exit /b 1
)

if not exist "%DIST_DIR%" mkdir "%DIST_DIR%"
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

"%PYTHON_EXE%" -m PyInstaller ^
    --onefile ^
    --console ^
    --clean ^
    --collect-submodules cryptography ^
    --collect-data cryptography ^
    --collect-binaries cryptography ^
    --hidden-import cryptography ^
    --hidden-import cryptography.hazmat.primitives ^
    --hidden-import cryptography.hazmat.primitives.serialization ^
    --hidden-import cryptography.hazmat.primitives.asymmetric ^
    --hidden-import cryptography.hazmat.primitives.asymmetric.ed25519 ^
    --hidden-import requests ^
    --hidden-import dotenv ^
    --hidden-import win32evtlog ^
    --hidden-import win32security ^
    --hidden-import win32crypt ^
    --hidden-import pythoncom ^
    --hidden-import pywintypes ^
    --name warsoc_agent ^
    --distpath "%DIST_DIR%" ^
    --workpath "%BUILD_DIR%" ^
    --specpath "%BUILD_DIR%" ^
    "%AGENT_SOURCE%"

if errorlevel 1 (
    echo [ERROR] Agent build failed.
    exit /b 1
)

echo [OK] Built %DIST_DIR%\warsoc_agent.exe
exit /b 0
