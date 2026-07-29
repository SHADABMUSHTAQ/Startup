@echo off
setlocal

set "ROOT_DIR=%~dp0"
set "ENTRY=%ROOT_DIR%scripts\warsoc_relay_service.py"
set "DIST_DIR=%ROOT_DIR%relay\dist"
set "BUILD_DIR=%ROOT_DIR%relay\build"
set "PYTHON_EXE="

if not exist "%ENTRY%" (
    echo [ERROR] Relay entry point not found: %ENTRY%
    exit /b 1
)

if exist "%ROOT_DIR%.venv\Scripts\python.exe" (
    "%ROOT_DIR%.venv\Scripts\python.exe" -c "import PyInstaller" >nul 2>&1
    if not errorlevel 1 set "PYTHON_EXE=%ROOT_DIR%.venv\Scripts\python.exe"
)
if not defined PYTHON_EXE (
    for /f "usebackq delims=" %%P in (`py -3.13 -c "import sys; print(sys.executable)" 2^>nul`) do set "PYTHON_EXE=%%P"
)
if not defined PYTHON_EXE (
    echo [ERROR] Python 3.13 with PyInstaller is required for the relay build.
    exit /b 1
)
"%PYTHON_EXE%" -c "import PyInstaller, cryptography, httpx, pydantic" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Install requirements.txt and requirements-relay-build.txt first.
    exit /b 1
)

if not exist "%DIST_DIR%" mkdir "%DIST_DIR%"
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

REM Keep this invocation on one physical line. LF-only checkouts make cmd.exe
REM caret continuations drop the final script argument.
"%PYTHON_EXE%" -m PyInstaller --onefile --console --clean --noconfirm --name warsoc_relay --paths "%ROOT_DIR%." --collect-submodules cryptography --collect-data cryptography --collect-binaries cryptography --hidden-import app.network_relay.runtime --hidden-import app.network_relay.identity --hidden-import app.network_relay.collector --hidden-import app.network_relay.parsers --hidden-import app.network_relay.spool --hidden-import app.network_relay.outbox --distpath "%DIST_DIR%" --workpath "%BUILD_DIR%" --specpath "%BUILD_DIR%" "%ENTRY%"

if errorlevel 1 (
    echo [ERROR] Relay build failed.
    exit /b 1
)

echo [OK] Built %DIST_DIR%\warsoc_relay.exe
exit /b 0
