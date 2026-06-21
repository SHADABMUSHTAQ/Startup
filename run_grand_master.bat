@echo off
setlocal
set "BASE_DIR=%~dp0"
cd /d "%BASE_DIR%"

:: Force current directory into Python Path as a fallback
set PYTHONPATH=.
set PYTHONIOENCODING=utf-8

echo ========================================================
echo        WarSOC Grand Master Automated Launcher (V3)
echo ========================================================
echo.

echo [1/6] Booting API Server...
start "WarSOC: API Server" cmd /k "call .venv\Scripts\activate && uvicorn app.main:app --host 127.0.0.1 --port 8000"
timeout /t 5 /nobreak >nul

echo [2/6] Running Triple-Lock CI Validation...
python scripts\ci_validate.py
if %ERRORLEVEL% NEQ 0 (
    echo [!] ALERT: Validation Failed. Aborting Launch to protect data.
    pause
    exit /b %ERRORLEVEL%
)
timeout /t 2 /nobreak >nul

echo [3/6] Booting SIEM Worker...
REM ⛔ PRODUCTION GUARD: clean_slate.py is intentionally DISABLED.
REM It does FLUSHALL on Redis + wipes MongoDB. Only run it manually for testing:
REM    python scripts\clean_slate.py
start "WarSOC: SIEM Worker" cmd /k "call .venv\Scripts\activate && python -m app.workers.siem_worker"
timeout /t 1 /nobreak >nul

echo [4/6] Booting FBR Worker...
start "WarSOC: FBR Worker" cmd /k "call .venv\Scripts\activate && python -m app.workers.fbr_worker"
timeout /t 1 /nobreak >nul

echo [5/6] Booting PECA Worker...
start "WarSOC: PECA Worker" cmd /k "call .venv\Scripts\activate && python -m app.workers.peca_worker"

echo.
echo ========================================================
echo ALL WORKERS ARE NOW LIVE AND REFREEE IS WATCHING!
echo ========================================================
pause
