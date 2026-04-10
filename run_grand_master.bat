@echo off
setlocal
set "BASE_DIR=%~dp0"
cd /d "%BASE_DIR%"

:: Force current directory into Python Path as a fallback
set PYTHONPATH=.

echo ========================================================
echo        WarSOC Grand Master Automated Launcher (V3)
echo ========================================================
echo.

echo [1/5] Running Triple-Lock CI Validation...
python scripts\ci_validate.py
if %ERRORLEVEL% NEQ 0 (
    echo [!] ALERT: Validation Failed. Aborting Launch to protect data.
    pause
    exit /b %ERRORLEVEL%
)
timeout /t 2 /nobreak >nul

echo [2/5] Booting SIEM Worker...
REM ⛔ PRODUCTION GUARD: clean_slate.py is intentionally DISABLED.
REM It does FLUSHALL on Redis + wipes MongoDB. Only run it manually for testing:
REM    python scripts\clean_slate.py
start "WarSOC: SIEM Worker" cmd /k "python -m app.workers.siem_worker"
timeout /t 1 /nobreak >nul

echo [3/5] Booting FBR Worker...
start "WarSOC: FBR Worker" cmd /k "python -m app.workers.fbr_worker"
timeout /t 1 /nobreak >nul

echo [4/5] Booting PECA Worker...
start "WarSOC: PECA Worker" cmd /k "python -m app.workers.peca_worker"

echo.
echo ========================================================
echo ALL WORKERS ARE NOW LIVE AND REFREEE IS WATCHING!
echo ========================================================
pause
