@echo off
setlocal
echo ====================================================
echo WARSOC COMPLETE STARTUP SCRIPT (Local Dev Mode)
echo ====================================================

cd /d "c:\Users\Lenovo\Desktop\Startup-backend"

echo [1/5] Starting Infrastructure (MongoDB & Redis)...
docker-compose up -d
timeout /t 3 /nobreak >nul

echo [2/5] Starting Backend Grand Master (API & Core Workers)...
start "WarSOC: Grand Master" cmd /c "run_grand_master.bat"

echo [3/5] Starting Email Daemon...
start "WarSOC: Email Daemon" cmd /k "set PYTHONIOENCODING=utf-8 && call .venv\Scripts\activate && python -m app.workers.email_daemon"

echo [4/5] Starting Frontend (Vite)...
cd /d "c:\Users\Lenovo\Desktop\Startup-main"
start "WarSOC: Frontend" cmd /k "npm run dev"

echo [5/5] Opening Dashboard in Browser...
timeout /t 5 /nobreak >nul
start http://localhost:5173

echo ====================================================
echo Startup sequence initiated! 
echo Please verify all terminal windows are running.
echo ====================================================
pause
