@echo off
setlocal enabledelayedexpansion

echo Starting AI-Powered VAPT Engine v1.1.1...
echo ========================================

:: Cleanup using PowerShell (more reliable than batch FOR loops)
echo [1/3] Cleaning up existing processes on ports 8484, 5173, 5174...
powershell -Command "Get-NetTCPConnection -LocalPort 8484, 5173, 5174 -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }; Write-Host 'Cleanup complete.'"

:: Database Check/Sync
echo [2/3] Checking database schema...
.\venv\Scripts\python.exe sync_db.py
.\venv\Scripts\python.exe fix_stuck_scans.py

:: Start Backend
echo [3/3] Launching Backend and Frontend...
echo Starting FastAPI Backend on port 8484...
start "VAPT Backend" cmd /c ".\venv\Scripts\python.exe -m uvicorn app:app --port 8484 --host 127.0.0.1 --reload"

:: Start Frontend
cd frontend
start "VAPT Frontend" cmd /c "npm run dev"

echo.
echo ========================================
echo VAPT Engine Started!
echo ----------------------------------------
echo Dashboard: http://localhost:5173/
echo API Docs:  http://127.0.0.1:8484/docs
echo ========================================
echo.
echo NOTE: If you want to use ONLINE AI mode, 
echo go to 'Settings' in the dashboard and 
echo add your Groq API Key.
echo.
pause
