@echo off
title VAPT Command Center
color 0a

echo.
echo  ===========================================
echo   VAPT COMMAND CENTER - Starting Services
echo  ===========================================
echo.

:: Start Backend on port 8001 (8000 is reserved by Splunk)
echo [1/2] Starting FastAPI backend on http://localhost:8001 ...
start "VAPT Backend" cmd /k "cd /d "%~dp0" && uvicorn backend.main:app --host 0.0.0.0 --port 8001 --reload"

:: Wait for backend
timeout /t 5 /nobreak >nul

:: Start Frontend
echo [2/2] Starting Next.js frontend on http://localhost:3000 ...
start "VAPT Frontend" cmd /k "cd /d "%~dp0frontend" && npm run dev"

:: Wait and open browser
timeout /t 7 /nobreak >nul
echo.
echo  [OK] Both services started!
echo  Dashboard: http://localhost:3000
echo  API Docs:  http://localhost:8001/docs
echo.
start "" "http://localhost:3000"
