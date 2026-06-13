@echo off
title VAPT ML Engine — Launcher
color 0A
echo.
echo  =============================================
echo    VAPT ML Engine v1.1.1
echo    Vulnerability Prediction AI
echo  =============================================
echo.

:: Step 1: Train the model if not already trained
if not exist "models\vapt_rf_model.pkl" (
    echo  [1/2] Training ML model... ^(first-time setup^)
    python train_fast.py
    if errorlevel 1 (
        echo  ERROR: Training failed. Make sure requirements are installed.
        echo  Run: pip install -r requirements.txt
        pause
        exit /b 1
    )
    echo  Model trained successfully.
    echo.
) else (
    echo  [1/2] Model already trained. Skipping training.
    echo.
)

:: Step 2: Launch FastAPI server
echo  [2/2] Starting VulneraSense API on http://127.0.0.1:8585
echo.
echo  Open http://127.0.0.1:8585 in your browser.
echo  Press Ctrl+C to stop.
echo.
python -m uvicorn app:app --host 127.0.0.1 --port 8585 --reload

pause
