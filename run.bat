@echo off
echo ============================================
echo   ThreatLens - Setup and Launch
echo ============================================

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Install from https://python.org
    pause
    exit /b 1
)

REM Create virtual environment if not exists
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate and install
echo Installing dependencies...
call venv\Scripts\activate.bat
pip install -r requirements.txt -q

REM Launch
echo.
echo Starting ThreatLens at http://localhost:5000
echo Press Ctrl+C to stop.
echo.
python app.py
pause

REM Delete old cached models so improved ones rebuild on first run
if exist "backend\models\ml_model.joblib" del "backend\models\ml_model.joblib"
if exist "backend\models\nlp_model.joblib" del "backend\models\nlp_model.joblib"
