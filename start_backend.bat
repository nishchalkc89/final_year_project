@echo off
echo ========================================
echo  PhishGuard - Starting Backend
echo ========================================

SET PYTHON=C:\Users\Asus\AppData\Local\Programs\Python\Python311\python.exe

IF NOT EXIST "%PYTHON%" (
    echo ERROR: Python not found at %PYTHON%
    echo Please run: winget install Python.Python.3.11
    pause
    exit /b 1
)

cd /d "%~dp0backend"

echo Starting FastAPI server on http://localhost:8000
echo API Docs: http://localhost:8000/docs
echo Press Ctrl+C to stop
echo.

"%PYTHON%" -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
