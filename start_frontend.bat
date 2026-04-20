@echo off
echo ========================================
echo  PhishGuard - Starting Frontend
echo ========================================
cd /d "%~dp0frontend"

IF NOT EXIST "node_modules" (
    echo Installing npm packages...
    npm install
)

echo.
echo Starting Vite dev server on http://localhost:5173
echo.
npm run dev
