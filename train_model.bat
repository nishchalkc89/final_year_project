@echo off
echo ========================================
echo  PhishGuard - ML Model Training
echo ========================================

SET PYTHON=C:\Users\Asus\AppData\Local\Programs\Python\Python311\python.exe

cd /d "%~dp0ml_model"

echo Step 1: Generating dataset...
"%PYTHON%" generate_dataset.py

echo.
echo Step 2: Training models (RF + XGBoost)...
"%PYTHON%" train.py

echo.
echo Training complete! Models saved to ml_model\models\
pause
