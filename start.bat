@echo off
title AEGIS Startup Script
echo =======================================
echo    AEGIS INTELLIGENCE PLATFORM 
echo =======================================
echo.
echo Starting Backend Engine (FastAPI)...
start "AEGIS Backend" cmd /k "cd backend && python -m uvicorn main:app --reload --port 8000"

echo Starting Frontend UI (Vite + React)...
start "AEGIS Frontend" cmd /k "cd frontend && npm run dev"

echo.
echo Launching protocol. Please wait...
timeout /t 3 /nobreak > NUL

echo Opening Web Application in Default Browser...
start http://localhost:5173/

echo.
echo SYSTEM ONLINE.
echo Keep the two new black terminal windows open while using AEGIS!
echo You can close this window now.
pause
