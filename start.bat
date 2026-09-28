@echo off
chcp 65001 >nul
title BlacksmithAI Launcher

echo ==========================================
echo   BlacksmithAI - One Click Launcher v2.0
echo ==========================================
echo.

cd /d "%~dp0\blacksmithAI"

echo [1/4] Checking Docker container...
docker ps --filter "name=shell-executor" --format "{{.Names}}" | findstr "shell-executor" >nul
if errorlevel 1 (
    echo Starting mini-kali container...
    docker start shell-executor
    timeout /t 5 /nobreak >nul
) else (
    echo Container already running.
)
echo.

echo [2/4] Checking Ollama...
curl -s http://localhost:11434/api/tags >nul 2>&1
if errorlevel 1 (
    echo Warning: Ollama not running. AI features will be disabled.
    echo Start Ollama from https://ollama.ai for full AI capabilities.
) else (
    echo Ollama running - AI features enabled.
)
echo.

echo [3/4] Running system health check...
.venv\Scripts\python.exe health_check.py
echo.

echo [4/4] Starting Web Dashboard...
start "BlacksmithAI Dashboard" cmd /c ".venv\Scripts\python.exe -m web.dashboard"
timeout /t 3 /nobreak >nul
echo.

echo ==========================================
echo   BlacksmithAI is running!
echo ==========================================
echo.
echo   Dashboard:  http://localhost:8501
echo   Health:    http://localhost:8501/health
echo   Scan:      http://localhost:8501/orchestrated-scan
echo   AI:        http://localhost:8501/ai
echo.
echo   Container: shell-executor (port 9756)
echo   LLM:       mistral-nemo:12b-pentest (local)
echo ==========================================
echo.

echo Press any key to open Dashboard in browser...
pause >nul
start http://localhost:8501

cmd /k
