@echo off
chcp 65001 >nul
title BlacksmithAI Stopper

echo ==========================================
echo   BlacksmithAI - Stopping all services
echo ==========================================
echo.

echo [1/2] Stopping Python Dashboard...
taskkill /f /im python.exe /fi "WINDOWTITLE eq BlacksmithAI Dashboard*" >nul 2>&1
echo Dashboard stopped.
echo.

echo [2/2] Stopping Docker container...
docker stop shell-executor >nul 2>&1
echo Container stopped.
echo.

echo ==========================================
echo   All services stopped.
echo ==========================================
echo.
pause
