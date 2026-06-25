@echo off
title CyberFusion Setup

echo =====================================
echo CyberFusion Dependency Installation
echo =====================================
echo.

where npm >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Node.js is not installed.
    echo Install Node.js first.
    pause
    exit /b 1
)

echo Installing Backend dependencies...
cd /d "%~dp0Backend-Virustotal-main\Backend-Virustotal-main\Backend-Virustotal-main"

call npm install

if %errorlevel% neq 0 (
    echo Backend installation failed.
    pause
    exit /b 1
)

echo.
echo Installing Frontend dependencies...
cd /d "%~dp0UI_UX-CTI-APP-main\UI_UX-CTI-APP-main"

call npm install

if %errorlevel% neq 0 (
    echo Frontend installation failed.
    pause
    exit /b 1
)

echo.
echo =====================================
echo Installation completed successfully.
echo =====================================
pause