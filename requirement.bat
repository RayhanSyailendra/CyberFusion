@echo off
title CyberFusion Setup

echo ==========================================
echo      CyberFusion Dependency Installer
echo ==========================================
echo.

:: Check Node.js installation
where node >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Node.js is not installed.
    echo Please install Node.js first:
    echo https://nodejs.org
    pause
    exit /b 1
)

where npm >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] npm is not installed.
    pause
    exit /b 1
)

echo [OK] Node.js detected.
echo.

:: =========================
:: Backend Installation
:: =========================

echo Installing Backend dependencies...
echo.

if not exist "CyberFusion/Backend-Virustotal-main" (
    echo [ERROR] Backend folder not found.
    pause
    exit /b 1
)

pushd "CyberFusion/Backend-Virustotal-main"

call npm install

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Backend installation failed.
    popd
    pause
    exit /b 1
)

popd

echo.
echo [SUCCESS] Backend dependencies installed.
echo.

:: =========================
:: Frontend Installation
:: =========================

echo Installing Frontend dependencies...
echo.

if not exist "CyberFusion/UI_UX-CTI-APP-main\UI_UX-CTI-APP-main" (
    echo [ERROR] Frontend folder not found.
    pause
    exit /b 1
)

pushd "CyberFusion/UI_UX-CTI-APP-main\UI_UX-CTI-APP-main"

call npm install

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Frontend installation failed.
    popd
    pause
    exit /b 1
)

popd

echo.
echo ==========================================
echo Installation Completed Successfully!
echo ==========================================
echo.
echo Backend and Frontend dependencies have been installed.
echo.
pause