@echo off
title PacketGuard - Network Firewall Simulator
echo ========================================================
echo   PacketGuard - Network Firewall Simulator
echo ========================================================
echo.

:: 1. Try Windows Python Launcher (py)
where py >nul 2>nul
if %errorlevel% equ 0 (
    echo Starting server with Python launcher (py)...
    py server.py
    goto :end
)

:: 2. Try standard python executable
where python >nul 2>nul
if %errorlevel% equ 0 (
    echo Starting server with python...
    python server.py
    goto :end
)

:: 3. Try python3 executable
where python3 >nul 2>nul
if %errorlevel% equ 0 (
    echo Starting server with python3...
    python3 server.py
    goto :end
)

:: 4. Fallback: Open index.html directly in default browser
echo [Notice] Python not detected in system PATH.
echo Launching PacketGuard directly in your default browser...
start index.html

:end
pause

