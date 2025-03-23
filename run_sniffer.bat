@echo off
:: Check for admin privileges
NET SESSION >nul 2>&1
if %errorLevel% == 0 (
    goto :run_script
) else (
    echo Requesting administrative privileges...
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B
)

:run_script
cls
echo ===============================================================
echo                    SniffWork Network Analyzer
echo ===============================================================
echo.
echo Welcome to SniffWork! This application requires Python and Scapy.
echo.
echo Prerequisites:
echo 1. Python 3.x installed (preferably Python 3.8 or higher)
echo 2. Required Python packages:
echo    - scapy
echo    - matplotlib
echo    - tkinter (usually comes with Python)
echo.
echo If you haven't installed the requirements, the script will try to
echo install them automatically.
echo.
echo ---------------------------------------------------------------
echo.
echo Checking Python installation...
python --version >nul 2>&1
if %errorLevel% == 0 (
    echo Python is installed.
) else (
    echo Python is not installed! Please install Python from:
    echo https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    pause
    exit /B
)

echo.
echo Checking and installing required packages...
python -m pip install --upgrade pip
python -m pip install scapy matplotlib

echo.
echo ---------------------------------------------------------------
echo Starting SniffWork...
echo.
echo Note: The application requires administrative privileges to
echo capture network packets. A UAC prompt may appear.
echo.
echo Press any key to start SniffWork...
pause >nul

cd /d "%~dp0"
python "Network Sniffer.py"

if %errorLevel% neq 0 (
    echo.
    echo An error occurred while running the application.
    echo Please check if all requirements are properly installed.
    echo.
    pause
) 