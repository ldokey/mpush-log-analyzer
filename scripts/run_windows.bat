@echo off
setlocal EnableExtensions
title MPushAgent Log Analyzer

cd /d "%~dp0\.."
if errorlevel 1 (
    echo ERROR: Cannot open project folder.
    pause
    exit /b 1
)
echo ===========================================
echo MPushAgent Log Analyzer - Windows launcher
echo ===========================================
echo NOTICE: Store customer logs on a private local NTFS folder.
echo WARNING: Shared NAS folders inherit permissions from the network share.
echo.

where py >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python launcher not found. Install Python 3.13 x64.
    pause
    exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
    echo Creating Python 3.13 virtual environment...
    py -3.13 -m venv .venv
    if errorlevel 1 goto FAIL
)
set "PYEXE=%CD%\.venv\Scripts\python.exe"
"%PYEXE%" -c "import sys; sys.exit(0 if sys.version_info[:2] == (3, 13) else 1)"
if errorlevel 1 (
    echo ERROR: Virtual environment Python version mismatch.
    echo Recreate the venv using Python 3.13.
    goto FAIL
)
"%PYEXE%" -c "import streamlit, pandas, jsonschema; from zoneinfo import ZoneInfo; ZoneInfo('Asia/Seoul')" >nul 2>&1
if errorlevel 1 (
    echo Installing dependencies...
    "%PYEXE%" -m pip install --disable-pip-version-check -r requirements.txt
    if errorlevel 1 goto FAIL
)
echo Starting http://127.0.0.1:8501
echo Press Ctrl+C to stop.
"%PYEXE%" -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501 --browser.gatherUsageStats false
if errorlevel 1 goto FAIL
exit /b 0

:FAIL
echo Failed. Review the preceding error messages.
pause
exit /b 1
