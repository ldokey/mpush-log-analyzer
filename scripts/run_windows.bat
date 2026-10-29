@echo off
setlocal EnableExtensions DisableDelayedExpansion
title MPushAgent Log Analyzer - Windows
cd /d "%~dp0\.."
if errorlevel 1 goto DIRECTORY_ERROR
if not exist "app.py" goto PACKAGE_ERROR
if not exist "requirements.txt" goto PACKAGE_ERROR

echo ===========================================
echo MPushAgent Log Analyzer - Windows
echo ===========================================
echo Local only: http://127.0.0.1:8501
echo Do not use a shared folder or a network drive for customer logs.
echo Do not copy a macOS/Linux .venv into this Windows folder.
echo.

set "PYEXE=%CD%\.venv\Scripts\python.exe"
if not exist "%PYEXE%" (
    if exist ".venv\bin\python" goto FOREIGN_VENV
    echo [1/3] Preparing local Python 3.13 environment...
    call :CREATE_VENV
    if errorlevel 1 goto FAILED
)
"%PYEXE%" -c "import sys,struct; sys.exit(0 if sys.version_info[:2] == (3,13) and struct.calcsize('P') == 8 else 1)" >nul 2>&1
if errorlevel 1 goto WRONG_VENV

echo [2/3] Checking required Python packages...
"%PYEXE%" -c "import streamlit,pandas,jsonschema; from zoneinfo import ZoneInfo; ZoneInfo('Asia/Seoul')" >nul 2>&1
if errorlevel 1 (
    echo Installing missing packages. Internet access may be required.
    "%PYEXE%" -m pip install --disable-pip-version-check -r requirements.txt
    if errorlevel 1 goto FAILED
)

echo [3/3] Opening local application.
echo Browser URL: http://127.0.0.1:8501
echo Stop the application with Ctrl+C in this window.
"%PYEXE%" -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501 --browser.gatherUsageStats false
if errorlevel 1 goto FAILED
exit /b 0

:CREATE_VENV
where py >nul 2>&1
if not errorlevel 1 (
    py -3.13 -c "import sys,struct; sys.exit(0 if sys.version_info[:2] == (3,13) and struct.calcsize('P') == 8 else 1)" >nul 2>&1
    if not errorlevel 1 (
        py -3.13 -m venv ".venv"
        if errorlevel 1 exit /b 1
        exit /b 0
    )
)
where python >nul 2>&1
if errorlevel 1 goto PYTHON_NOT_FOUND
python -c "import sys,struct; sys.exit(0 if sys.version_info[:2] == (3,13) and struct.calcsize('P') == 8 else 1)" >nul 2>&1
if errorlevel 1 goto PYTHON_NOT_FOUND
python -m venv ".venv"
if errorlevel 1 exit /b 1
exit /b 0

:PYTHON_NOT_FOUND
echo ERROR: Python 3.13 64-bit was not found.
echo Install Python 3.13 x64 from python.org and enable the Python launcher.
echo Check with: py -3.13 --version
exit /b 1

:FOREIGN_VENV
echo ERROR: A macOS/Linux virtual environment was found in .venv.
echo Use a fresh project copy without .venv. The script will not delete it.
goto FAILED

:WRONG_VENV
echo ERROR: Existing .venv is not Python 3.13 64-bit.
echo Move the existing .venv elsewhere, then run START_WINDOWS.bat again.
goto FAILED

:DIRECTORY_ERROR
echo ERROR: Cannot open the project directory. Use a local Windows folder.
goto FAILED

:PACKAGE_ERROR
echo ERROR: app.py or requirements.txt is missing.
echo Extract the entire project archive, not just START_WINDOWS.bat.
goto FAILED

:FAILED
echo.
echo Startup failed. See docs\WINDOWS_QUICK_START.md for troubleshooting.
pause
exit /b 1
