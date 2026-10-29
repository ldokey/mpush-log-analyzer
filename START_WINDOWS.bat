@echo off
setlocal EnableExtensions DisableDelayedExpansion
call "%~dp0scripts\run_windows.bat"
exit /b %errorlevel%
