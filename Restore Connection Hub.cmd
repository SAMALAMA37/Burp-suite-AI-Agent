@echo off
setlocal
cd /d "%~dp0"
if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
  "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" "%~dp0provider_hub\launch_hub.py" --connect-burp %*
) else (
  python "%~dp0provider_hub\launch_hub.py" --connect-burp %*
)
if errorlevel 1 pause
