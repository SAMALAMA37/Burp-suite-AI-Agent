@echo off
setlocal
cd /d "%~dp0"
if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
  "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" "%~dp0nine_router\launch_9router.py" %*
) else (
  python "%~dp0nine_router\launch_9router.py" %*
)
if errorlevel 1 pause
