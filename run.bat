@echo off
REM Get the directory of the batch file
set "script_dir=%~dp0"

REM Change to that directory
cd /d "%script_dir%"

REM Run the Python script
python main.py

REM Keep the command prompt open
echo.
echo Press any key to continue...
pause >nul
