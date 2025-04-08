@echo off
SETLOCAL

REM Set Python path
SET PYTHON_EXEC=python

REM Ensure pip is available
echo [*] Checking pip...
%PYTHON_EXEC% -m ensurepip >nul 2>&1

REM Upgrade pip
echo [*] Upgrading pip...
%PYTHON_EXEC% -m pip install --upgrade pip

REM Install required Python packages
echo [*] Installing dependencies from requirements.txt...
%PYTHON_EXEC% -m pip install -r requirements.txt

REM Done!
echo.
echo [✔] Setup complete!
echo.
echo To run the OSINT scanner, use:
echo.
echo     python OSINT.py --ip 8.8.8.8
echo     python OSINT.py --url https://example.com
echo     python OSINT.py --domain example.com
echo     python OSINT.py --hash xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
echo     python OSINT.py --email jogn.doe@example.com 
echo     python OSINT.py --account john.doe
echo
echo     To Output Results 
echo     python OSINT.py --domain example.com --output file.txt
echo.

ENDLOCAL
pause
