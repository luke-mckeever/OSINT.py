@echo off
SETLOCAL ENABLEEXTENSIONS

echo Checking if Python is installed...
where python >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Python not found. Downloading and installing Python 3.13...

    powershell -Command "Invoke-WebRequest -Uri https://www.python.org/ftp/python/3.13.0/python-3.13.0-amd64.exe -OutFile python-installer.exe"
    start /wait python-installer.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0

    echo Python 3.13 installed successfully.
) ELSE (
    echo Python is already installed.
)

echo Installing required Python packages...
python -m pip install --upgrade pip
pip install -r requirements.txt

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
