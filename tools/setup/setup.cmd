@echo off
rem ESP32-P4 time server setup (Windows).
rem   setup.cmd          opens the setup window
rem   setup.cmd --cli    guided setup in this console instead
setlocal
cd /d "%~dp0"

set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY (where python >nul 2>nul && set "PY=python")
if not defined PY (
  echo Python 3.10 or newer is needed. Install it with:
  echo     winget install --id Python.Python.3.12 -e
  echo then open a new window and run setup.cmd again.
  pause
  exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  echo First run: preparing the setup tool. This takes a minute...
  %PY% -m venv .venv || goto :failed
  ".venv\Scripts\python.exe" -m pip install --quiet --upgrade pip || goto :failed
  ".venv\Scripts\python.exe" -m pip install --quiet -r requirements.txt || goto :failed
)

".venv\Scripts\python.exe" -m ntp_setup %*
exit /b %errorlevel%

:failed
echo Preparing the setup tool failed. Check the internet connection and try again.
rmdir /s /q .venv 2>nul
pause
exit /b 1
