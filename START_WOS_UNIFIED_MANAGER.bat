@echo off
setlocal EnableExtensions
cd /d "%~dp0"
set "LOGDIR=%LOCALAPPDATA%\WOS_Unified_Manager"
set "ERRLOG=%LOGDIR%\startup_console.log"
if not exist "%LOGDIR%" mkdir "%LOGDIR%" >nul 2>nul

echo ==== START %date% %time% ==== > "%ERRLOG%"
echo Dossier: %CD% >> "%ERRLOG%"

REM V4.0.47 - IMPORTANT: use the SAME Python family as INSTALL_DEPENDENCIES.bat.
REM Prefer the local virtual environment when present.
if exist ".venv\Scripts\python.exe" (
  set "PYEXE=%CD%\.venv\Scripts\python.exe"
  goto :run
)

REM Without a venv, prefer the Windows Python Launcher (same choice as installer).
where py >nul 2>nul
if not errorlevel 1 (
  for /f "usebackq delims=" %%I in (`py -3 -c "import sys; print(sys.executable)" 2^>nul`) do set "PYEXE=%%I"
)
if defined PYEXE goto :run

where python >nul 2>nul
if not errorlevel 1 (
  for /f "usebackq delims=" %%I in (`python -c "import sys; print(sys.executable)" 2^>nul`) do set "PYEXE=%%I"
)
if not defined PYEXE (
  echo Python introuvable. >> "%ERRLOG%"
  echo Python introuvable.
  pause
  exit /b 9009
)

:run
echo Python: %PYEXE% >> "%ERRLOG%"
"%PYEXE%" WOS_Unified_Manager_V4_0_49.py >> "%ERRLOG%" 2>&1
set "RC=%ERRORLEVEL%"
if "%RC%"=="0" goto :eof

echo.
echo ECHEC DEMARRAGE - code %RC%
echo Journal: %ERRLOG%
echo.
type "%ERRLOG%"
pause
