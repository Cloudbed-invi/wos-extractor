@echo off
setlocal EnableExtensions
cd /d "%~dp0"

echo ============================================================
echo WOS Unified Manager V4.0.47 - Installation des dependances
echo ============================================================

REM Choose the base Python once, then create a LOCAL venv.
set "BASEPY="
where py >nul 2>nul
if not errorlevel 1 (
  for /f "usebackq delims=" %%I in (`py -3 -c "import sys; print(sys.executable)" 2^>nul`) do set "BASEPY=%%I"
)
if not defined BASEPY (
  where python >nul 2>nul
  if not errorlevel 1 (
    for /f "usebackq delims=" %%I in (`python -c "import sys; print(sys.executable)" 2^>nul`) do set "BASEPY=%%I"
  )
)
if not defined BASEPY (
  echo ERREUR: Python 3 introuvable.
  pause
  exit /b 9009
)

echo Python de base: %BASEPY%

if not exist ".venv\Scripts\python.exe" (
  echo Creation de l'environnement Python local .venv ...
  "%BASEPY%" -m venv .venv
  if errorlevel 1 goto :error
)

set "PYEXE=%CD%\.venv\Scripts\python.exe"
echo Python WOS: %PYEXE%

"%PYEXE%" -m pip install --upgrade pip
if errorlevel 1 goto :error
"%PYEXE%" -m pip install --upgrade scapy pyautogui pillow
if errorlevel 1 goto :error
"%PYEXE%" -m pip install --upgrade rapidocr-onnxruntime
if errorlevel 1 (
  echo.
  echo ATTENTION: RapidOCR n'a pas pu etre installe.
  echo La capture reseau restera utilisable, mais l'agent visuel pourra etre indisponible.
)

echo.
echo Verification Scapy dans LE MEME Python que l'application...
"%PYEXE%" -c "import sys, scapy; print('OK Scapy -', sys.executable); print('Scapy', getattr(scapy,'__version__','?'))"
if errorlevel 1 goto :error

echo.
echo Installation terminee.
echo START_WOS_UNIFIED_MANAGER.bat utilisera automatiquement ce .venv.
echo Npcap reste necessaire pour la capture WOS live.
pause
exit /b 0

:error
echo.
echo ERREUR pendant l'installation. Code %ERRORLEVEL%
pause
exit /b %ERRORLEVEL%
