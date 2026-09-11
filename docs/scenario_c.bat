@echo off
REM =============================================================================
REM PHASE 4 — Szenario C: Windows + Direktverbindung
REM =============================================================================
REM Voraussetzungen:
REM   - Aktive Internetverbindung (kein VPN)
REM   - venv aktiviert: .venv\Scripts\activate
REM   - Ausführen aus dem Projektroot: docs\scenario_c.bat
REM =============================================================================

setlocal enabledelayedexpansion

set DOMAIN=example.com
set OUTPUT=docs\examples\scenario_c_windows_direct.json
set REPORT_DIR=docs\examples

echo.
echo === PHASE 4: Szenario C (Windows + Direktverbindung) ===
echo Domain  : %DOMAIN%
echo Output  : %OUTPUT%
echo.

REM Externe IP abrufen
for /f "tokens=*" %%i in ('curl -s --max-time 5 https://api.ipify.org 2^>nul') do set EXTERNAL_IP=%%i
echo Externe IP : %EXTERNAL_IP%
echo.

if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

REM Scan ausführen
python run.py %DOMAIN%
if errorlevel 1 (
    echo ERROR: Scan fehlgeschlagen
    exit /b 1
)

REM Letzten Report holen und Szenario-Metadaten hinzufügen
python docs\attach_scenario_metadata.py --id C --label "Windows + Direktverbindung" --os Windows --external-ip "%EXTERNAL_IP%" --output "%OUTPUT%"

echo.
echo === Szenario C abgeschlossen ===
