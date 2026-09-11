@echo off
REM =============================================================================
REM PHASE 4 — Szenario D: Windows + VPN (AT/CH/DE)
REM =============================================================================
REM Voraussetzungen:
REM   - VPN aktiv (Österreich, Schweiz oder Deutschland)
REM   - venv aktiviert: .venv\Scripts\activate
REM   - Ausführen aus dem Projektroot: docs\scenario_d.bat
REM =============================================================================

setlocal enabledelayedexpansion

set DOMAIN=example.com
set OUTPUT=docs\examples\scenario_d_windows_vpn.json
set REPORT_DIR=docs\examples

echo.
echo === PHASE 4: Szenario D (Windows + VPN) ===
echo.
echo ^>^> WICHTIG: VPN muss aktiv sein zu Oesterreich / Schweiz / Deutschland
echo.

REM Externe IP + Land prüfen
for /f "tokens=*" %%i in ('curl -s --max-time 5 https://api.ipify.org 2^>nul') do set EXTERNAL_IP=%%i
for /f "tokens=*" %%i in ('curl -s --max-time 5 https://ipinfo.io/%EXTERNAL_IP%/country 2^>nul') do set GEO=%%i

echo Externe IP : %EXTERNAL_IP%  (Land: %GEO%)
echo.
echo Drücke eine Taste wenn VPN aktiv ist und bereit...
pause >nul

if not exist "%REPORT_DIR%" mkdir "%REPORT_DIR%"

REM Scan ausführen
python run.py %DOMAIN%
if errorlevel 1 (
    echo ERROR: Scan fehlgeschlagen
    exit /b 1
)

REM Report mit Metadaten speichern
python docs\attach_scenario_metadata.py --id D --label "Windows + VPN" --os Windows --external-ip "%EXTERNAL_IP%" --vpn --vpn-country "%GEO%" --output "%OUTPUT%"

echo.
echo === Szenario D abgeschlossen ===
