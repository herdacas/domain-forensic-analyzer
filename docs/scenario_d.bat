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
python -c "
import json, os, glob
from datetime import datetime

reports = sorted(glob.glob('reports/*.json'), key=os.path.getmtime, reverse=True)
if not reports:
    print('ERROR: Kein Report in reports/')
    exit(1)

with open(reports[0]) as f:
    data = json.load(f)

data['scenario'] = {
    'id': 'D',
    'label': 'Windows + VPN',
    'os': 'Windows',
    'vpn': True,
    'vpn_country': '%GEO%',
    'external_ip': '%EXTERNAL_IP%',
    'timestamp': datetime.utcnow().isoformat() + 'Z'
}

os.makedirs('%REPORT_DIR%', exist_ok=True)
with open('%OUTPUT%', 'w') as f:
    json.dump(data, f, indent=2, default=str)

print(f'Report gespeichert: %OUTPUT%')
meta = data.get('analyst', {})
asn = data.get('results', {}).get('cdn', {}).get('asn_info', {})
opsec = meta.get('opsec_assessment', {})
print(f'VPN det. : {opsec.get(\"potential_vpn\", \"n/a\")}')
print(f'ASN      : {asn.get(\"asn\", \"n/a\")} {asn.get(\"organization\", \"\")}')
"

echo.
echo === Szenario D abgeschlossen ===
