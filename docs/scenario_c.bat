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
    'id': 'C',
    'label': 'Windows + Direktverbindung',
    'os': 'Windows',
    'vpn': False,
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
echo === Szenario C abgeschlossen ===
