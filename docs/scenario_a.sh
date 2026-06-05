#!/usr/bin/env bash
# =============================================================================
# PHASE 4 — Szenario A: Linux + Direktverbindung
# =============================================================================
# Voraussetzungen:
#   - Aktive Internetverbindung (kein VPN)
#   - venv aktiviert: source .venv/bin/activate
#   - Ausführen aus dem Projektroot: bash docs/scenario_a.sh
# =============================================================================

set -e

DOMAIN="example.com"
OUTPUT="docs/examples/scenario_a_linux_direct.json"
REPORT_DIR="docs/examples"

echo ""
echo "=== PHASE 4: Szenario A (Linux + Direktverbindung) ==="
echo "Domain  : $DOMAIN"
echo "Output  : $OUTPUT"
echo ""

# Prüfe ob kein VPN läuft
EXTERNAL_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "unknown")
echo "Externe IP : $EXTERNAL_IP"
echo ""

mkdir -p "$REPORT_DIR"

# Scan ausführen und Report in reports/ speichern
python3 run.py "$DOMAIN"

# Letzten JSON-Report aus reports/ holen
LATEST=$(ls -t reports/*.json 2>/dev/null | head -1)
if [ -z "$LATEST" ]; then
    echo "ERROR: Kein Report gefunden in reports/"
    exit 1
fi

# Metadaten hinzufügen und als Szenario-Report speichern
python3 - <<PYEOF
import json, sys, os
from datetime import datetime

with open("$LATEST") as f:
    data = json.load(f)

data["scenario"] = {
    "id": "A",
    "label": "Linux + Direktverbindung",
    "os": "Linux",
    "vpn": False,
    "external_ip": "$EXTERNAL_IP",
    "timestamp": datetime.utcnow().isoformat() + "Z"
}

with open("$OUTPUT", "w") as f:
    json.dump(data, f, indent=2, default=str)

print(f"Report gespeichert: $OUTPUT")
print(f"Domain   : {data.get('domain', 'unknown')}")
print(f"External : $EXTERNAL_IP")
meta = data.get("analyst", {})
asn = data.get("results", {}).get("cdn", {}).get("asn_info", {})
opsec = meta.get("opsec_assessment", {})
print(f"VPN det. : {opsec.get('potential_vpn', 'n/a')}")
print(f"ASN      : {asn.get('asn', 'n/a')} {asn.get('organization', '')}")
PYEOF

echo ""
echo "=== Szenario A abgeschlossen ==="
