#!/usr/bin/env bash
# =============================================================================
# PHASE 4 — Szenario B: Linux + VPN (NL/DE/AT)
# =============================================================================
# Voraussetzungen:
#   - VPN aktiv (Niederlande, Deutschland oder Österreich)
#   - venv aktiviert: source .venv/bin/activate
#   - Ausführen aus dem Projektroot: bash docs/scenario_b.sh
# =============================================================================

set -e

DOMAIN="example.com"
OUTPUT="docs/examples/scenario_b_linux_vpn.json"
REPORT_DIR="docs/examples"

echo ""
echo "=== PHASE 4: Szenario B (Linux + VPN) ==="
echo ""
echo "⚠️  WICHTIG: VPN muss aktiv sein zu Niederlande / Deutschland / Österreich"
echo ""

# Externe IP prüfen
EXTERNAL_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || echo "unknown")
GEO=$(curl -s --max-time 5 "https://ipinfo.io/$EXTERNAL_IP/country" 2>/dev/null || echo "unknown")
echo "Externe IP : $EXTERNAL_IP  (Land: $GEO)"
echo ""

if [[ "$GEO" == "DE" || "$GEO" == "NL" || "$GEO" == "AT" ]]; then
    echo "✅ VPN-Land erkannt: $GEO — weiter"
else
    echo "Aktuelles Land: $GEO"
    echo "Drücke ENTER um fortzufahren (oder Ctrl+C zum Abbrechen)..."
    read -r
fi

mkdir -p "$REPORT_DIR"

# Scan ausführen
python3 run.py "$DOMAIN"

# Letzten Report holen
LATEST=$(ls -t reports/*.json 2>/dev/null | head -1)
if [ -z "$LATEST" ]; then
    echo "ERROR: Kein Report in reports/"
    exit 1
fi

python3 - <<PYEOF
import json
from datetime import datetime

with open("$LATEST") as f:
    data = json.load(f)

data["scenario"] = {
    "id": "B",
    "label": "Linux + VPN",
    "os": "Linux",
    "vpn": True,
    "vpn_country": "$GEO",
    "external_ip": "$EXTERNAL_IP",
    "timestamp": datetime.utcnow().isoformat() + "Z"
}

with open("$OUTPUT", "w") as f:
    json.dump(data, f, indent=2, default=str)

print(f"Report gespeichert: $OUTPUT")
meta = data.get("analyst", {})
asn = data.get("results", {}).get("cdn", {}).get("asn_info", {})
opsec = meta.get("opsec_assessment", {})
print(f"VPN det. : {opsec.get('potential_vpn', 'n/a')}")
print(f"ASN      : {asn.get('asn', 'n/a')} {asn.get('organization', '')}")
PYEOF

echo ""
echo "=== Szenario B abgeschlossen ==="
