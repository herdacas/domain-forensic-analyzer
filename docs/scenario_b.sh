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

# Läuft dieses Skript unter "sudo vpn-ns run bash docs/scenario_b.sh", geht die
# aktivierte venv (source .venv/bin/activate) i.d.R. verloren, weil sudo PATH
# zurücksetzt. Deshalb explizit die venv-Binary bevorzugen, falls vorhanden.
PYTHON="python3"
if [ -x ".venv/bin/python" ]; then
    PYTHON=".venv/bin/python"
fi

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
"$PYTHON" run.py "$DOMAIN"

# Letzten Report holen und Szenario-Metadaten anhängen
"$PYTHON" docs/attach_scenario_metadata.py --id B --label "Linux + VPN" --os Linux --external-ip "$EXTERNAL_IP" --vpn --vpn-country "$GEO" --output "$OUTPUT"

echo ""
echo "=== Szenario B abgeschlossen ==="
