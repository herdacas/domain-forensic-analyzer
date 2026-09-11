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

# Explizite venv-Binary bevorzugen (robust gegen PATH-Reset unter sudo)
PYTHON="python3"
if [ -x ".venv/bin/python" ]; then
    PYTHON=".venv/bin/python"
fi

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
"$PYTHON" run.py "$DOMAIN"

# Letzten Report holen und Szenario-Metadaten anhängen
"$PYTHON" docs/attach_scenario_metadata.py --id A --label "Linux + Direktverbindung" --os Linux --external-ip "$EXTERNAL_IP" --output "$OUTPUT"

echo ""
echo "=== Szenario A abgeschlossen ==="
