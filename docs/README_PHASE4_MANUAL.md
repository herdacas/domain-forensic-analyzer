# Phase 4 — Cross-Platform & OPSEC Validation

Schritt-für-Schritt Anleitung zur manuellen Ausführung aller 4 Test-Szenarien.

---

## Überblick

| Szenario | OS | VPN | Skript |
|----------|----|-----|--------|
| A | Linux | Nein (Direktverbindung) | `docs/scenario_a.sh` |
| B | Linux | Ja (NL / DE / AT) | `docs/scenario_b.sh` |
| C | Windows | Nein (Direktverbindung) | `docs/scenario_c.bat` |
| D | Windows | Ja (AT / CH / DE) | `docs/scenario_d.bat` |

Jedes Skript führt einen `example.com`-Scan durch, holt den zuletzt erstellten JSON-Report aus `reports/` und speichert ihn mit Szenario-Metadaten in `docs/examples/`.

---

## Vorbereitung (einmalig)

```bash
# Projektroot aufrufen
cd domain-forensic-analyzer

# venv aktivieren (Linux)
source .venv/bin/activate

# venv aktivieren (Windows)
.venv\Scripts\activate

# API-Keys prüfen (optional, aber empfohlen für vollständige Reports)
cat config/api_keys.json
```

---

## Szenario A — Linux + Direktverbindung

**Voraussetzung:** kein VPN aktiv

```bash
bash docs/scenario_a.sh
```

**Erwartetes Ergebnis:**
- `docs/examples/scenario_a_linux_direct.json` erstellt
- `VPN det. : False`
- ASN zeigt deinen ISP

---

## Szenario B — Linux + VPN

**Voraussetzung:** VPN aktiv (Exit-Node in NL, DE oder AT)

1. VPN starten
2. Prüfen: `curl https://api.ipify.org && curl https://ipinfo.io/country`
3. Szenario ausführen:

```bash
bash docs/scenario_b.sh
```

**Erwartetes Ergebnis:**
- `docs/examples/scenario_b_linux_vpn.json` erstellt
- `VPN det. : True` (wenn rDNS des VPN-Providers erkannt wird)
- ASN zeigt VPN-Provider oder Exit-Node-ISP

---

## Szenario C — Windows + Direktverbindung

**Voraussetzung:** kein VPN aktiv

```powershell
docs\scenario_c.bat
```

**Erwartetes Ergebnis:**
- `docs\examples\scenario_c_windows_direct.json` erstellt
- `VPN det. : False`

---

## Szenario D — Windows + VPN

**Voraussetzung:** VPN aktiv (Exit-Node in AT, CH oder DE)

1. VPN starten
2. Prüfen: `curl https://api.ipify.org`
3. Szenario ausführen:

```powershell
docs\scenario_d.bat
```

**Erwartetes Ergebnis:**
- `docs\examples\scenario_d_windows_vpn.json` erstellt
- `VPN det. : True` (wenn VPN-Provider rDNS bekannt)

---

## Reports zurückgeben

Nachdem alle 4 Szenarien abgeschlossen sind:

```
docs/examples/
  scenario_a_linux_direct.json
  scenario_b_linux_vpn.json
  scenario_c_windows_direct.json
  scenario_d_windows_vpn.json
```

Diese 4 Dateien dem Agent übergeben — er erstellt dann automatisch `VALIDATION_REPORT.md` und die Vergleichsmatrix.

---

## Häufige Probleme

| Problem | Lösung |
|---------|--------|
| `ModuleNotFoundError: No module named 'src'` | venv nicht aktiviert oder falsches Verzeichnis |
| `No module named 'cryptography'` | `pip install -r requirements.txt` erneut ausführen |
| VPN nicht erkannt (`VPN det. : False` obwohl VPN aktiv) | Erwartet — nur bekannte VPN-Provider-Hostnamen werden erkannt. Ist korrekt. |
| Scan dauert >3 Minuten | Normal bei langsamem DNS/Traceroute. Warten. |
| `reports/` leer | Scan ist abgestürzt — Terminal-Ausgabe prüfen |
