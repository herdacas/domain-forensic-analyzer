# Phase 4 — Validation Report

**Status:** PENDING — wird nach Erhalt aller 4 JSON-Reports vom Agent ausgefüllt

---

## Vergleichsmatrix

| Domain | OS | Location | External_IP | VPN_Detected | ASN | DNS_OK | SSL_OK | Risk |
|--------|----|----------|-------------|--------------|-----|--------|--------|------|
| example.com | Linux | Direct | — | — | — | — | — | — |
| example.com | Linux | VPN | — | — | — | — | — | — |
| example.com | Windows | Direct | — | — | — | — | — | — |
| example.com | Windows | VPN | — | — | — | — | — | — |

---

## Szenario A — Linux + Direktverbindung

- **Externe IP:** —
- **VPN erkannt:** —
- **ASN:** —
- **DNS-Auflösung:** —
- **SSL-Zertifikat:** —
- **WHOIS:** —
- **Geolocation:** —
- **Module 11/11:** —
- **Auffälligkeiten:** —

## Szenario B — Linux + VPN

- **Externe IP:** —
- **VPN erkannt:** —
- **VPN-Land:** —
- **ASN:** —
- **Abweichung zu A (erwartet):** GEO & ASN unterschiedlich ✓
- **Auffälligkeiten:** —

## Szenario C — Windows + Direktverbindung

- **Externe IP:** —
- **VPN erkannt:** —
- **ASN:** —
- **Abweichung zu A:** Traceroute-Format (tracert vs tracepath) ✓
- **Auffälligkeiten:** —

## Szenario D — Windows + VPN

- **Externe IP:** —
- **VPN erkannt:** —
- **VPN-Land:** —
- **ASN:** —
- **Auffälligkeiten:** —

---

## Konsistenz-Check

| Prüfung | Ergebnis |
|---------|----------|
| DNS-Records identisch über alle Szenarien | — |
| SSL-Zertifikat identisch | — |
| WHOIS-Daten konsistent | — |
| GEO/ASN unterschiedlich bei VPN (erwartet) | — |
| Keine Fehler in Logs | — |
| Reports vollständig erstellt | — |

---

## Fazit

*Wird nach Analyse ausgefüllt.*

---

*Erstellt von Phase 4 Validation Agent*
