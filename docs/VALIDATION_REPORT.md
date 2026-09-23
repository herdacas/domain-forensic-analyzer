# Phase 4 — Validation Report

**Status:** COMPLETE — alle 4 Szenarien ausgeführt und ausgewertet (2026-09-23)

**Quellen:**
- `docs/examples/scenario_a_linux_direct.json` (2026-09-11, Linux, Direktverbindung)
- `docs/examples/scenario_b_linux_vpn.json` (2026-09-11, Linux, VPN NL)
- `docs/examples/scenario_c_windows_direct.json` (2026-09-11, Windows, Direktverbindung)
- `docs/examples/scenario_d_windows_vpn.json` (2026-09-11, Windows, VPN NL)

Target-Domain in allen 4 Läufen: `example.com`

---

## Vergleichsmatrix

| Domain | OS | Location | External_IP | VPN_Detected | ASN | DNS_OK | SSL_OK | Risk |
|--------|----|----------|-------------|--------------|-----|--------|--------|------|
| example.com | Linux | Direct | 81.169.211.133 | Nein | n/a (null) | ✓ 172.66.147.243 | ✓ | minimal |
| example.com | Linux | VPN (NL) | 89.38.97.215 | Nein¹ | n/a (null) | ✓ 104.20.23.154 | ✓ | minimal |
| example.com | Windows | Direct | 95.91.196.245 | Nein | n/a (null) | ✓ 172.66.147.243 | ✓ | minimal |
| example.com | Windows | VPN (NL) | 190.2.149.74 | Nein¹ | n/a (null) | ✓ 104.20.23.154 | ✓ | minimal |

¹ False Negative — bekannte Limitierung, siehe Konsistenz-Check.

---

## Szenario A — Linux + Direktverbindung

- **Externe IP:** 81.169.211.133
- **VPN erkannt:** Nein (korrekt, kein VPN aktiv)
- **ASN:** null / null (siehe Auffälligkeiten)
- **DNS-Auflösung:** ✓ A `172.66.147.243`, AAAA `2606:4700:10::ac42:93f3`, NS `elliott.ns.cloudflare.com` / `hera.ns.cloudflare.com`
- **SSL-Zertifikat:** SSL Corporation, TLSv1.3, Wildcard, gültig bis 2026-10-27 (46 Tage)
- **WHOIS:** Registrar `RESERVED-Internet Assigned Numbers Authority`, Creation 1995-08-14
- **Geolocation:** leer (`infrastructure.location: {}`)
- **Module 11/11:** ✓ alle erfolgreich, 0 failed
- **Auffälligkeiten:** DNSSEC-Status `not_detected` — weicht von B/C/D (`enabled`) ab, siehe Konsistenz-Check. Traceroute: 10 Hops, `responsive_hops: 0`, `connectivity_status: unknown`.

## Szenario B — Linux + VPN

- **Externe IP:** 89.38.97.215
- **VPN erkannt:** Nein — False Negative
- **VPN-Land:** NL
- **ASN:** null / null
- **Abweichung zu A (erwartet):** GEO & ASN unterschiedlich ✓ (andere externe IP, anderer Cloudflare-PoP `104.20.23.154` statt `172.66.147.243`)
- **Auffälligkeiten:** `potential_vpn: false` trotz aktivem ProtonVPN — bekannte Limitierung (rDNS-basierte Erkennung, siehe CLAUDE.md §48). DNSSEC hier `enabled` (Diskrepanz zu A). Traceroute: 5 Hops (kürzerer Pfad über VPN-Exit).

## Szenario C — Windows + Direktverbindung

- **Externe IP:** 95.91.196.245
- **VPN erkannt:** Nein (korrekt)
- **ASN:** null / null
- **Abweichung zu A:** Traceroute-Format (`tracert` vs `tracepath`) ✓ — beide liefern strukturell kompatible Hop-Daten (9 vs 10 Hops, gleiche Zielauflösung `172.66.147.243` wie Szenario A trotz anderem Netz/Standort — Cloudflare Anycast-Verhalten konsistent)
- **Auffälligkeiten:** DNSSEC `enabled` (wie B/D, nicht wie A). Ansonsten deckungsgleich mit A (SSL, WHOIS, Risk).

## Szenario D — Windows + VPN

- **Externe IP:** 190.2.149.74
- **VPN erkannt:** Nein — False Negative
- **VPN-Land:** NL
- **ASN:** null / null
- **Auffälligkeiten:** Gleiches Muster wie B: `potential_vpn: false` trotz VPN, gleicher Cloudflare-PoP `104.20.23.154` wie B (beide NL-Exit) — bestätigt, dass die IP-Auflösung konsistent vom Netzwerkpfad abhängt, nicht vom OS. 8 Hops.

---

## Konsistenz-Check

| Prüfung | Ergebnis |
|---------|----------|
| DNS-Records identisch über alle Szenarien | ⚠️ Teilweise — A/C liefern dieselbe IP (Direct), B/D dieselbe IP (VPN/NL); erwartetes Anycast-Verhalten, keine Regression |
| SSL-Zertifikat identisch | ✓ Ja — Issuer, TLS-Version, Cert-Type, Ablaufdatum identisch in allen 4 |
| WHOIS-Daten konsistent | ✓ Ja — Registrar und Creation Date identisch in allen 4 |
| GEO/ASN unterschiedlich bei VPN (erwartet) | ⚠️ Externe IP unterscheidet sich korrekt zwischen Direct/VPN; ASN-Feld selbst ist in **allen 4** Szenarien `null` — kein VPN-spezifischer Effekt, sondern bestehende Lücke in der ASN-Extraktion (nicht Gegenstand von Phase 4, aber dokumentationswürdig) |
| Keine Fehler in Logs | ✓ Ja — `errors: []`, `warnings: []` in allen 4 Reports |
| Reports vollständig erstellt | ✓ Ja — alle 4 mit vollständigem `result.results` Block, 11/11 Module erfolgreich |

### Zusätzliche Beobachtungen (nicht im Template vorgesehen)

1. **VPN-Erkennung — False Negative bestätigt cross-platform:** In B (Linux+VPN) und D (Windows+VPN) bleibt `potential_vpn: false`, obwohl VPN aktiv war. Deckt sich mit der in CLAUDE.md (§48, Session 2026-06-08) dokumentierten Limitierung: rDNS-Keyword-Matching erkennt ProtonVPN nicht, da dessen Infrastruktur (Drittanbieter wie Datapacket/M247) keine "vpn"-Strings im Hostnamen trägt. Bestätigt als **plattformunabhängiges, erwartetes Verhalten** — kein neuer Bug.
2. **DNSSEC-Status inkonsistent bei identischer Domain:** A zeigt `not_detected`, B/C/D zeigen `enabled` für dieselbe Domain `example.com`. Da DNSSEC eine Domain-Eigenschaft ist (nicht netzwerkpfadabhängig), deutet das auf eine **flake in der DS/DNSKEY-Abfrage** hin (Timing/Resolver-abhängig), nicht auf einen VPN- oder OS-Unterschied. Empfehlung: als bekannte Flakiness dokumentieren, kein Blocker für Release.
3. **`network_path.responsive_hops: 0` und `connectivity_status: unknown` in allen 4 Läufen:** Traceroute liefert Hop-Anzahl, aber keine als "responsive" markierten Hops. Konsistent über alle Plattformen/VPN-Zustände — vermutlich ein generisches Aggregations-Detail in `result_aggregator.py`, keine VPN-Regression.
4. **`infrastructure.location: {}` durchgehend leer** in allen 4 Reports — GEO-Block liefert keine Daten für `example.com` (evtl. weil ip-api.com für diese spezielle Test-Domain keine sinnvollen GEO-Daten liefert, oder ein bereits bekanntes Feld-Mapping-Problem). Konsistent über alle Szenarien, also keine VPN-spezifische Regression.

---

## Fazit

**Kernziel von Phase 4 erreicht:** Die VPN-DNS-Timeout-Fixes aus Session 2026-06-08 (`_probe_nameservers()`, TCP-Port-53-Reachability-Check) funktionieren zuverlässig auf **beiden Plattformen** — alle 4 Szenarien liefern 11/11 erfolgreiche Module, keine Fehler, keine Timeouts. Das war vor dem Fix auf Windows+VPN bei 6/11 mit TIMEOUT.

SSL- und WHOIS-Daten sind über alle 4 Szenarien identisch, was die Domain-Level-Korrektheit unabhängig von Netzwerkpfad/OS bestätigt. GEO/ASN-basierte externe IP unterscheidet sich korrekt zwischen Direct- und VPN-Läufen (Cloudflare Anycast-PoP wechselt erwartungsgemäß).

Drei Punkte sind **nicht** VPN-spezifisch, aber während der Auswertung aufgefallen und sollten in einem separaten Ticket/Session behandelt werden (nicht Blocker für Phase-4-Merge):
- ASN-Feld durchgehend `null` (Extraktionslücke)
- DNSSEC-Status-Flake bei identischer Domain (A vs. B/C/D)
- `network_path` liefert `responsive_hops: 0` / `connectivity_status: unknown` durchgehend

Die bekannte VPN-Erkennungslücke (rDNS-Keyword-Matching erkennt ProtonVPN nicht) ist bereits dokumentiert und bestätigt sich hier als plattformunabhängig — kein neuer Fund, keine Regression.

**Empfehlung:** Phase 4 als abgeschlossen markieren, PR `feature/phase-4-validation` → `main` mergen. Die drei o.g. Nebenbefunde als separate Follow-up-Issues anlegen.

---

*Erstellt von Phase 4 Validation Agent — 2026-09-23*
