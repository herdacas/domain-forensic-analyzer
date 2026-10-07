# Re-Validierung Phase 4 — 2026-10-07

Ziel: Prüfen, ob die Änderungen aus `feature/phase-4-validation` (PR #3) im aktuellen `main` (`5304039`) weiterhin greifen, bevor der lokale Branch gelöscht wird.

Target: `example.com` (identisch mit den Phase-4-Szenarien A–D, direkt vergleichbar)

---

## Scan 1 — Linux, VPN aus

| Feld | Wert |
|---|---|
| Zeitpunkt | 2026-10-07 15:59–16:00 |
| Plattform | Linux (Ubuntu 24.04, Server), Python 3.12.3 aus `.venv` |
| Befehl | `.venv/bin/python run.py example.com` |
| Report | `reports/0013_example.com.json` |
| Exit-Code | 0 |
| Dauer | 50,8 s (Szenario A: 44,2 s) |
| Module | 11/11 erfolgreich, 0 failed, 0 timeout |
| `errors` / `warnings` | leer / leer |

### Phase-4-Änderungen im Einzelnen

| Änderung (Commit auf dem Branch) | Erwartung | Ergebnis |
|---|---|---|
| Nameserver-Probe `_probe_nameservers()` (`e62d9e7`) | Erreichbare Resolver werden übernommen, kein Ausfiltern ohne Grund | ✓ `127.0.0.53` erreichbar und verwendet, Probe < 0,01 s |
| `dns_timeout` 10 → 5 s, Resolver `timeout=2` / `lifetime=5` (`442fbe4`) | Werte aktiv | ✓ 5 s / 2 s / 5 s |
| DNS-Modul ohne Timeout | schnelle Auflösung | ✓ DNS-Modul nach ~0,6 s fertig, A `172.66.147.243` |
| AXFR-Socket-Timeout 3 s (`442fbe4`) | kein Hängen, sauberes Ergebnis | ✓ `not_allowed`, 2 Cloudflare-NS getestet |
| `is_historical`-Fehlauslösung (`442fbe4`) | kein Historical-Modus bei aktiver Domain | ✓ nicht ausgelöst (IPv4 vorhanden, `failure_type` leer) |
| OPSEC-Terminologie (`66fd8f9`) | neue Formulierung in der Konsole | ✓ `VPN/Proxy Signals: No known provider signatures observed` |
| VPN-Erkennung ohne VPN | `potential_vpn: false` | ✓ korrekt (kein VPN aktiv) |

### Follow-ups aus dem Phase-4-Bericht

| Befund 2026-09-23 | Stand heute | Bewertung |
|---|---|---|
| ASN durchgehend `null` | `AS13335 Cloudflare, Inc.` | ✓ behoben (PR #10) |
| `infrastructure.location` leer | Land, Stadt, Org, AS gefüllt | ✓ behoben (PR #11) |
| DNSSEC-Flake (`not_detected` vs. `enabled`) | `check_failed` → Konsole: „check failed (network/timeout — inconclusive)“ | ✓ behoben (PR #8). Ursache bestätigt: Der System-Resolver dieses Servers (`systemd-resolved`, 127.0.0.53) antwortet auf DS/DNSKEY mit `SERVFAIL`; direkt bei Cloudflare bzw. über 1.1.1.1 sind DS und DNSKEY vorhanden. Das Tool meldet jetzt korrekt „inconclusive“ statt fälschlich „nicht vorhanden“. |
| `network_path.responsive_hops: 0`, `connectivity_status: unknown` | unverändert | ✗ **offen in `main`** — siehe F-1 |

### Findings

**F-1 (mittel) — Aggregierter Netzwerkpfad widerspricht den Rohdaten.**
`result.network_path` meldet `responsive_hops: 0` und `connectivity_status: unknown`, obwohl Ping erreichbar ist und die Traceroute bis Hop 7 antwortet. Ursache in [`src/core/result_aggregator.py:392-393`](../src/core/result_aggregator.py): Gelesen werden die Schlüssel `responsive_hops` (existiert in `traceroute_data` nicht) und `connectivity["ping"]` (heißt tatsächlich `ping_reachable`). Behoben ist das auf `refactor/v1.0-production-polish` (lokal, 18 Commits, nicht gepusht), nicht in `main`.

**F-2 (niedrig) — `connectivity_test.http_accessible: false` trotz HTTP 200.**
Die Konsole zeigt `HTTP Status: 200 OK`, das JSON-Feld `http_accessible` bleibt `false`. Ursache: HTTP auf Port 80 wird in `network_intelligence.py` nur geprüft, wenn HTTPS fehlschlägt. Das ist so gewollt, das Feld ist aber missverständlich benannt. Kein Release-Blocker.

**F-3 (Umgebung, kein Bug) — DNSSEC auf diesem Server nicht prüfbar.**
Siehe Tabelle oben. Auf einem Rechner mit validierendem Resolver ist `enabled` zu erwarten.

**Hinweis:** `config/api_keys.json` hat die Rechte `644` und ist damit für alle lokalen Benutzer lesbar. Empfehlung: `chmod 600`.

### Zwischenfazit Scan 1

Alle Änderungen aus `feature/phase-4-validation` sind im aktuellen `main` wirksam. Es gibt keine Regression. Offen ist nur F-1, und dafür liegt der Fix bereits auf dem Refactor-Branch.

---

## Scan 2 — Linux, VPN an

| Feld | Wert |
|---|---|
| Zeitpunkt | 2026-10-07 17:42–17:43 |
| Plattform | Linux (derselbe Server), Proton-WireGuard-Namespace `dfa-vpn` |
| Befehl | `sudo ip netns exec dfa-vpn sudo -u dfa-admin /opt/domain-forensic-analyzer/.venv/bin/python /opt/domain-forensic-analyzer/run.py example.com` |
| Netz-Bedingungen | DNS nur über den VPN-Resolver `10.2.0.1` erlaubt (nftables-Guard), IPv6-Egress gesperrt |
| Report | `reports/0014_example.com.json` |
| Exit-Code | 0 |
| Dauer | 49,8 s (Szenario B: 49,4 s) |
| Module | 11/11 erfolgreich, 0 failed, 0 timeout |
| `errors` / `warnings` | leer / leer |

### Vergleich mit Scan 1 und Szenario B (Phase 4, Linux + VPN)

| Feld | Scan 1 (VPN aus) | Scan 2 (VPN an) | Szenario B (2026-09-11) |
|---|---|---|---|
| Externe IP | Server-IP | VPN-Exit, ≠ Scan 1 | derselbe VPN-Exit wie Scan 2 |
| `behind_nat` / Attribution Risk | false / MEDIUM | true / LOW | true / LOW |
| `potential_vpn` | false (korrekt) | false (bekannte Limitierung) | false |
| A-Record | `172.66.147.243` | `104.20.23.154` (anderer Cloudflare-PoP) | `104.20.23.154` |
| DNS-Modul | < 1 s | < 1 s | — |
| DNSSEC | `check_failed` (inconclusive) | `enabled` | `enabled` |
| AXFR | `not_allowed` | `not_allowed` | `not_allowed` |
| ASN | AS13335 Cloudflare | AS13335 Cloudflare | `null` |
| Location | gefüllt | gefüllt | leer |
| Traceroute | 10 Hops, letzter Antwort-Hop 7 | 5 Hops, letzter Antwort-Hop 2 | 5 Hops, letzter Antwort-Hop 2 |
| `network_path.responsive_hops` / `connectivity_status` | 0 / unknown | 0 / unknown | 0 / unknown |
| Risk | minimal | minimal | minimal |

### Bewertung Scan 2

- **Nameserver-Probe und DNS-Timeouts (`e62d9e7`, `442fbe4`):** ✓ Im Namespace ist ausschließlich `10.2.0.1` als DNS erlaubt. Das DNS-Modul war trotzdem in unter 1 s fertig, ohne Timeout. Vor dem Phase-4-Fix lief genau diese Konstellation unter Windows in 6/11 Module mit TIMEOUT.
- **`is_historical` (`442fbe4`):** ✓ nicht ausgelöst.
- **OPSEC (`66fd8f9`):** ✓ `behind_nat: true`, Attribution Risk sinkt von MEDIUM auf LOW. `potential_vpn` bleibt `false`. Das ist die dokumentierte Limitierung (rDNS-Keyword-Matching erkennt die Proton-Infrastruktur nicht), keine Regression.
- **F-3 bestätigt:** Über den VPN-Resolver ist DNSSEC `enabled`. Das `check_failed` aus Scan 1 liegt also am System-Resolver des Servers, nicht am Tool.
- **F-1 bestätigt:** Auch mit VPN bleiben `responsive_hops: 0` / `connectivity_status: unknown`, obwohl Ping erreichbar ist und Hop 2 antwortet.

---

## Gesamtfazit

Beide Scans sind erfolgreich (2 × 11/11, keine Fehler, keine Timeouts). Alle Änderungen aus `feature/phase-4-validation` wirken im aktuellen `main`, mit und ohne VPN. Drei der vier Follow-ups aus Phase 4 sind in `main` behoben (ASN, Location, DNSSEC-Einstufung).

Offen bleiben:

| # | Befund | Schwere | Weg |
|---|---|---|---|
| F-1 | `network_path.responsive_hops` / `connectivity_status` falsch aggregiert | mittel | Fix liegt auf `refactor/v1.0-production-polish`, kommt mit dessen Merge nach `main` |
| F-2 | `http_accessible` irreführend, wenn HTTPS erreichbar ist | niedrig | eigenes Ticket |
| — | VPN-Erkennung erkennt Proton nicht | bekannt | dokumentierte Limitierung |

Der lokale Branch `feature/phase-4-validation` kann gelöscht werden.
