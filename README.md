# Domain Forensic Analyzer

[![Tests](https://github.com/herdacas/domain-forensic-analyzer/actions/workflows/test.yml/badge.svg)](https://github.com/herdacas/domain-forensic-analyzer/actions/workflows/test.yml)
[![Python](https://img.shields.io/badge/python-3.10%20|%203.11%20|%203.12-blue)](https://www.python.org)
[![Coverage](https://img.shields.io/badge/coverage-70%25-green)](https://github.com/herdacas/domain-forensic-analyzer/actions)
[![Pylint](https://img.shields.io/badge/pylint-9.11%2F10-brightgreen)](https://pylint.readthedocs.io)

A terminal-based OSINT tool that gives you a complete intelligence picture of any domain in one run — from DNS configuration and certificate history to infrastructure fingerprinting, threat intelligence, and network path analysis. Designed for security analysts, incident responders, and researchers who need actionable data without juggling 10 different tools.

See [SECURITY.md](SECURITY.md) for the OPSEC threat model (what this tool exposes to a scanned target), [CONTRIBUTING.md](CONTRIBUTING.md) if you want to work on it, and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for module layout and the report lifecycle.

---

## What you get

A single structured report covering everything relevant to a domain investigation:

- **Who registered it** — registrar, creation date, expiry, registrant disclosure or privacy proxy detection, registry policy flags (DENIC, SIDN, and others that redact by policy)
- **Where it lives** — IP, ASN, hosting provider, CDN/WAF detection (Cloudflare, Akamai, Fastly, OVH, Hetzner, and more), geographic risk assessment
- **How it's configured** — full DNS record set with TTLs, SPF chain resolution, DMARC/DKIM/CAA, DNSSEC, zone transfer probe
- **What changed over time** — historical DNS timeline across Mnemonic PDNS, RobTex, VirusTotal, and certificate transparency logs; nameserver and MX migration events grouped by date
- **How it behaves** — HTTP→HTTPS redirect, HSTS, CSP, X-Frame-Options, TLS certificate chain (issuer, SANs, expiry, version)
- **Who else is on that IP** — reverse-IP co-hosted domains from three passive sources
- **What the threat intel says** — VirusTotal domain reputation, AbuseIPDB IP score, SecurityTrails historical subdomain data
- **What the network path looks like** — traceroute with hop classification, ping latency
- **Risk summary** — heuristic score with specific factors listed (expired cert, newly registered, no HTTPS redirect, high geographic risk, etc.)

Inactive or expired domains fall into **historical analysis mode** automatically — the tool reconstructs what it can from passive sources without failing noisily.

---

## Quick Start

**Linux / Ubuntu:**

```bash
git clone https://github.com/herdacas/domain-forensic-analyzer.git
cd domain-forensic-analyzer
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
sudo apt install iputils-ping traceroute   # optional, improves network module
python3 run.py example.com
```

**Windows:**

```powershell
git clone https://github.com/herdacas/domain-forensic-analyzer.git
cd domain-forensic-analyzer
python -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt
python run.py example.com
```

No API keys required to start. Active probes and free APIs cover roughly 70% of the full report out of the box.

---

## Usage

```bash
# Single domain — argument or interactive prompt
python3 run.py example.com
python3 run.py

# Batch mode — one domain per line, # comments supported
python3 run.py --list domains.txt
```

**Input handling:**
- Subdomains are automatically stripped to apex (`aws.amazon.com` → `amazon.com`)
- Compound ccTLDs are preserved (`bbc.co.uk` stays `bbc.co.uk`)
- Internationalized domains are converted to punycode (`münchen.de` → `xn--mnchen-3ya.de`)
- IP addresses and file paths are rejected with a clear error

Reports are written automatically to `reports/` after each scan — no flags needed.

---

## API Keys (optional)

Add keys to unlock historical DNS, reputation data, and deeper WHOIS intelligence.

**Option A — environment variables:**

```bash
export VIRUSTOTAL_API_KEY="your_key"
export ABUSEIPDB_API_KEY="your_key"
export WHOISXML_API_KEY="your_key"
export SECURITYTRAILS_API_KEY="your_key"
```

**Option B — config file** (`config/api_keys.json`, git-ignored):

```json
{
  "virustotal":     { "api_key": "YOUR_KEY" },
  "abuseipdb":      { "api_key": "YOUR_KEY" },
  "whoisxml":       { "api_key": "YOUR_KEY" },
  "securitytrails": { "api_key": "YOUR_KEY" }
}
```

| Source | Key | Free tier |
|--------|-----|-----------|
| WHOIS enrichment | `WHOISXML_API_KEY` | 500 req/month |
| Domain & IP reputation | `VIRUSTOTAL_API_KEY` | 500 req/day |
| IP abuse score | `ABUSEIPDB_API_KEY` | 1 000 req/day |
| Historical DNS | `SECURITYTRAILS_API_KEY` | 50 req/month |

Modules without a configured key are skipped and marked in the execution summary. The tool never crashes on a missing key.

---

## Report Structure

```
SUMMARY           — overall risk, key factors, recommendation
TARGET            — resolved IPs, nameservers, mail servers
GEO & ASN         — country, city, ASN, ISP, hosting type, geographic risk
WHOIS             — registration details, privacy proxy, registry policy
DNS FORENSICS     — full record set, email security, DNSSEC
DNS HISTORY       — IP/NS/MX change timeline across passive sources
NETWORK PATH      — traceroute with hop classification, latency
HTTP/S BEHAVIOR   — redirect chain, HSTS, CSP, X-Frame-Options
SSL / TLS         — certificate issuer, validity, SANs, TLS version
INFRASTRUCTURE    — CDN/WAF/hosting provider, edge protection
ATTACK SURFACE    — discovered subdomains, sensitive asset candidates
THREAT INTELLIGENCE — VT domain score, AbuseIPDB IP score, SecurityTrails
IP & DOMAIN HISTORY — reverse-IP co-hosted domains, historical IPs
RISK ASSESSMENT   — heuristic score with specific risk factors
EXECUTION         — module timing, API coverage, log reference
```

---

## Platform Compatibility

| Platform | Python | Status |
|---|---|---|
| Windows 10/11 (PowerShell) | 3.10 – 3.12 | ✅ Validated — CI + manual cross-platform scenarios (direct + VPN) |
| Linux (Ubuntu) | 3.10 – 3.12 | ✅ Validated — CI + manual cross-platform scenarios (direct + VPN) |
| macOS | 3.10 – 3.12 | ⚠️ Should work (no OS-specific code paths beyond the Windows/Linux traceroute split) but not covered by CI or manual validation — report issues if you hit one |

Windows uses `tracert`; Linux uses `tracepath` (auto-detected). Neither being installed degrades the NETWORK PATH block gracefully instead of failing the scan. See [`docs/VALIDATION_REPORT.md`](docs/VALIDATION_REPORT.md) for the full cross-platform validation results (4 scenarios: Windows/Linux × direct connection/VPN).

## Network Dependencies (Linux)

| Binary | Used for | Install |
|--------|----------|---------|
| `ping` | Latency check | `sudo apt install iputils-ping` |
| `traceroute` / `tracepath` | Network path | `sudo apt install traceroute` |

If neither is available the NETWORK PATH module degrades gracefully — all other modules continue normally.

---

## Security Notes

- Active probes (DNS resolution, SSL/TLS handshake, HTTP/S, ping, traceroute, subdomain DNS) are visible to the target host.
- Passive APIs (VirusTotal, AbuseIPDB, SecurityTrails, RobTex, Mnemonic, crt.sh) do not expose your IP to the target.
- For low-footprint investigations, route traffic through a VPN at OS level before running.
- VPN/proxy detection in the OPSEC block is rDNS keyword matching — it will not catch every VPN provider (see [SECURITY.md](SECURITY.md) for details). Don't treat "not detected" as proof no VPN is active.
- Do not commit `config/api_keys.json` or `.env` files.

Full threat model, data-handling notes, and known security-relevant limitations: [SECURITY.md](SECURITY.md).

---

## Example Reports

Real scan output (`example.com`) from the Phase 4 cross-platform validation, one per platform/network combination:

| Scenario | File |
|---|---|
| Linux, direct connection | [`docs/examples/scenario_a_linux_direct.json`](docs/examples/scenario_a_linux_direct.json) |
| Linux, VPN | [`docs/examples/scenario_b_linux_vpn.json`](docs/examples/scenario_b_linux_vpn.json) |
| Windows, direct connection | [`docs/examples/scenario_c_windows_direct.json`](docs/examples/scenario_c_windows_direct.json) |
| Windows, VPN | [`docs/examples/scenario_d_windows_vpn.json`](docs/examples/scenario_d_windows_vpn.json) |

These are the structured `reports/<id>_<domain>.json` exports the tool writes automatically — use them to see the full field set without running a scan yourself. A raw console capture (what you'd see in the terminal, ANSI codes included) is at [`docs/vpn_pretest_windows.txt`](docs/vpn_pretest_windows.txt).

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `UnicodeEncodeError: 'charmap' codec can't encode characters` | Legacy Windows console (cp1252) rendering `├──` box-drawing characters | Fixed as of the UTF-8 console reconfiguration in `run.py` — if you still see this, make sure you're running `run.py` directly (not importing `domain_analyzer` in a script without the same startup) |
| Module marked `FAILED` immediately after starting a VPN | DNS query sent to a nameserver blocked by the VPN's routing (commonly seen with ProtonVPN, which blocks port 53 to the physical adapter's DNS) | Already handled — `DNSAnalyzer` probes each candidate nameserver's TCP port 53 reachability before querying and skips unreachable ones. If it still happens, the VPN may be blocking *all* resolvers; check `nslookup` works manually first |
| `DNS History: UNAVAILABLE` or a `NameError` in `dns_history_analyzer.py` | Missing `import json` (fixed in a past release) or a source returning malformed data | Update to the latest `main` — this was a known bug fixed pre-1.0 |
| A module reports "no API key" even though one is set in `config/api_keys.json` | A placeholder value in `.env` (e.g. `VIRUSTOTAL_API_KEY=your_key_here`) is overriding it via `load_dotenv()` | Remove or fill in the placeholder line in `.env` — env vars take priority over the JSON config |
| `192.168.0.1` or similar gets scanned instead of rejected | You're on an older build — IP-address rejection was added in a later 1.0.x-track fix | Update to the latest `main` |
| Traceroute/ping section shows "not available" | `traceroute`/`tracepath`/`ping` binary not installed (Linux) or blocked by a firewall | `sudo apt install iputils-ping traceroute` — the rest of the report is unaffected either way |
| `crt.sh` certificate history missing | crt.sh is a shared community service and occasionally rate-limits or times out | The tool retries automatically, then falls back to CertSpotter. If both fail, `Certificate History` shows `not available (all sources failed)` — this is upstream flakiness, not a bug |
| Domain shows `HISTORICAL ANALYSIS (domain inactive)` but you know it's live | Current DNS resolution failed — could be a genuinely expired domain, or a transient network/VPN DNS issue | Check the domain resolves manually (`nslookup domain.com`) before trusting the historical-mode fallback |

## FAQ

**Do I need API keys to use this?**
No. Active probes and free APIs (ip-api.com, crt.sh, CertSpotter, RobTex, HackerTarget, Mnemonic PDNS) cover roughly 70% of the report with zero configuration. API keys unlock deeper WHOIS, reputation, and historical DNS data.

**Does this tool actively exploit or attack the target?**
No. Every probe is standard reconnaissance (DNS queries, a TLS handshake, an HTTP request, ping/traceroute, a zone-transfer *attempt*). It does not brute-force, exploit, or send any malicious payloads. See [SECURITY.md](SECURITY.md) for exactly what's active vs. passive.

**Will the target know I scanned them?**
Possibly — see the "Active probes" list in [SECURITY.md](SECURITY.md). DNS queries, the TLS handshake, ping/traceroute, and the zone-transfer attempt all originate from your IP and can appear in the target's own logs. The passive API lookups do not.

**Why does GEO & ASN sometimes show empty or `null` fields?**
Geolocation and ASN data come from `ip-api.com` (free tier, no key). Coverage varies by IP range and CDN provider — some anycast/CDN IPs don't carry meaningful ASN data through that API. This is an upstream data-availability gap, not a bug in the tool.

**Can I run this against a batch of domains unattended?**
Yes — `python run.py --list domains.txt`. Each domain gets its own timeout budget (`MODULE_TIMEOUTS` in `config/settings.py`) so one slow/unresponsive domain won't stall the whole batch indefinitely.

**Does it work on macOS?**
Almost certainly, since there's no macOS-specific code path missing, but it hasn't been part of CI or the manual cross-platform validation — see the Platform Compatibility table above.

---

## Known Limitations

- WHOIS registrant fields are redacted by registry policy for several ccTLDs (DENIC/DE, SIDN/NL, SWITCH/CH, and others) — the report flags this explicitly rather than showing empty fields.
- SecurityTrails and VirusTotal history depth depends on account tier and provider PDNS coverage.
- Subdomain discovery is DNS-pattern based; wildcard DNS degrades results to candidate-only mode.
- Certificate Transparency shows issuance history, not authoritative DNS. Wildcard-only certs (`*.domain.com`) produce no subdomain entries by design.
- The risk model is heuristic — treat it as a starting point for investigation, not a definitive verdict.
