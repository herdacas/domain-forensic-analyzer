# Domain Forensic Analyzer

A terminal-based OSINT tool that gives you a complete intelligence picture of any domain in one run — from DNS configuration and certificate history to infrastructure fingerprinting, threat intelligence, and network path analysis. Designed for security analysts, incident responders, and researchers who need actionable data without juggling 10 different tools.

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
- Do not commit `config/api_keys.json` or `.env` files.

---

## Known Limitations

- WHOIS registrant fields are redacted by registry policy for several ccTLDs (DENIC/DE, SIDN/NL, SWITCH/CH, and others) — the report flags this explicitly rather than showing empty fields.
- SecurityTrails and VirusTotal history depth depends on account tier and provider PDNS coverage.
- Subdomain discovery is DNS-pattern based; wildcard DNS degrades results to candidate-only mode.
- Certificate Transparency shows issuance history, not authoritative DNS. Wildcard-only certs (`*.domain.com`) produce no subdomain entries by design.
- The risk model is heuristic — treat it as a starting point for investigation, not a definitive verdict.
