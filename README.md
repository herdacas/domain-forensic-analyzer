# Domain Forensic Analyzer

Terminal-based OSINT tool for investigating domains across DNS, WHOIS, SSL/TLS, infrastructure, network path, and external threat-intelligence sources. Produces a structured forensic report in the terminal and exports JSON + raw text to `reports/`.

---

## Quick Start (Linux / Ubuntu)

```bash
# 1. Clone
git clone https://github.com/herdacas/domain-forensic-analyzer.git
cd domain-forensic-analyzer

# 2. Virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Python dependencies
pip install -r requirements.txt

# 4. System dependencies (optional but recommended)
sudo apt install traceroute iputils-ping

# 5. Run
python3 run.py example.com
```

No API keys required to start. Active probes + free APIs cover ~70% of the full report out of the box.

---

## Usage

```bash
# Interactive prompt
python3 run.py

# Direct domain argument
python3 run.py example.com

# Batch mode — one domain per line, # comments allowed
python3 run.py --list domains.txt
```

Reports are written automatically to `reports/` after each scan — no flags needed.

---

## API Keys (optional)

Add keys to unlock historical DNS, reputation data, and deeper WHOIS intelligence.

**Option A — environment variables (recommended for servers):**

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

`base_url` und `rate_limit` sind optional — werden automatisch auf Standardwerte gesetzt wenn nicht angegeben. Das Format ist identisch auf Linux und Windows.

| Module           | Key                    | Free tier         |
|------------------|------------------------|-------------------|
| WHOIS            | `WHOISXML_API_KEY`     | 500 req/month     |
| VirusTotal       | `VIRUSTOTAL_API_KEY`   | 500 req/day       |
| AbuseIPDB        | `ABUSEIPDB_API_KEY`    | 1 000 req/day     |
| SecurityTrails   | `SECURITYTRAILS_API_KEY` | 50 req/month   |
| SSL/TLS          | —                      | no key required   |
| GEO & ASN        | —                      | no key required   |
| HTTP/S Behavior  | —                      | no key required   |

Modules without a configured key are skipped and marked in the execution summary. The tool never crashes on a missing key.

---

## Report Sections

```
SUMMARY
TARGET
GEO & ASN
WHOIS REGISTRATION
DNS FORENSICS
DNS HISTORY TIMELINE
NETWORK PATH
HTTP/S BEHAVIOR
SSL / TLS
INFRASTRUCTURE
ATTACK SURFACE
THREAT INTELLIGENCE
IP & DOMAIN HISTORY
RISK ASSESSMENT
EXECUTION
```

---

## Modules

11 modules run in sequence:

| # | Module          | What it does                                                        |
|---|-----------------|---------------------------------------------------------------------|
| 1 | dns             | A/AAAA/CNAME/NS/MX/TXT/SOA, SPF chain, DMARC, DKIM, CAA, DNSSEC   |
| 2 | whois           | Registration via WhoisXML API + python-whois fallback               |
| 3 | dns_history     | Historical DNS timeline (Mnemonic, RobTex, VirusTotal, CT logs)    |
| 4 | cdn             | CDN/WAF/hosting detection, GEO & ASN from ip-api.com               |
| 5 | network         | Ping, traceroute, HTTP/S behavior probe                             |
| 6 | subdomain       | DNS-based subdomain discovery with wildcard handling                |
| 7 | ssl             | TLS certificate inspection (issuer, validity, SANs, TLS version)   |
| 8 | securitytrails  | SecurityTrails domain intelligence                                  |
| 9 | abuseipdb       | IP reputation                                                       |
|10 | virustotal      | Domain reputation and category intelligence                         |
|11 | ip_history      | Reverse-IP lookup (VirusTotal, RobTex, HackerTarget)               |

---

## Project Structure

```
run.py                          Entry point
config/
  api_keys.json                 API credentials (git-ignored)
src/
  core/
    domain_analyzer.py          Orchestrator + report renderer
    report_exporter.py          JSON + raw TXT export
  analyzers/                    One module per analyzer (see table above)
  utils/
    colors.py                   Terminal color helpers
    validators.py               Domain input validation + normalization
reports/                        Auto-created on first run (git-ignored)
  NNNN_domain.json              Structured JSON report per scan
  raw/NNNN_domain.txt           Raw console output per scan
tests/
  test_module_performance.py    Per-module timing benchmark
  test_dns_analyzer.py
  test_dns_history_analyzer.py
  test_result_aggregator.py
```

---

## Testing

```bash
# Module timing benchmark — runs all 11 modules against a real domain
python3 tests/test_module_performance.py github.com

# Unit tests
python3 -m pytest tests/test_dns_analyzer.py tests/test_dns_history_analyzer.py tests/test_result_aggregator.py
```

---

## Network Dependencies (Linux)

| Binary       | Used by           | Install if missing                     |
|--------------|-------------------|----------------------------------------|
| `traceroute` | NETWORK PATH      | `sudo apt install traceroute`          |
| `tracepath`  | NETWORK PATH      | auto-fallback, usually pre-installed   |
| `ping`       | NETWORK PATH      | `sudo apt install iputils-ping`        |

If neither `traceroute` nor `tracepath` is available, NETWORK PATH reports the missing dependency and all other modules continue normally.

---

## Security Notes

- Do not commit `config/api_keys.json` or `.env`.
- Active probes (DNS, SSL/TLS handshake, HTTP/S, ping, traceroute) are visible to the target host.
- External lookup APIs (VirusTotal, AbuseIPDB, SecurityTrails) observe the queried domain.
- For low-footprint investigations, route traffic through a VPN at the OS level before running the tool.

---

## Known Limitations

- WHOIS fields may be redacted by registry policy (DENIC, SIDN, SWITCH, and others) — shown explicitly in the report.
- SecurityTrails and VirusTotal history depth depends on account tier and provider coverage.
- Subdomain discovery is DNS-pattern based and degrades to candidate-only mode under wildcard DNS.
- Certificate Transparency shows certificate issuance history, not authoritative DNS history. Wildcard-only certs (`*.domain.com`) produce no subdomain entries by design.
- The risk model is heuristic — use it to guide investigation, not as a definitive verdict.
