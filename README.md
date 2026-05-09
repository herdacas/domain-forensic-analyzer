# Domain Forensic Analyzer

Domain Forensic Analyzer is a terminal-based OSINT workflow for investigating a domain across DNS, WHOIS registration data, DNS history, infrastructure, SSL/TLS certificates, network path, attack surface, and external threat-intelligence sources.

The project is currently CLI-first and report-focused. It is designed for defensive investigation, infrastructure review, and forensic triage of domain posture.

## Current Capabilities

The final report includes:

- forensic session metadata and OPSEC context (analysis type, stealth level, active probes, passive sources)
- target DNS summary with GEO and ASN context
- WHOIS registration summary with registry policy and privacy proxy detection
- DNS forensic posture (SPF, DMARC, DKIM, CAA, DNSSEC, CNAME, full NS/MX with TTL)
- DNS history timeline with first seen dates, NS/MX migration events, and Certificate Transparency history
- network path and traceroute details
- HTTP/S behavior (redirect chain, HSTS, server header, assessment)
- SSL/TLS certificate inspection (issuer, validity, SANs, TLS version, expiry risk)
- infrastructure and CDN/WAF assessment with hosting type and geographic risk
- attack surface findings from subdomain discovery
- threat intelligence summary from integrated reputation APIs
- IP and domain history with reverse-IP co-hosted domain intelligence
- risk assessment with ordered risk factors and overall risk level
- execution summary with per-module status and API attribution

## Installation

### 1. Clone the repository

```powershell
git clone https://github.com/herdacas/domain-forensic-analyzer.git
cd domain-forensic-analyzer
```

### 2. Create and activate a virtual environment (recommended)

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

### 4. Configure API keys

Create `config/api_keys.json` with your API keys (the file is git-ignored):

```json
{
  "securitytrails": {
    "api_key": "YOUR_SECURITYTRAILS_API_KEY",
    "base_url": "https://api.securitytrails.com/v1",
    "rate_limit": 50
  },
  "abuseipdb": {
    "api_key": "YOUR_ABUSEIPDB_API_KEY",
    "base_url": "https://api.abuseipdb.com/api/v2",
    "rate_limit": 1000
  },
  "virustotal": {
    "api_key": "YOUR_VIRUSTOTAL_API_KEY",
    "base_url": "https://www.virustotal.com/api/v3",
    "rate_limit": 1000
  },
  "whoisxml": {
    "api_key": "YOUR_WHOISXML_API_KEY",
    "base_url": "https://whoisxmlapi.com/whoisserver/WhoisService",
    "rate_limit": 500
  }
}
```

Alternatively, export environment variables instead of editing the file:

```powershell
$env:VIRUSTOTAL_API_KEY    = "your_key"
$env:ABUSEIPDB_API_KEY     = "your_key"
$env:WHOISXML_API_KEY      = "your_key"
$env:SECURITYTRAILS_API_KEY = "your_key"
```

The analyzer falls back gracefully when keys are missing: modules requiring an absent key are skipped and marked SKIPPED in the execution summary. GEO/ASN and SSL/TLS modules require no API key.

## Usage

Run the analyzer interactively (prompts for domain):

```powershell
python run.py
```

Pass the target domain directly to skip the interactive prompt:

```powershell
python run.py example.com
```

Analyze multiple domains from a list file:

```powershell
python run.py --list domains.txt
```

The list file is a plain text file with one domain per line. Empty lines and lines starting with `#` are ignored, so you can use comments to organize your targets:

```text
# Production infrastructure
example.com
example.org

# Third-party services
github.com
cloudflare.com
```

Create the file anywhere you like and pass the path to `--list`. The file is never committed — add it to `.gitignore` or keep it outside the repository to avoid accidentally publishing your target list.

Reports are written automatically to `reports/` after each scan. No additional flags are required.

## Program Structure

```text
domain-forensic-analyzer/
├── run.py                          Entry point — CLI arg handling, list mode, report export trigger
├── requirements.txt                Python dependencies
├── domains.txt                     Example domain list for --list mode
│
├── config/
│   └── api_keys.json               API credentials (git-ignored, never committed)
│
├── reports/                        Auto-created on first run (git-ignored, stays local)
│   ├── NNNN_domain.json            Structured JSON report per scan (scan ID + full result payload)
│   └── raw/
│       └── NNNN_domain.txt         Raw console output per scan (with ANSI codes, exact terminal copy)
│
├── src/
│   ├── core/
│   │   ├── domain_analyzer.py      Orchestrator, report renderer, risk model, OPSEC block, display logic
│   │   └── report_exporter.py      JSON + raw TXT export; stdout capture; scan-ID management
│   │
│   ├── analyzers/
│   │   ├── dns_analyzer.py         DNS records (A/AAAA/CNAME/NS/MX/TXT/SOA), hardening checks,
│   │   │                           SPF include chain, DMARC sp/rua/ruf, DKIM selectors, CAA, DNSSEC
│   │   ├── whois.py                WHOIS via WhoisXML API + python-whois fallback;
│   │   │                           registry policy detection; privacy proxy detection
│   │   ├── dns_history_analyzer.py Historical DNS timeline — SecurityTrails, VirusTotal, crt.sh;
│   │   │                           NS/MX change grouping; first-seen dates; CT history
│   │   ├── cdn_detector.py         CDN/cloud/hosting/gov-cloud detection (hostname + IP prefix);
│   │   │                           GEO & ASN via ip-api.com; geographic risk classification
│   │   ├── ip_history_analyzer.py  Reverse-IP lookup (VirusTotal, RobTex, HackerTarget);
│   │   │                           co-hosted domain intelligence; domain IP history
│   │   ├── network_intelligence.py Ping, traceroute, HTTP/S behavior probe (redirect chain, HSTS,
│   │   │                           Server header, assessment label)
│   │   ├── ssl_analyzer.py         TLS certificate inspection via direct port 443 connection
│   │   │                           (stdlib ssl + cryptography); two-pass verified/unverified
│   │   ├── subdomain_scanner.py    DNS-based subdomain discovery; wildcard DNS handling
│   │   ├── securitytrails_client.py SecurityTrails domain intelligence API
│   │   ├── abuseipdb_client.py     AbuseIPDB IP reputation API
│   │   └── virustotal_client.py    VirusTotal domain + IP reputation API
│   │
│   ├── config/                     Runtime API config loader
│   └── utils/
│       └── colors.py               Terminal color helpers
│
└── tests/
    ├── test_dns_analyzer.py
    ├── test_dns_history_analyzer.py
    └── test_result_aggregator.py
```

Each analyzer module is self-contained and exposes a single primary `analyze_*()` method. The orchestrator in `domain_analyzer.py` calls all 11 modules in sequence and merges results into a `UnifiedResult` object used for both terminal display and JSON export.

## API Configuration

API keys are resolved in priority order:

1. environment variable (e.g. `WHOISXML_API_KEY`)
2. `config/api_keys.json` under the matching key
3. graceful fallback (python-whois for WHOIS; module skipped for reputation APIs)

The WhoisXML fallback chain is:

1. use `WHOISXML_API_KEY` if present
2. otherwise read `config/api_keys.json` under `whoisxml`
3. otherwise use local `python-whois`

API key sources per module:

| Module | Key | Free tier |
|---|---|---|
| WHOIS | `WHOISXML_API_KEY` | 500 req/month |
| VirusTotal | `VIRUSTOTAL_API_KEY` | 500 req/day |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | 1 000 req/day |
| SecurityTrails | `SECURITYTRAILS_API_KEY` | 50 req/month |
| SSL/TLS | — | no key required |
| GEO & ASN | — | no key required (ip-api.com) |
| HTTP/S Behavior | — | no key required |

## Module Details

### DNS Forensics

`src/analyzers/dns_analyzer.py` collects current DNS state:

- A and AAAA records
- CNAME record (shown only when present; root apex domains rarely have one)
- reverse DNS
- nameservers with TTL
- MX records with priority and TTL (resolved via dnspython for full FQDNs)
- A record TTL
- SOA metadata (primary NS, serial)
- TXT records
- SPF policy, enforcement mode, and recursive include chain (depth ≤ 2)
- DMARC policy, subdomain policy (`sp=`), and reporting addresses (`rua=`, `ruf=`) separately
- heuristic DKIM selector discovery (10 common selectors including `s1`, `smtp`, `google`, `mail`)
- CAA policy with explicit `issuewild` reporting
- DNSSEC detection
- zone-transfer testing
- DNS configuration assessment with hardening-gap findings

The final report surfaces DNS hardening gaps such as soft-fail SPF, monitor-only DMARC, missing DMARC, absent DNSSEC, missing CAA, and zone-transfer exposure.

### WHOIS Registration

`src/analyzers/whois.py` provides registration intelligence:

- WhoisXML API support with local `python-whois` fallback
- registrar, creation, expiration, and updated dates
- registrant name, organization, country, and email when available
- nameserver extraction and source attribution
- registry policy detection for WHOIS-redacting TLDs

Registries known to redact WHOIS fields by policy are detected automatically. Affected fields display "Not disclosed by registry (DENIC policy)" instead of a blank "Unknown", and a Registry Note line explains the policy at the top of the WHOIS block. Covered TLDs: `.de` (DENIC), `.at` (nic.at), `.ch` (SWITCH), `.nl` (SIDN), `.fi`, `.no`, `.se`, `.dk`.

Privacy proxy detection identifies 12 known proxy services (WhoisGuard, Domains By Proxy, PrivacyProtect, Withheld for Privacy, Perfect Privacy, Identity Protection Service, Contact Privacy, Data Protected, Redacted for Privacy, Privacy Guardian, Anonymize.com, Whois Privacy Protection). When detected, the proxy service name is shown in the WHOIS block.

### DNS History Timeline

`src/analyzers/dns_history_analyzer.py` builds a normalized historical timeline.

Data sources:

- SecurityTrails DNS history endpoints
- VirusTotal domain resolutions
- Certificate Transparency through `crt.sh` (with retry logic: up to 3 attempts, 1s backoff)
- native fallback when no external history is available

The DNS history report includes:

- data source attribution
- first seen date (earliest across all passive sources and WHOIS creation date)
- current IP first seen date with age label (relatively recent / established / long-standing)
- NS record changes grouped by date as real migration events
- MX record changes grouped by date as real migration events
- Certificate Transparency history from crt.sh (certificate count and date range)
- timeline span, major change count, and change-frequency assessment
- infrastructure-stability assessment and suspicious-pattern detection
- historical risk events

Same-day load-balanced VirusTotal resolution sets are grouped so large providers such as Google are not incorrectly flagged as rapid DNS churn. Certificate Transparency events are excluded from change-frequency analysis to prevent CDN domains from being incorrectly flagged as volatile. Historical NS, MX, A, and CT events are kept in dedicated buckets so that high-volume CT activity cannot crowd out DNS records.

### SSL/TLS Certificate Inspection

`src/analyzers/ssl_analyzer.py` inspects TLS certificate and protocol details via a direct connection to port 443:

- two-pass connection: verified first, then unverified fallback for expired or self-signed certificates
- issuer (organization and CN, displayed as `Org (CN)`)
- certificate validity window (valid from / valid until)
- days to expiry with color-coded status
- certificate type: Wildcard, Multi-SAN, or Single
- TLS protocol version
- Subject Alternative Names (SANs), capped at 10 with overflow count
- self-signed detection and overall assessment label

Risk flags fed into the risk model:

- expired certificate → HIGH
- expiring in under 14 days → HIGH
- expiring in under 30 days → MEDIUM
- self-signed certificate → MEDIUM
- deprecated TLS version (TLS 1.0, TLS 1.1) → risk factor added

No API key is required. The `cryptography` library is used for certificate parsing.

### Infrastructure Detection

`src/analyzers/cdn_detector.py` estimates:

- CDN and edge provider via two-pass detection (rDNS hostname matching first, IP prefix fallback)
- direct hosting versus CDN-backed infrastructure
- protection level and WAF/edge-protection availability
- geolocation context (country, region, city, ASN, ISP) via ip-api.com (no API key)
- hosting type classification (CDN, gov-cloud, cloud, hosting, transit, government, education, commercial)
- geographic risk (HIGH for CN/RU/KP/IR, MEDIUM for other elevated-risk countries)

Supported providers include Cloudflare, AWS, Azure, GCP, Akamai, Fastly, Sucuri, OVHcloud, Hetzner, IONOS/1&1, Outscale (French Government Cloud), Deutsche Telekom (DTAG), and Bundescloud/BWI.

### Network Intelligence

`src/analyzers/network_intelligence.py` performs:

- ping reachability checks
- HTTP/HTTPS connectivity checks
- traceroute collection with hop parsing, RTT extraction, and partial traceroute handling

Partial routes are preserved in the report instead of being collapsed into generic failure output.

### HTTP/S Behavior

`src/analyzers/network_intelligence.py` also probes HTTP/S behavior via `_test_http_behavior()`:

- HTTP probe with `allow_redirects=False` — detects 301/302 redirect to HTTPS
- HTTPS probe with manual redirect following (up to 5 hops)
- extracts `Server` header and `Strict-Transport-Security` from the final response
- HSTS shown as `max-age=N; includeSubDomains` when present, "not configured" when absent
- redirect chain displayed as `http://domain -> https://domain/ (N hop)`
- assessment labels: Strong (HTTPS + redirect + HSTS), Moderate (HTTPS + one of the two), Weak (HTTP only)

Risk flags fed into the risk model:

- HTTP served without redirect to HTTPS → risk factor (LOW)
- HSTS not configured → risk factor (LOW)

No API key is required.

### Attack Surface

`src/analyzers/subdomain_scanner.py` performs DNS-based subdomain discovery and categorization.

The report distinguishes:

- standard-resolution domains: findings shown as discovered subdomains
- wildcard DNS domains: findings shown as candidates only

Wildcard DNS is treated as a semantic constraint, not automatically as a risk.

### IP and Domain History

`src/analyzers/ip_history_analyzer.py` provides reverse-IP and co-hosted domain intelligence:

- domain IP history extracted from the DNS history timeline (deduped, newest first)
- reverse-IP lookup from three passive sources: VirusTotal, RobTex, and HackerTarget
- results merged and deduplicated; top 20 shown with per-entry source attribution
- total co-hosted count always displayed regardless of display limit
- CDN-aware branching: CDN IPs display 5 co-hosted domain samples; direct IPs display the full top-20 merged list
- infrastructure assessment: dedicated server, VPS, shared hosting, or CDN shared infrastructure

### Threat Intelligence

The analyzer integrates:

- SecurityTrails for domain intelligence and historical summary
- AbuseIPDB for IP reputation
- VirusTotal for domain reputation, categories, and resolutions
- WhoisXML for registration intelligence

The execution summary lists which live APIs were used in the run.

## Report Export

After each scan, two files are written automatically to the `reports/` directory. No flag is required; export is always enabled.

### JSON report

`reports/NNNN_domain.json` — structured payload including:

- `scan_id` — zero-padded 4-digit sequential ID (e.g. `0012`)
- `timestamp` — ISO 8601 UTC timestamp
- `domain` — target domain
- `scan_duration_seconds` — wall-clock time for the full scan
- `analyst` — IP, system platform, and OPSEC metadata
- `result` — full analysis result (`UnifiedResult.to_dict()`) with all module outputs

### Raw console capture

`reports/raw/NNNN_domain.txt` — exact terminal output including ANSI color codes. Useful for archiving or diffing report output between runs.

### Scan ID

Scan IDs are assigned by reading the highest existing `NNNN_` prefix in `reports/`, incrementing by one. IDs are stable across restarts and never reused. The same ID appears in both the `.json` and `.txt` filenames for a given scan.

## Current Output Sections

```text
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

## Core Modules

The analyzer runs 11 core modules in sequence:

1. `dns` — current DNS resolution and DNS hardening checks
2. `whois` — registration intelligence via WhoisXML API with local WHOIS fallback
3. `dns_history` — historical DNS timeline from passive sources
4. `cdn` — CDN, WAF, hosting, and edge-protection detection; GEO & ASN data
5. `network` — connectivity, traceroute path analysis, and HTTP/S behavior probes
6. `subdomain` — DNS-based subdomain discovery with wildcard handling
7. `ssl` — TLS certificate inspection and protocol analysis
8. `securitytrails` — SecurityTrails domain intelligence
9. `abuseipdb` — IP reputation intelligence
10. `virustotal` — domain reputation and category intelligence
11. `ip_history` — reverse-IP lookup and co-hosted domain intelligence

## Testing

Run the focused suite:

```powershell
python -m pytest tests/test_dns_history_analyzer.py tests/test_result_aggregator.py tests/test_dns_analyzer.py
```

The test suite covers:

- DNS forensic helper behavior
- DNS history timeline sorting and deduplication
- load-balanced VirusTotal grouping
- result aggregation risk handling

## Security Notes

- Do not commit `config/api_keys.json`.
- Do not commit `.env`.
- Rotate API keys if they were pasted into logs, issues, chat, or commits.
- The analyzer is a mixed passive/active tool. External API and lookup providers observe queries; the target host observes active probes.
- The SSL/TLS module makes a direct TCP/TLS connection to port 443 on the target host.
- The HTTP/S behavior module makes real HTTP and HTTPS requests to the target host.

## Known Limitations

- Some WHOIS registries redact or omit registration fields.
- SecurityTrails and VirusTotal history depth depends on account access and provider coverage.
- Certificate Transparency provides certificate issuance history, not authoritative DNS history.
- Subdomain discovery is DNS-pattern based and becomes candidate-only under wildcard DNS.
- The risk model is heuristic and should support investigation, not replace analyst judgment.
- DNS history pattern analysis counts raw NS record entries rather than distinct migration events. Domains with 4+ nameservers that migrated once can incorrectly show "multiple nameserver changes" in the DNS History sub-risk. The top-level overall risk is not affected.

## Recent Major Updates

- **Report export** — after each scan, a structured JSON report and a raw console capture (with ANSI codes) are written to `reports/`. Scan IDs are sequential and stable across restarts. Export never interrupts the scan.
- **HTTP/S Behavior block** — new report block between NETWORK PATH and SSL/TLS; HTTP probe detects redirect to HTTPS; HTTPS probe follows redirect chain (up to 5 hops) and extracts Server header and HSTS policy; assessment: Strong / Moderate / Weak; risk flags for missing redirect and absent HSTS.
- **OPSEC Assessment corrected** — analysis type changed from "PASSIVE OSINT" to "MIXED - Passive APIs + Active Probes"; stealth level floor raised to MEDIUM unconditionally; Active Probes and Passive Sources listed explicitly in the OPSEC block.
- **SSL/TLS module** — direct TLS handshake to port 443; two-pass connection handles expired and self-signed certificates; extracts issuer, validity window, days to expiry, SANs, cert type, and TLS version; expiry and self-signed risk flags feed into the overall risk model.
- **Domain age risk flag** — newly registered domains (< 30 days) flagged HIGH; recently registered (30–90 days) flagged MEDIUM in the risk summary.
- **MX FQDN fix** — MX records now resolved via `dnspython` `dns.resolver.resolve()` giving full FQDNs; nslookup-based parsing removed.
- **Privacy proxy detection** — 12 known proxy services (WhoisGuard, Domains By Proxy, PrivacyProtect, and others) detected in WHOIS registrant fields.
- **crt.sh retry logic** — Certificate Transparency collection retries up to 3 times (max_retries=2, 1s backoff) before reporting failure.
- **CNAME records** — DNS FORENSICS block now includes CNAME when present; omitted for domains where none exists.
- **Reverse IP global limit** — co-hosted domains from all sources are merged and deduplicated before display; top 20 shown with per-entry source attribution; total count always visible.
- **GEO & ASN block** — report section after TARGET; shows country (ISO code + name), region, city, ASN number, ASN organisation, ISP, hosting type classification, and geographic risk. Data sourced from ip-api.com (no API key required).
- **CDN provider detection extended** — hostname-pattern matching pass added (takes priority over IP prefix); 6 new providers: Outscale (French Government Cloud), OVHcloud, Hetzner, IONOS/1&1, Deutsche Telekom (DTAG), Bundescloud/BWI. New infrastructure types: `gov-cloud`, `hosting`, `transit`.
- **IP & Domain History module** — reverse-IP lookup from VirusTotal, RobTex, and HackerTarget; domain IP history from passive DNS timeline; CDN-aware co-hosted domain display.
- **DNS History Timeline extended** — first seen date, current IP first seen with age label, NS/MX change events grouped by date, Certificate Transparency history block.
- **DNS Forensics extended** — TTL values on A/NS/MX records, SPF include chain recursive (depth ≤ 2), DMARC sp=/rua=/ruf= separately, CAA issuewild explicit, DKIM selectors expanded.
- **WHOIS registry policy awareness** — DENIC and 7 other redacting registries detected; "Not disclosed by registry" replaces silent Unknown.
- **CLI argument support** — `python run.py domain.com` skips interactive prompt.
- **List mode** — `python run.py --list domains.txt` runs all domains sequentially with a per-domain status summary table.
