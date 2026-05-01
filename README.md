# Domain Forensic Analyzer

Domain Forensic Analyzer is a terminal-based OSINT workflow for investigating a domain across DNS, WHOIS registration data, DNS history, infrastructure, network path, attack surface, and external threat-intelligence sources.

The project is currently CLI-first and report-focused. It is designed for defensive investigation, infrastructure review, and forensic triage of domain posture.

## Current Capabilities

The analyzer now runs 9 core modules in sequence:

1. `dns` - current DNS resolution and DNS hardening checks
2. `whois` - registration intelligence via WhoisXML API with local WHOIS fallback
3. `dns_history` - historical DNS timeline from passive sources
4. `cdn` - CDN, WAF, hosting, and edge-protection detection
5. `network` - connectivity and traceroute path analysis
6. `subdomain` - DNS-based subdomain discovery with wildcard handling
7. `securitytrails` - SecurityTrails domain intelligence
8. `abuseipdb` - IP reputation intelligence
9. `virustotal` - domain reputation and category intelligence

The final report includes:

- forensic session metadata and OPSEC context
- target DNS summary
- WHOIS registration summary
- DNS forensic posture
- DNS history timeline
- infrastructure/CDN/WAF assessment
- network path and traceroute details
- attack-surface findings
- threat-intelligence summary
- risk assessment and execution summary

## Quick Start

Install dependencies:

```powershell
pip install -r requirements.txt
```

Run the analyzer:

```powershell
python src/core/domain_analyzer.py
```

The tool prompts for a target domain and renders a terminal report.

## API Configuration

API keys can be provided through environment variables or local config files. Local secret files are intentionally git-ignored.

Supported environment variables:

```text
SECURITYTRAILS_API_KEY
ABUSEIPDB_API_KEY
VIRUSTOTAL_API_KEY
WHOISXML_API_KEY
```

The JSON config path is:

```text
config/api_keys.json
```

Example structure:

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

WhoisXML also supports the environment-first pattern used by the analyzer:

1. use `WHOISXML_API_KEY` if present
2. otherwise read `config/api_keys.json` under `whoisxml`
3. otherwise fall back to local `python-whois`

## Module Details

### DNS Forensics

`src/analyzers/dns_analyzer.py` collects current DNS state:

- A and AAAA records
- reverse DNS
- nameservers
- MX records
- SOA metadata
- TXT records
- SPF policy and enforcement mode
- DMARC policy and reporting
- heuristic DKIM selector discovery
- CAA policy
- DNSSEC detection
- zone-transfer testing
- DNS configuration assessment

The final report surfaces DNS hardening gaps such as soft-fail SPF, monitor-only DMARC, missing DMARC, absent DNSSEC, missing CAA, and zone-transfer exposure.

### WHOIS Registration

`src/analyzers/whois.py` provides registration intelligence:

- WhoisXML API support
- local `python-whois` fallback
- registrar
- creation, expiration, and updated dates
- registrant name, organization, country, and email when available
- nameserver extraction
- source attribution

Some registries, especially `.de`, may not expose all registration fields through API or local WHOIS. In those cases the report keeps unknown fields explicit instead of inventing data.

### DNS History Timeline

`src/analyzers/dns_history_analyzer.py` builds a normalized historical timeline.

Data sources:

- SecurityTrails DNS history endpoints
- VirusTotal domain resolutions
- Certificate Transparency through `crt.sh`
- native fallback when no external history is available

The DNS history report includes:

- data source attribution
- timeline span
- major change count
- recent historical events
- previous and new values where available
- change classification
- change-frequency assessment
- infrastructure-stability assessment
- suspicious-pattern detection
- historical risk events

Same-day load-balanced VirusTotal resolution sets are grouped so large providers such as Google are not incorrectly flagged as rapid DNS churn.

### Infrastructure Detection

`src/analyzers/cdn_detector.py` estimates:

- CDN and edge provider
- direct hosting versus CDN-backed infrastructure
- protection level
- WAF or edge-protection availability
- geolocation context

### Network Intelligence

`src/analyzers/network_intelligence.py` performs:

- ping reachability checks
- HTTP/HTTPS connectivity checks
- traceroute collection
- hop parsing
- RTT extraction
- partial traceroute handling
- timeout reporting
- hop classification

Partial routes are preserved in the report instead of being collapsed into generic failure output.

### Attack Surface

`src/analyzers/subdomain_scanner.py` performs DNS-based subdomain discovery and categorization.

The report distinguishes:

- standard-resolution domains: findings are shown as discovered subdomains
- wildcard DNS domains: findings are shown as candidates only

Wildcard DNS is treated as a semantic constraint, not automatically as a risk.

### Threat Intelligence

The analyzer integrates:

- SecurityTrails for domain intelligence and historical summary
- AbuseIPDB for IP reputation
- VirusTotal for domain reputation, categories, and resolutions
- WhoisXML for registration intelligence

The execution summary lists which live APIs were used in the run.

## Current Output Sections

Typical report sections:

```text
SUMMARY
TARGET
WHOIS REGISTRATION
DNS FORENSICS
DNS HISTORY TIMELINE
INFRASTRUCTURE
NETWORK PATH
ATTACK SURFACE
THREAT INTELLIGENCE
RISK ASSESSMENT
EXECUTION
```

## Project Structure

```text
config/                 Local configuration templates and settings
docs/                   Supplemental docs
src/analyzers/          Individual analyzer modules
src/config/             Runtime API config loader
src/core/               CLI orchestration and result aggregation
src/utils/              Colors, formatting, validators
tests/                  Pytest tests
```

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
- The analyzer performs passive OSINT-style collection, but external API and lookup providers can still observe queries.

## Known Limitations

- Some WHOIS registries redact or omit registration fields.
- SecurityTrails and VirusTotal history depth depends on account access and provider coverage.
- Certificate Transparency provides certificate issuance history, not authoritative DNS history.
- Subdomain discovery is DNS-pattern based and becomes candidate-only under wildcard DNS.
- The risk model is heuristic and should support investigation, not replace analyst judgment.

## Recent Major Updates

- Added WHOIS registration module with WhoisXML support.
- Added DNS forensics for SPF, DMARC, DKIM, CAA, DNSSEC, SOA, TXT, and zone transfer.
- Added DNS History Timeline module.
- Improved traceroute handling for partial and timeout cases.
- Improved VirusTotal category formatting.
- Added API config template support for WhoisXML.
- Cleaned test layout so active pytest tests live under `tests/`.
