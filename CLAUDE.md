# CLAUDE.md — Domain Forensic Analyzer

Developer context for Claude Code sessions. Keep this file up to date at the end of each session.

---

## Project Overview

Terminal-based domain OSINT tool. Runs 11 modules in sequence, renders a structured forensic report. Python 3, Windows-primary (PowerShell), venv at project root.

Entry point: `python run.py [domain]` — domain argument skips interactive prompt.

---

## Architecture

```
run.py                          Entry point (CLI arg support added)
src/core/domain_analyzer.py     Orchestrator, ThreadAwareStdoutRouter, display_forensic_summary()
src/core/report_exporter.py     JSON + raw TXT report export (ReportExporter, capture_console)
src/analyzers/
    dns_analyzer.py             DNS resolution + hardening checks
    whois.py                    WHOIS via WhoisXML API + python-whois fallback
    dns_history_analyzer.py     Historical DNS timeline (Mnemonic, RobTex, VT, crt.sh, SecurityTrails)
    cdn_detector.py             CDN/cloud/gov-cloud detection — IP prefix + hostname-pattern matching
    ip_history_analyzer.py      Reverse-IP lookup (VT, RobTex, HackerTarget)
    network_intelligence.py     Ping + traceroute + HTTP/S behavior
    ssl_analyzer.py             TLS certificate inspection (stdlib ssl + cryptography)
    subdomain_scanner.py        DNS-based subdomain discovery
    securitytrails_client.py    SecurityTrails domain intelligence
    abuseipdb_client.py         IP reputation
    virustotal_client.py        Domain reputation
src/utils/colors.py             Terminal color helpers
config/api_keys.json            API keys (git-ignored)
```

Module execution order: `dns → whois → dns_history → cdn → network → subdomain → ssl → securitytrails → abuseipdb → virustotal → ip_history`

---

## What Was Implemented (Session 2026-05-07 — part 2)

### 1. CLI Argument Support
**File:** `src/core/domain_analyzer.py` — `get_domain_input()` (~line 794)
- `python run.py freecash.com` now skips interactive prompt and starts scan directly
- Invalid argument prints error and exits with code 1

### 2. DNS History Timeline — Extended Report Block
**Files:** `src/analyzers/dns_history_analyzer.py`, `src/core/domain_analyzer.py`

New fields in the DNS HISTORY TIMELINE report block:
- `First Seen` — earliest date across all passive sources and WHOIS creation date
- `Current IP first seen` — age-labeled (relatively recent / established / long-standing)
- `NS Record Changes` — grouped by date as real migration events
- `MX Record Changes` — grouped by date as real migration events
- `Certificate History (crt.sh)` — certificate count + earliest/latest date

Bug fixes:
- CT events excluded from `_analyze_patterns()` — no more false "rapid DNS change pattern" for CDN domains
- `timeline_span` computed from ALL deduplicated events before the `[:60]` display limit
- Separate buckets `a_history`, `ns_history`, `mx_history`, `ct_history` returned by analyzer — CT events can no longer crowd out DNS events from the top-60 display window
- CDN anycast note appended to "not found in history" when CDN provider is detected
- `infrastructure_stability` label: "volatile" only when `monthly_rate >= 5`; established domains with historical migrations now get "moderately dynamic"

Key data structures added to `analyze_dns_history()` return dict:
```python
"a_history":  [...],   # all A/AAAA events, top 50 desc
"ns_history": [...],   # all NS events, chronological, top 30
"mx_history": [...],   # all MX events, chronological, top 30
"ct_history": [...],   # CT events, top 60 desc
"timeline":   [...],   # non-CT events only, top 60 desc (for Recent Events + pattern analysis)
```

### 3. IP & Domain History Module (new module)
**Files:** `src/analyzers/ip_history_analyzer.py` (new), `src/core/domain_analyzer.py`

- Reverse-IP lookup from 3 passive sources: VirusTotal `/ip_addresses/{ip}/resolutions`, RobTex `/ipquery/{ip}`, HackerTarget `/reverseiplookup/`
- Domain IP History extracted from dns_history A-events (deduped by IP, newest first)
- CDN branch: shows co-hosted domain sample with count
- Non-CDN branch: per-source breakdown
- Infrastructure assessment: dedicated / VPS / shared / CDN

### 4. DNS Forensics Block — Extended
**Files:** `src/analyzers/dns_analyzer.py`, `src/core/domain_analyzer.py`

New fields:
- TTL values on NS, MX, A records (`[TTL Xs]` suffix)
- Full NS and MX lists (sorted by priority for MX)
- SPF include chain recursive resolution with `_SPF_MAX_DEPTH = 2`
- DMARC `sp=`, `rua=`, `ruf=` stored and displayed separately
- DKIM: added `s1`, `smtp` to common selectors
- CAA: `issuewild` explicitly shown or "no issuewild restriction"
- Removed all `print()` statements from business logic

### 5. CDN Detector Fix
**File:** `src/analyzers/cdn_detector.py`

- Added Cloudflare IP ranges `104.24.` – `104.27.` (were missing, caused misidentification as Azure)
- Removed all `print()` statements from business logic

### 6. WHOIS Registry Policy Awareness
**Files:** `src/analyzers/whois.py`, `src/core/domain_analyzer.py`

- `REDACTING_REGISTRIES` dict covering: `.de` (DENIC), `.at` (nic.at), `.ch` (SWITCH), `.nl` (SIDN), `.fi` (Traficom), `.no` (Norid), `.se` (IIS), `.dk` (DK Hostmaster)
- `_detect_registry_policy(domain)` helper added
- `registry_policy` field added to both `get_whois_xmlapi()` and `get_whois_local()` result dicts
- Display: "Not disclosed by registry (DENIC policy)" instead of silent "Unknown"
- Display: "Registry Note" line at top of WHOIS block when policy applies

### 7. CDN Provider Detection — Extended
**File:** `src/analyzers/cdn_detector.py`

- Added `hostname_patterns` field to all provider entries
- New two-pass detection in `_detect_provider(ip, rdns_hostname=None)`:
  - Pass 1: hostname-pattern matching against rDNS (higher specificity, takes priority)
  - Pass 2: IP prefix `startswith()` (fallback)
- `analyze_infrastructure()` now accepts `rdns_hostname` parameter
- `domain_analyzer.py` CDN call-site passes `dns_result.get('reverse_dns')` through
- New provider types: `gov-cloud`, `hosting`, `transit` (added to `_format_provider_type()`)
- 6 new providers:

| Key | Name | Type | Primary signal |
|---|---|---|---|
| `outscale` | Outscale (French Government Cloud) | gov-cloud | hostname `outscale.com`, `cloudgouv`; IP `80.247.` |
| `ovhcloud` | OVHcloud | cloud | hostname `ovh.net`, `ovhcloud.com`; 12 IP prefixes |
| `hetzner` | Hetzner | hosting | hostname `your-server.de`, `hetzner.de`; 11 IP prefixes |
| `ionos` | IONOS / 1&1 | hosting | hostname `ionos.com`, `1und1.de`; 5 IP prefixes |
| `telekom_dtag` | Deutsche Telekom (DTAG) | transit | hostname `t-online.de`, `dtag.de`; 5 IP prefixes |
| `bundescloud` | Bundescloud / BWI | gov-cloud | hostname-only: `bund.de`, `bwi.de` |

### 8. GEO & ASN Report Block (new)
**Files:** `src/analyzers/cdn_detector.py`, `src/core/domain_analyzer.py`

New report block inserted after TARGET, before WHOIS REGISTRATION.

Data source: ip-api.com (free, no API key, 45 req/min). `countryCode` field added to existing request.
No second HTTP call — data already fetched by the CDN module (`cdn_result['geolocation']`, `cdn_result['asn_info']`).

Display fields:
- IP, Country (ISO code – name), Region, City
- ASN number, ASN Organisation (parsed from ip-api.com `as` field)
- ISP, Hosting Type, Geographic Risk

New helper functions in `domain_analyzer.py`:
- `_classify_hosting_type(cdn_result, domain)` — 4-stage classification:
  1. CDN provider type (`cdn`, `gov-cloud`, `cloud`, `hosting`, `transit`)
  2. TLD patterns (`.gov`, `.gv.at`, `.gouv.`, `.bund.de`, `.mil`, etc.)
  3. German federal domain name prefixes (`bundesregierung.`, `bundestag.`, `bundesamt`, etc.)
  4. Gov IT provider org/ISP strings (`conet deutschland`, `babiel`, `bundesrechenzentrum`, `dataport`, `brz gmbh`, `govix`)
  5. Education keywords → `Education`
  6. Cloud/hosting keywords → `Cloud`
  7. Fallback → `Commercial`
- `_get_geographic_risk(country_code)` — `HIGH` for CN/RU/KP/IR, `MEDIUM` for BY/SY/VE/CU/MM/SD/AF/IQ/LY/SO/YE, `LOW` otherwise

Tested: `ssi.gouv.fr` (Outscale/gov-cloud), `hetzner.com` (Hetzner/hosting), `bundesregierung.de` (Government via domain prefix + gov org), `cloudflare.com` (CDN), `kaspersky.ru` (Commercial in NL — correct, not RU).

---

## Current Report Block Order

```
SUMMARY
TARGET
GEO & ASN
WHOIS REGISTRATION
DNS FORENSICS
DNS HISTORY TIMELINE
NETWORK PATH
HTTP/S BEHAVIOR              ← new
SSL / TLS
INFRASTRUCTURE
ATTACK SURFACE
THREAT INTELLIGENCE
IP & DOMAIN HISTORY
RISK ASSESSMENT
EXECUTION
```

---

## What Was Implemented (Session 2026-05-07 — part 3)

### 9. OPSEC Assessment — Corrected
**File:** `src/core/domain_analyzer.py` — `assess_opsec_risk()`, `display_forensic_header()`

- `analysis_type` corrected from `"PASSIVE OSINT"` to `"MIXED - Passive APIs + Active Probes"`
- `stealth_level` floor raised to `MEDIUM` unconditionally — active probes always run; `LOW` was misleading
- VPN detection rewritten: rDNS lookup against known VPN provider hostnames instead of checking IP string
- New display sub-blocks added: **Active Probes** (6 entries) and **Passive Sources** (3 entries)

### 10. Domain Age Risk Flag
**File:** `src/core/domain_analyzer.py` — `_compute_risk_summary()`

- `creation_date` from WHOIS result now evaluated for recency
- < 30 days → `HIGH` risk + "Newly registered domain (N days old)"
- 30–90 days → `MEDIUM` risk + "Recently registered domain (N days old)"
- Uses `datetime.now(timezone.utc)` (stdlib, no new dependency)

### 11. MX FQDN Fix
**File:** `src/analyzers/dns_analyzer.py` — `_analyze_mx_records()`

- Replaced nslookup-based `_parse_mx_records()` with `dns.resolver.resolve(domain, 'MX')`
- `rdata.exchange` gives full FQDN; `.rstrip('.')` normalizes trailing dot
- Removed dead helpers: `_parse_mx_records()`, `_extract_mx_parts()`, `_deduplicate_mx_records()`
- Sort by `rdata.preference` replaces manual priority extraction

### 12. Privacy Proxy Detection
**Files:** `src/analyzers/whois.py`, `src/core/domain_analyzer.py`

- `_PRIVACY_PROXY_SIGNALS` list: 12 known proxy services (WhoisGuard, Domains By Proxy, PrivacyProtect, Withheld for Privacy, Perfect Privacy, Identity Protection Service, Contact Privacy, Data Protected, Redacted for Privacy, Privacy Guardian, Anonymize.com, Whois Privacy Protection)
- `_detect_privacy_proxy(registrar, registrant_email, registrant_name)` — searches combined haystack for known keywords
- `privacy_proxy` field added to both `get_whois_local()` and `get_whois_xmlapi()` result dicts
- Display: `├── Privacy Proxy: <name> detected` (warning color) inserted after Country, hidden when None

### 13. crt.sh Retry Logic
**File:** `src/analyzers/dns_history_analyzer.py` — `_collect_certificate_transparency()`

- `max_retries=2`, `backoff=1s` between attempts (3 total attempts)
- Uses `for/else` pattern: `else` block only fires when all attempts exhausted
- `last_error` preserved across attempts for accurate error reporting on final failure

---

## What Was Implemented (Session 2026-05-09 — part 3)

### 17. HTTP/S Behavior Block (new report block)
**Files:** `src/analyzers/network_intelligence.py`, `src/core/domain_analyzer.py`

- New method `_test_http_behavior(domain)` in `NetworkIntelligence`
- HTTP probe: `requests.get(allow_redirects=False)` — single hop, checks 301/302 redirect to HTTPS
- HTTPS probe: manual redirect following up to 5 hops, extracts `Server` and `Strict-Transport-Security` from final response
- `urllib3.disable_warnings()` suppresses InsecureRequestWarning (needed for `verify=False` on expired/self-signed certs)
- `requests` import added at module level in `network_intelligence.py`
- Result stored as `results['http_behavior']` in `analyze_network()`
- Display: new `HTTP/S BEHAVIOR` block inserted between NETWORK PATH and SSL/TLS
- HSTS display: shows `max-age=N; includeSubDomains` when present, "not configured" when absent
- Redirect Chain: `http://domain -> https://domain/ (N hop)` format
- Assessment labels: Strong (HTTPS + redirect + HSTS), Moderate (HTTPS + one of the two), Weak (HTTP without redirect)
- Port unreachable / timeout: single fallback line `not available (connection refused or timeout)`
- Risk flags in `_compute_risk_summary()`: "HTTP served without redirect to HTTPS" and "HSTS not configured" (both LOW-level factors, no overall_risk upgrade)

---

## What Was Implemented (Session 2026-05-09 — part 2)

### 16. SSL/TLS Module (new module)
**Files:** `src/analyzers/ssl_analyzer.py` (new), `src/core/domain_analyzer.py`, `requirements.txt`

- New dependency: `cryptography>=41.0.0` (v48 installed)
- Two-pass TLS connection: Pass 1 with hostname verification, Pass 2 without (expired/self-signed fallback)
- Timeout: 10s per attempt; graceful error returns for port 443 unreachable, timeout, SSL handshake failure
- Certificate parsing via `cryptography.x509.load_der_x509_certificate(cert_der)`
- Extracted fields: `issuer_org`, `issuer_cn`, `valid_from`, `valid_until`, `days_to_expiry`, `sans`, `has_wildcard`, `cert_type` (Wildcard/Multi-SAN/Single), `tls_version`, `self_signed`, `assessment`
- Display: inserted between NETWORK PATH and INFRASTRUCTURE; SANs capped at 10 with overflow line
- Risk flags in `_compute_risk_summary()`: expired → HIGH, <14d → HIGH, <30d → MEDIUM, self-signed → MEDIUM, deprecated TLS → factor added
- OPSEC block: SSL/TLS handshake added to Active Probes list
- Module order: `ssl` inserted after `subdomain` (last active probe before passive API modules)
- Module count: 10 → 11 (`[x/11]`)
- Issuer display: `org (cn)` format; falls back to whichever field is available

---

## What Was Implemented (Session 2026-05-09)

### 14. Reverse IP — Global Top-20 Limit
**Files:** `src/analyzers/ip_history_analyzer.py`, `src/core/domain_analyzer.py`

- `source` field added to each entry in the merged deduplicated list (attribution: VirusTotal / RobTex / HackerTarget)
- Display replaced: per-source loops removed; single combined list, top 20 non-CDN / top 5 CDN
- Header shows total count: `Reverse IP (1.2.3.4, showing top 20 of 674 total)`
- `... +N more` overflow line + `Total unique co-hosted: N` footer

### 15. CNAME Records
**Files:** `src/analyzers/dns_analyzer.py`, `src/core/domain_analyzer.py`

- New `_analyze_cname_record(domain)` method using `dns.resolver.resolve(domain, 'CNAME')`
- Graceful fallback: `NoAnswer`, `NXDOMAIN`, `NoNameservers`, `Timeout` all return `cname_target: None`
- Called in `analyze_domain()` alongside other record types; `cname_target: None` initial value in result dict
- Display: `├── CNAME: domain → target` inserted after A Record TTL line; line omitted entirely when `None`
- Root apex domains rarely have CNAME — only shown when present

---

## Coverage Stand (2026-05-09)

| Area | Coverage |
|------|----------|
| DNS | ~85% |
| IP / Hosting | ~95% |
| SSL / TLS | ~90% |
| HTTP/S | ~70% |
| WHOIS | ~90% |
| Reputation | ~80% |

---

## What Was Implemented (Session 2026-05-09 — report export)

### 19. JSON Report Export + Raw Console Capture
**Files:** `src/core/report_exporter.py` (new), `src/core/domain_analyzer.py`, `run.py`

- New module `src/core/report_exporter.py`:
  - `capture_console()` — context manager; tees `ThreadAwareStdoutRouter._target` into a `StringIO` buffer so worker-thread muting still fires first and only visible output is captured
  - `ReportExporter.export()` — silently swallows all exceptions; never interrupts the scan
  - `_next_scan_id(reports_dir)` — reads `reports/` for highest `NNNN_` prefix, returns next 4-digit ID
  - `_sanitize_filename(domain)` — replaces `<>:"/\|?*` and whitespace with `_`
  - `_SafeEncoder` — custom `json.JSONEncoder` that converts `datetime`/`date` → ISO string, `Enum` → `.value`, unknown types → `str()`

- `reports/raw/` created automatically by `ReportExporter._ensure_dirs()`
- Per-scan output files:
  - `reports/<NNNN>_<domain>.json` — structured payload: `scan_id`, `timestamp`, `domain`, `session_id`, `scan_duration_seconds`, `analyst` (IP, system, OPSEC), `result` (full `UnifiedResult.to_dict()`)
  - `reports/raw/<NNNN>_<domain>.txt` — exact captured console output (includes ANSI codes)
- `domain_analyzer.py main()` — wraps header + analysis + summary in `with capture_console()`, then calls `exporter.export()` after the context exits; export only runs when `result is not None`
- `run.py run_list_mode()` — same per domain; `domain_start = datetime.now()` captured before the loop body; `exporter.export()` called after `with` exits, inside existing try/except

---

## What Was Implemented (Session 2026-05-09 — final)

### 18. Risk Factor Ordering Fix
**File:** `src/core/domain_analyzer.py` — `_compute_risk_summary()`

- SSL/TLS risk block moved before HTTP/S block
- Certificate expiry now appears first in `risk_factors` list
- For expired domains: "Certificate expired N days ago" is now #1 in SUMMARY top-3, before "HSTS not configured"
- `overall_risk` logic unchanged; purely a display-ordering improvement

---

## What Was Implemented (Session 2026-05-10)

### 20. Bug Fixes: RobTex list crash + SecurityTrails encoding

**Bug #2 — RobTex returns bare `[]` for non-resolving domains**
**File:** `src/analyzers/dns_history_analyzer.py` — `_collect_robtex_history()` line ~182

- `json.loads(raw_line)` can return a `list` (e.g. `[]`) instead of a `dict` when RobTex has no PDNS data
- `entry.get("rrtype", "")` then crashed with `'list' object has no attribute 'get'`
- Fix: added `if not isinstance(entry, dict): continue` after the `json.loads()` call

**Bug #3 — Non-ASCII characters in SecurityTrails output**
**File:** `src/core/domain_analyzer.py` — `display_forensic_summary()` ~line 2173

- German text `'nicht verfügbar – Limit erreicht oder kein API Key'` and `'nicht verfügbar'` used `ü` (U+00FC) and `–` (en dash, U+2013) in print output
- Replaced with ASCII-safe English equivalents:
  - `'not available - quota exceeded or no API key'`
  - `'not available'`

### 21. Domain Input Normalization

**File:** `src/utils/validators.py` — `DomainValidator.preprocess_domain()`
**File:** `run.py` — `_parse_domain_list()`
**File:** `src/core/domain_analyzer.py` — `get_domain_input()`

- `preprocess_domain()` added to `DomainValidator`:
  - Reserved TLDs (RFC 2606/6761: `.invalid`, `.local`, `.test`, `.localhost`, `.example`) → skip with message
  - Any subdomain stripped to apex SLD.TLD (e.g. `aws.amazon.com` → `amazon.com`)
  - Compound ccTLDs (co.uk, com.au, etc.) → 3-label apex preserved (e.g. `bbc.co.uk` stays)
  - `COMPOUND_TLDS` set covers 18 common compound ccTLDs
- `_parse_domain_list()` in `run.py` now deduplicates after normalization
- `get_domain_input()` in `domain_analyzer.py` applies `preprocess_domain()` to both CLI arg and interactive input

### 22. Wildcard / Catch-All Risk Fix

**File:** `src/core/result_aggregator.py` — `_extract_and_standardize_assets_fixed()`
**File:** `src/analyzers/subdomain_scanner.py` — `_detect_wildcard()`

- Wildcard-detected subdomains capped at `informational` risk (was incorrectly `HIGH`)
- Wildcard detector updated to treat IP-pool catch-alls (random subdomains → different IPs) as wildcards
  - Any 2+ random probe subdomains resolving (whether to same or different IPs) = catch-all
  - Previously only single-IP wildcards were caught; IP-pool platforms (Vercel, Cloudflare, etc.) were missed

### 23. README Overhaul + .gitignore Update

**File:** `README.md` — complete rewrite
- Sections: Current Capabilities → Installation (git clone, venv, pip, API keys) → Usage → Program Structure → API Configuration → Module Details → Report Export → Current Output Sections → Core Modules → Testing → Security Notes → Known Limitations → Recent Major Updates

**File:** `.gitignore` — added block:
```
# Local user files — stay on this machine, never committed
domains.txt
validate_export.py
reports/
```

---

## Open Gaps / Known Issues

| Issue | File | Notes |
|-------|------|-------|
| `analysis_status` missing from whois fallback | `domain_analyzer.py` `_get_fallback_result()` | WHOIS fallback dict lacks `analysis_status: 'abgeschlossen'`. Low impact. |

---

## What Was Implemented (Session 2026-05-10 — part 2)

### 24. Linux tracepath Integration
**File:** `src/analyzers/network_intelligence.py` — `_perform_traceroute()`

- Restructured into Windows (`tracert`, line-by-line) and Linux (`tracepath`, `communicate()`) branches
- `_parse_tracepath_output()` — parses `tracepath` line format; returns hops with `hop`, `status` (`responsive`/`timeout`), `ip`, `hostname`, `latencies` fields
- Post-parse early-stopping: consecutive timeout hops ≥ `max_consecutive_no_response_hops` → truncate + `stopped_early=True`
- `stopped_early=True` → `status: 'partial'`; otherwise `status: 'success'`
- Removed `_try_tracepath_fallback()` — was blocking HTTP/S in same thread

**README:** Added Linux installation section with venv activation, optional `traceroute` note, `export` for API keys, `python3 run.py` usage.

### 26. SecurityTrails Quota Messaging (Priority 2)
**File:** `src/analyzers/securitytrails_client.py`

- `analysis_status: 'quota_exceeded'` returned instead of `'failed'` — orchestrator no longer marks module FAILED
- `response.status_code in (402, 429)` checked in all three endpoint methods (`_get_domain_info`, `_get_historical_dns_summary`, `_get_subdomains`)
- THREAT INTELLIGENCE block already had correct human-readable message; only progress line was wrong

### 27. NS Change Threshold Fix (Priority 3)
**File:** `src/analyzers/dns_history_analyzer.py` — `_analyze_patterns()`

- NS events grouped by date; distinct migration dates counted instead of raw record entries
- Threshold: `len(distinct_ns_dates) > 2` (was `raw_count >= 4`)
- A domain with 4 NS records set in a single migration day no longer fires "multiple nameserver changes"

### 28. CSP / X-Frame-Options (Priority 4)
**Files:** `src/analyzers/network_intelligence.py`, `src/core/domain_analyzer.py`

- `Content-Security-Policy` and `X-Frame-Options` extracted from final HTTPS response in `_test_http_behavior()`
- Added to `result` dict as `csp` (full value or None) and `x_frame_options` (uppercased value or None)
- HTTP/S BEHAVIOR display: `X-Frame-Options: DENY/SAMEORIGIN` (or "not set"), `Content-Security-Policy: present` (or "not configured")
- No risk flags added — purely informational display

---

## What Was Implemented (Session 2026-05-10 — part 3, testrun)

### 29. TLD Diversity Testrun Fixes

Domains tested: google.com, bundesregierung.de, bbc.co.uk, ssi.gouv.fr, expired.badssl.com (→ badssl.com), newdomain.xyz.

**Bug — module count mismatch (two-part fix):**
- `_count_execution_outcomes()` in `domain_analyzer.py`: added `quota_exceeded` and `skipped` to `_non_failure` set so they're not counted as failed
- `modules_successful` in `result_aggregator.py`: added same statuses to `_ok_statuses` so summary header and EXECUTION block both read 11/11 matching the done-line

**Bug — "small shared / VPS" with 1-2 co-hosted domains:**
`domain_analyzer.py` infrastructure label: threshold changed from `== 0` to `<= 2` for "dedicated / private". A domain with only www mapped to the same IP (bundesregierung.de) now correctly shows "dedicated / private".

**Bug — ssi.gouv.fr stripped to gouv.fr:**
`src/utils/validators.py` `COMPOUND_TLDS` expanded from 18 to ~50 entries. Added government/institutional namespace TLDs: `gouv.fr`, `gob.es/mx/ar/cl/pe`, `gov.au/br/in/sg/nz/za/il/it/pl/pt/gr/tr/ph/my`, `ac.jp/nz/za/in/id/il`, `edu.au/sg/br/pl`, `nhs.uk`, `police.uk`, `ne.jp`, `or.jp`.

**Bug — wildcard domain shows "(SENSITIVE)" in category breakdown:**
`domain_analyzer.py` attack surface block: Admin/API/Dev categories now show dim "(candidates)" when `wildcard_detected`, not red "(SENSITIVE)". Consistent with "Sensitive Candidates: 0" in summary header.

**Bug — redirect chain shows `:443` explicitly:**
`domain_analyzer.py` redirect chain display: `_strip_default_port()` helper strips `:443` from https:// and `:80` from http:// URLs before display. Purely cosmetic normalization.

---

## What Was Implemented (Session 2026-05-10 — CT fallback chain)

### 30. CT-Logs Fallback Chain (crt.sh → CertSpotter)
**File:** `src/analyzers/dns_history_analyzer.py`

- Replaced single `_collect_certificate_transparency()` with three-method chain:
  - `_collect_crtsh(domain)` — renamed from original; label `"crt.sh"`; query `%.{domain}` with `output=json`; `max_retries=2`, 1 s backoff; returns `{status, label, events}`
  - `_collect_certspotter(domain)` — new; `GET https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names`; no API key; same retry pattern; returns `{status, label, events}`
  - `_collect_certificate_transparency(domain)` — orchestrator: tries crt.sh first; falls back to CertSpotter if `status != "success"`; if both fail, returns `{status: "failed", events: [], ct_metadata: None}`
- `ct_metadata` dict added to successful result:
  ```python
  {"count": N, "source_label": "crt.sh"|"CertSpotter", "earliest": "YYYY-MM-DD", "latest": "YYYY-MM-DD", "subdomains": [...]}
  ```
- Subdomain extraction: strips apex itself and wildcard-only names (`*.domain.com` → apex after `lstrip("*.")` → skipped); only specific per-subdomain SAN certs produce entries in `subdomains`
- `analyze_dns_history()` propagates `ct_metadata` in its return dict
- **Wildcard cert limitation**: domains issuing only `*.domain.com` produce no subdomain entries — this is expected and correct (CT cannot reveal subdomain enumeration from wildcard certs)

**File:** `src/core/domain_analyzer.py` — CT display block

- Replaced hardcoded "crt.sh" label with dynamic `ct_metadata`-driven rendering:
  - `source_label` from `ct_metadata` shown in `Certificate History (source)` header
  - `Subdomains via CT:` line appears only when specific SANs present
  - Falls back to legacy `ct_history` list path when `ct_metadata` is absent
  - `not available (all sources failed)` when both sources fail

**Tested domains:** bundesregierung.de (crt.sh primary), discord.com (CertSpotter fallback), heise.de (CertSpotter fallback). Dynamic source labels confirmed in "Data Sources" and "Live APIs" lines.

---

## What Was Implemented (Session 2026-05-11)

### 31. Mnemonic Passive DNS Integration
**File:** `src/analyzers/dns_history_analyzer.py` — `_collect_mnemonic_history()`

- New source added to `analyze_dns_history()` source pipeline: runs always, no API key required
- Endpoint: `GET https://api.mnemonic.no/pdns/v3/{domain}?limit=1000`
- Provider: Norwegian CERT (mnemonic.no) — established, trusted passive DNS operator
- Single request returns all record types (A, AAAA, MX, CNAME, PTR); timestamps in milliseconds → `/1000` before `_normalize_timestamp()`
- Unauthenticated limits: 10 req/min, 1 000 req/day — well within single-scan budget (1 call)
- 429 → `quota_exceeded`; 404 → `failed`; same status semantics as all other sources
- Events feed into existing deduplication and bucket logic unchanged
- Tested: bundesregierung.de → 22 events, A-records with correct timestamps

**Evaluated but rejected:**
- `domscan.net /v1/dns/history` — beta endpoint, only stores data from prior API lookups (no external PDNS database); useless for first-time domain queries
- `dnshistory.org` scraping — deep data but HTML-dependent; fragile and maintainability risk

### 32. README — Operational Security Section
**File:** `README.md`

- **Zero-config mode** paragraph added under Usage: explains that the tool works without any API keys (~70% of report from active probes + free APIs)
- **Reducing your footprint (VPN routing)** subsection added under Security Notes: recommends VPN at OS level

---

## What Was Implemented (Session 2026-05-12)

### 33. REQ-001 — Filename / File-Path Rejection
**File:** `src/utils/validators.py` — `DomainValidator.preprocess_domain()`

New class variable `_FILE_EXTENSIONS` (frozenset) covering: `txt`, `pdf`, `csv`, `json`, `log`, `py`, `xlsx`, `docx`, `xml`, `yaml`, `yml`, `ini`, `cfg`, `bat`, `exe`. `.sh` (Saint Helena ccTLD) and `.md` (Moldova ccTLD) intentionally excluded.

Three structural checks added at the top of `preprocess_domain()`, before any other processing:
- **Backslash in cleaned input** → `"Error: '...' does not look like a domain name."` (catches UNC paths / Windows paths)
- **No dot in cleaned input** → same error (catches bare single-word input like `google`)
- **Last label in `_FILE_EXTENSIONS`** → same error; `.txt` input additionally gets `"\n  Did you mean: python run.py --list <file>"`

Fix applied to `get_domain_input()` in `domain_analyzer.py` line ~861: changed `print(f"Error: {msg}")` → `print(msg)` so rejection messages (which already start with "Error:") don't get a double prefix.

### 34. REQ-002 — IDN / Punycode Conversion
**File:** `src/utils/validators.py` — `DomainValidator._to_punycode()` (new) + `preprocess_domain()`

New static method `_to_punycode(domain)`:
- Primary: `domain.encode('idna').decode('ascii')` — handles full domain string
- Fallback: label-by-label encoding for mixed/edge cases
- Returns `None` on failure (invalid Unicode labels)

Conversion inserted after file-extension checks, before reserved-TLD check:
```python
try:
    cleaned.encode('ascii')
except UnicodeEncodeError:
    converted = DomainValidator._to_punycode(cleaned)
    if converted is None:
        return None, f"Skipping '{raw_display}': invalid internationalized domain name"
    cleaned = converted
```

Tested: `münchen.de` → `xn--mnchen-3ya.de`, `café.fr` → `xn--caf-dma.fr`, `sub.münchen.de` → strips to `xn--mnchen-3ya.de`.

### 37. REQ-003 — Historical Fallback for Inactive / Expired Domains
**File:** `src/core/domain_analyzer.py`

New helper `DomainAnalyzer._get_historical_fallback_ip()`:
- Reads `self.current_analysis['results']['dns_history']['a_history']`
- Returns `(ip, date_str)` of the most recent IPv4 A-record event (newest-first list)
- Returns `(None, None)` when no A-history exists

`_call_module_function()` changes:
- **`cdn` branch**: when `ip_address is None` after all existing checks, calls `_get_historical_fallback_ip()` and stores result in `dns_result['historical_fallback_ip']` / `['historical_fallback_date']`
- **`abuseipdb` branch**: reads `dns_result.get('historical_fallback_ip')` as final fallback (uses cached value from cdn branch — cdn always runs first)
- **`ip_history` branch**: same cached-value pattern

`display_forensic_summary()` changes:
- Three variables added near top: `hist_ip`, `hist_date`, `is_historical`
- **TARGET block**: when `ip is None` and `is_historical`, shows `├── IPv4: not currently resolving`, `├── Status: HISTORICAL ANALYSIS (domain inactive)`, `├── Last Known IP: X.X.X.X (last seen YYYY-MM-DD)`
- **GEO & ASN block**: IP line shows historical IP with `(historical)` qualifier; last line adds `Note: IP-based data from last known IP (X.X.X.X, ~YYYY-MM)` in historical mode
- **THREAT INTELLIGENCE**: `IP Reputation:` line appends `(historical IP)` qualifier in historical mode
- **IP & DOMAIN HISTORY / Reverse IP**: uses `current_ip or hist_ip` as effective IP; adds `historical` qualifier to header; Assessment line appends `(historical data)` in historical mode

Tested with `securecloud4you.com` (user's former domain, expired since ~2021):
- Most recent historical IP: `77.111.240.167` (2021-02-16)
- CDN/AbuseIPDB/ip_history now run with this IP instead of FAILING
- TARGET block shows HISTORICAL ANALYSIS status clearly

### 36. REQ-005 — IP Address Rejection
**File:** `src/utils/validators.py` — `DomainValidator.preprocess_domain()`

Added check before subdomain-stripping logic:
```python
if all(label.isdigit() for label in cleaned.split('.')):
    return None, f"Error: '{raw_display}' is an IP address, not a domain name."
```
- `192.168.0.1` → rejected immediately with clear error
- `8.8.8.8` → rejected
- `1and1.de`, `123.com` → pass (non-numeric labels present)

Previously: `192.168.0.1` was silently stripped to `0.1` and scanned as a domain (11-second wasted scan).

### 35. REQ-004 — Batch JSON Output (single file per --list run)
**File:** `src/core/report_exporter.py`

New helper `_next_batch_id(batch_dir)`: reads `BATCH_NNNN_` prefixes in `reports/batch/`, returns next ID string e.g. `"BATCH_0002"`.

New method `ReportExporter._ensure_batch_dir()`: creates `reports/` and `reports/batch/`.

New method `ReportExporter.export_batch(source_file, scan_records, list_start, total_duration_seconds)`:
- Writes `reports/batch/BATCH_NNNN_<listname>.json`
- Payload: `batch_id`, `timestamp`, `source_file`, `total_domains`, `completed`, `failed`, `duration_seconds`, `summary` (risk_distribution + domain rows), `scans` (full result dicts)
- `_ensure_batch_dir()` called; never raises

**File:** `run.py` — `run_list_mode()`

- `batch_records` list collects one dict per domain: `{domain, status, duration_s, risk, forensic_metadata, result}`
- Per-domain `exporter.export()` call removed — batch mode only writes to `reports/batch/`
- After overall summary printed: `exporter.export_batch(...)` called once
- `elapsed` now stored as float (`time.monotonic() - t0`) for accurate `duration_s` in JSON; cast to `int` only for display

**Directory layout:**
```
reports/
  0012_google.com.json        ← single-domain scan (unchanged)
  batch/
    BATCH_0001_domains.json   ← complete batch run
```

---

## What Was Implemented (Session 2026-05-12 — continued)

### 36. REQ-003 — Historical Display for Inactive Domains (final)

**File:** `src/core/domain_analyzer.py`

New function `_display_historical_blocks()` inserted before `display_forensic_summary()`:
- Shows compact report for inactive/expired domains (no current DNS resolution)
- Blocks shown: DNS HISTORY TIMELINE (full), IP & DOMAIN HISTORY (historical IPs only),
  THREAT INTELLIGENCE (VT domain reputation only), RISK ASSESSMENT, EXECUTION
- Blocks skipped: GEO & ASN, WHOIS, DNS FORENSICS, NETWORK PATH, HTTP/S, SSL/TLS,
  INFRASTRUCTURE, ATTACK SURFACE — eliminates the FAILED/UNAVAILABLE cascade
- EXECUTION block shows `Mode: HISTORICAL ANALYSIS (domain inactive — current DNS resolution failed)`

Early return in `display_forensic_summary()` after TARGET block:
```python
if is_historical:
    _display_historical_blocks(...)
    return
```

`is_historical` detection:
```python
hist_ip = None   # first IPv4 from dns_history.a_history
is_historical = bool(hist_ip and not dns_result.get('ipv4'))
```

Tested: `securecloud4you.com` — clean 7-block report, no noise.

### 37. Windows UTF-8 Console Fix

**File:** `run.py`

Added at startup (after `sys.path.insert`):
```python
import io
if isinstance(sys.stdout, io.TextIOWrapper):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if isinstance(sys.stderr, io.TextIOWrapper):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
```

Fixes `UnicodeEncodeError: 'charmap' codec can't encode characters` for `├──` box-drawing
characters on Windows consoles using cp1252 (default). Type-safe via `isinstance` check.

---

## What Was Implemented (Session 2026-05-12 — consistency review)

Full codebase review by multi-agent audit. 15 findings, 10 fixed, 2 false positives, 3 deferred.

### 38. Consistency Review Fixes

**Files:** `src/core/domain_analyzer.py`, `src/core/result_aggregator.py`, `src/analyzers/whois.py`, `src/analyzers/dns_history_analyzer.py`, `src/analyzers/cdn_detector.py`, `src/utils/validators.py`

| ID | Severity | Fix |
|----|----------|-----|
| C-1 | CRITICAL | `domain` → `result.domain` in CNAME display line — was NameError on any domain with CNAME |
| H-2 | HIGH | Module count `'9 Core Analyzers'` → `'11 Core Analyzers'` in forensic header |
| H-3 | HIGH | Added Mnemonic PDNS + CertSpotter to Passive Sources display in OPSEC header |
| H-4 | HIGH | `w.last_updated` → `w.updated_date` in `whois.py` — `last_updated` doesn't exist in python-whois; updated_date was always None |
| H-5 | HIGH | Deleted dead `SECURITYTRAILS_API_KEY` / `VIRUSTOTAL_API_KEY` module-globals from `whois.py` |
| M-2 | MEDIUM | Domain IP History in `display_forensic_summary()`: reads `a_history` (not `timeline`) — `timeline` is capped at 60 mixed events and was missing A-records crowded out by NS/MX |
| M-3 | MEDIUM | `result_aggregator.py`: `cdn_result.get('provider_type')` → `cdn_result.get('infrastructure_type')` — CDN module writes `infrastructure_type`, not `provider_type`; was always `'Unknown'` |
| M-5 | MEDIUM | Deleted dead `_deduplicate_and_sort_events()` in `dns_history_analyzer.py` — never called |
| L-1 | LOW | Deleted dead `extract_domains_from_text()` in `validators.py` — broken regex reconstruction, no callers |
| L-3 | LOW | Deleted dead `classify_infrastructure_type()` + `get_security_assessment()` in `cdn_detector.py` |

**Confirmed false positives (not fixed):**
- H-1: REQ-003 historical fallback — correctly handled via `_display_historical_blocks()` display-layer, not module-injection (by design)
- M-6: WHOIS `analysis_status` in error path — orchestrator (`_call_module_function()`) sets it explicitly at line 463; individual analyzer doesn't need to

**Deferred (low/no runtime impact):**
- M-1: ~~DNS HISTORY TIMELINE ~170 lines duplicated~~ — **DONE (Session 2026-05-13)**: extracted to `_render_dns_history_block()` at line 1418; ~280 lines removed
- M-4: `supported_modules` in `result_aggregator.py` lists 7 instead of 11 — attribute is unused at runtime
- L-2: `print()` calls in `network_intelligence.py` / `subdomain_scanner.py` business logic — suppressed by thread muting, no visible effect

---

## What Was Implemented (Session 2026-05-13)

### 39. DNS HISTORY TIMELINE Refactor (M-1 — deduplication)
**File:** `src/core/domain_analyzer.py`

- New helper `_render_dns_history_block(dns_history_result, whois_result, dns_result, cdn_result)` at line 1418
- Replaced ~120-line block in `_display_historical_blocks()` + ~169-line block in `display_forensic_summary()` with two single-line calls
- ~280 duplicate lines removed; historical mode auto-skips "Current IP first seen" because `dns_result.get('ipv4')` is None
- Minor fix: Block 1 had a slightly incorrect connector calculation (`min(3, len-1)`), now uses correct `len(visible_ns) - 1` from Block 2

---

## What Was Implemented (Session 2026-05-14)

### 40. Tests + Code Quality Quick Wins

**Tests completed:**

| Test | Domain | Result |
|------|--------|--------|
| Domain age risk flag (< 30 days) | `convertwithai.tech`, `vigorcoffe.com` | ✓ "Newly registered domain (2 days old)" → HIGH in SUMMARY |
| Subdomains via CT display path | `letsencrypt.org`, `mozilla.org`, `apache.org`, `github.com`, `wikimedia.org` | Feature confirmed working by code review; all test domains use wildcard certs so path is untriggerable with major orgs — by design (wildcard certs do not expose subdomain enumeration) |

**Code quality fixes (Q-1, Q-2, Q-5, Q-7, Q-8, Q-9):**

- **Q-1** — Removed dead `from src.core.security_manager import create_security_manager` import; deleted `src/core/security_manager.py` (382 lines)
- **Q-2** — Removed duplicate `import socket` inside VPN-detection block; top-level import sufficient
- **Q-5** — Extracted 11 module timeouts to `MODULE_TIMEOUTS` in `config/settings.py`; `DomainAnalyzer.__init__` does `dict(MODULE_TIMEOUTS)`
- **Q-7** — WHOIS branch in `_call_module_function()` now raises `Exception` on error instead of setting `analysis_status` inline; consistent with all other modules
- **Q-8** — Extracted `_compute_execution_statistics(modules_to_run)` from `_execute_analysis_workflow()`; returns `(successful, failed, timeout, skipped, api_success, api_total)`; workflow method 15 lines shorter
- **Q-9a** — Replaced 47-line 4-stage fallback key search with `subdomain_result.get('discovered_assets') or []`
- **Q-9b** — Extracted `_infer_risk_level(subdomain_name)` and `_build_risk_lookup(sensitive_assets)` as static methods; `_extract_and_standardize_assets_fixed()` reduced from 85 → 35 lines

**Skipped with reasoning:**

- **Q-3** — MX function has unique priority-formatting and domain-completion logic; generic merge would require 5+ params — worse than two focused functions
- **Q-4** — Only 2 `_format_whois_*` functions exist (not 4); both are distinct — no merge warranted
- **Q-6** — Not actual duplication: `_compute_risk_summary()` evaluates 7 cross-module signals for overall domain risk; `result_aggregator.py` infers per-asset risk from subdomain name only — different scales and purposes

---

## Code Quality Scan — Session 2026-05-13

Full codebase scan (12 files, ~12 000 lines). 12 findings. Quick wins (Q-1–Q-5) addressed 2026-05-14.

### SOFORT SINNVOLL (Niedrig Aufwand + Niedrig Risiko)

| ID | Status | Datei | Beschreibung |
|----|--------|-------|--------------|
| Q-1 | ✓ DONE | `domain_analyzer.py` | Dead import + `security_manager.py` gelöscht |
| Q-2 | ✓ DONE | `domain_analyzer.py` | Doppelter `import socket` entfernt |
| Q-3 | — SKIP | `domain_analyzer.py` | MX-Funktion zu komplex für generischen Merge — würde Code verschlechtern |
| Q-4 | — SKIP | `domain_analyzer.py` | Nur 2 statt 4 `_format_whois_*` vorhanden; beide inhaltlich verschieden |
| Q-5 | ✓ DONE | `domain_analyzer.py` + `config/settings.py` | `MODULE_TIMEOUTS` nach `config/settings.py` ausgelagert |

### MITTELFRISTIG (Mittel Aufwand, klarer Mehrwert)

| ID | Status | Datei | Beschreibung |
|----|--------|-------|--------------|
| Q-6 | — SKIP | `domain_analyzer.py` + `result_aggregator.py` | Kein echter Duplikat — verschiedene Risiko-Ebenen (Domain vs. Asset) |
| Q-7 | ✓ DONE | `domain_analyzer.py` | WHOIS wirft Exception bei Fehler — konsistent mit anderen Modulen |
| Q-8 | ✓ DONE | `domain_analyzer.py` | `_compute_execution_statistics()` extrahiert |
| Q-9 | ✓ DONE | `result_aggregator.py` | Dead fallbacks entfernt; `_infer_risk_level()` + `_build_risk_lookup()` extrahiert |

### FINGER WEG (Hohes Risiko oder fraglicher Wert)

| ID | Datei | Beschreibung | Grund |
|----|-------|--------------|-------|
| Q-10 | `domain_analyzer.py` | LOGURU Fallback (~21–25, ~155–173) — `else`-Branch ist NOOP | Komplexe Laufzeitkopplung; Nutzen minimal |
| Q-11 | Alle Analyzer + `domain_analyzer.py` | Deutsch/Englisch-Mix in Status-Codes (`'abgeschlossen'`, `'fehlgeschlagen'`, `'failed'`) | Riesiger Scope (20+ Stellen), hohes Regressionsrisiko; separates Projekt |
| Q-12 | `domain_analyzer.py` | Split 3060-line monolith → 6 files (stdout_router, domain_analyzer, metadata, display_helpers, display, cli) | **PLANNED** — see §42 for full plan; required for v1.0.0 |

---

## What Was Implemented (Session 2026-05-14 — part 2)

### 41. Pre-release Bug Fixes + Code Hygiene

**Commits:** `0498ee3`, `67f2faa`

- **`import json` missing** in `dns_history_analyzer.py` → `NameError` in `_collect_robtex_history()` on every scan; `DNS History: UNAVAILABLE`
- **Flat-format `api_keys.json`** support added to `api_config.py` `_load_configurations()` — now accepts both `{"service": "key"}` and `{"service": {"api_key": "key"}}` formats; old code crashed with `AttributeError: 'str' object has no attribute 'get'` → silent module init failure → Demo Mode for all API clients
- **`.env` placeholder override** bug traced and documented: `whois.py` calls `load_dotenv()` at module level; if `.env` contains placeholder values (e.g. `VIRUSTOTAL_API_KEY=your_key_here`), they override real keys in `api_keys.json` via `os.getenv()`. Fixed by clearing placeholder lines from `.env`.
- **`[Demo-Mode]` → `[Demo Mode]`** label normalised in display code (4 occurrences)
- **Code hygiene commit** (`0498ee3`): removed print() bleed from `network_intelligence.py` + `subdomain_scanner.py`; stale `APIConfig` from `config/__init__.py.__all__`; German docstrings cleaned across 9 files; pylint score 9.06 → 9.11/10
- **Remaining unstaged files** (line-ending normalisation + code hygiene): committed in same session

### 42. Q-12 — domain_analyzer.py Monolith Split (PLANNED, next session)

**Current state:** `src/core/domain_analyzer.py` is 3060 lines — unmaintainable.

**Planned split into 6 files:**

| File | ~Lines | Contents |
|------|--------|----------|
| `src/core/stdout_router.py` | 40 | `ModuleExecutionResult`, `ThreadAwareStdoutRouter` |
| `src/core/domain_analyzer.py` | 650 | `DomainAnalyzer` class only (unchanged logic) |
| `src/core/metadata.py` | 100 | `get_external_ip`, `get_local_ip`, `get_system_metadata`, `assess_opsec_risk` |
| `src/core/display_helpers.py` | 580 | `_compute_risk_summary` + 20 small format/extract helpers (L971–L1617) |
| `src/core/display.py` | 1400 | `display_forensic_header`, `_render_dns_history_block`, `_display_historical_blocks`, `display_forensic_summary` (L820–L3010) |
| `src/core/cli.py` | 100 | `get_domain_input`, `main` |

**Dependency chain (no cycles):**
```
stdout_router.py    ← no local deps
metadata.py         ← Colors only
display_helpers.py  ← Colors, DomainValidator
display.py          ← display_helpers, metadata, Colors
cli.py              ← DomainAnalyzer, display, display_helpers
domain_analyzer.py  ← stdout_router only
```

**`run.py` import changes required:**
```python
# Before (all from domain_analyzer):
from src.core.domain_analyzer import (DomainAnalyzer,
    _compute_risk_summary, display_forensic_header,
    display_forensic_summary)
from src.core.domain_analyzer import main as single_main

# After:
from src.core.domain_analyzer import DomainAnalyzer
from src.core.display_helpers import _compute_risk_summary
from src.core.display import display_forensic_header, display_forensic_summary
from src.core.cli import main as single_main
```

**Line ranges for extraction (verified via AST):**
- `ModuleExecutionResult`: L63–70, `ThreadAwareStdoutRouter`: L73–97
- `DomainAnalyzer`: L104–718
- metadata functions: L721–817
- `display_forensic_header`: L820–925
- `get_domain_input`: L928–968
- `_compute_risk_summary` + helpers: L971–L1617
- `_render_dns_history_block`, `_display_historical_blocks`, `display_forensic_summary`: L1620–L3010
- `main`: L3013–L3056

**After split:** run full scan (e.g. `python run.py earnlab.com`) to verify before tagging v1.0.0.

---

## What Was Implemented (Session 2026-06-04)

### 43. Q-12 — domain_analyzer.py Split COMPLETE

**Commit:** `755fe6c` on branch `refactor/split-domain-analyzer`
**Tag:** `v1.0.1` (v1.0.0 was set prematurely on 2026-05-14 before split)

`src/core/` now contains 7 focused modules:

| File | Lines | Contents |
|------|-------|----------|
| `stdout_router.py` | 48 | `ModuleExecutionResult`, `ThreadAwareStdoutRouter`, `sys.stdout` init |
| `metadata.py` | 97 | `get_external_ip`, `get_local_ip`, `get_system_metadata`, `assess_opsec_risk` |
| `cli.py` | 101 | `get_domain_input`, `main` |
| `result_formatter.py` | 2315 | All display/render functions + `display_forensic_header` |
| `domain_analyzer.py` | 674 | `DomainAnalyzer` class only |
| `result_aggregator.py` | 556 | (unchanged) |
| `report_exporter.py` | 338 | (unchanged) |

**Fixed during split:** `platform` and `threading` imports were missing from `domain_analyzer.py` after extraction — caught by full-scan test.

**Verified:** Full `python run.py example.com` scan — 10/11 modules successful.

---

## What Was Implemented (Session 2026-06-04 — Release Pipeline)

### RELEASE_V1_0_0_ROADMAP.md — Phasen 1–4 (Teil 1)

Alle Commits auf `main`. Aktiver Branch beim Session-Ende: `feature/phase-4-validation` (gepusht, noch nicht gemergt).

#### Phase 1 — Test-Suite ✅ COMPLETE (gemergt in main)
- 291 Tests, 70% Coverage
- 14 neue Test-Dateien in `tests/`
- `pytest.ini`, `conftest.py`, `.coveragerc`, `pytest-cov` in requirements.txt
- Commit: `521dfe9` auf `feature/phase-1-test-suite` → in main gemergt

#### Phase 2 — CI/CD Pipeline ✅ COMPLETE (gemergt in main)
- `.github/workflows/test.yml`: Matrix Python 3.10/3.11/3.12 × Ubuntu/Windows
- `pylint src/ --fail-under=8.0` als separater Job
- Coverage-Artifact-Upload, `--cov-fail-under=70`
- README-Badges: Tests, Python, Coverage, Pylint
- Commit: `bc627a7` auf `feature/phase-2-cicd` → in main gemergt

#### Phase 3 — Packaging ✅ COMPLETE (gemergt in main)
- `pyproject.toml`: setuptools, version=1.0.0, alle 7 deps, `dfa` Entry-Point
- `src/__init__.py`: `__version__` von `"3.4"` → `"1.0.0"` korrigiert
- `CHANGELOG.md`: v1.0.0 Highlights + Known Limitations
- `pip install -e .` verifiziert: `domain-forensic-analyzer 1.0.0`
- Commit: `ccddc44` auf `feature/phase-3-packaging` → in main gemergt

#### Phase 4 — Cross-Platform OPSEC Validation ⏳ IN PROGRESS
**Branch:** `feature/phase-4-validation` (gepusht, noch **nicht** in main gemergt)
**Aktueller HEAD:** `66fd8f9`

**Deliverables erstellt:**
- `docs/scenario_a.sh` — Linux + Direktverbindung
- `docs/scenario_b.sh` — Linux + VPN (NL/DE/AT)
- `docs/scenario_c.bat` — Windows + Direktverbindung
- `docs/scenario_d.bat` — Windows + VPN (AT/CH/DE)
- `docs/README_PHASE4_MANUAL.md`, `docs/VALIDATION_REPORT_TEMPLATE.md`
- `docs/examples/` — Zielverzeichnis für JSON-Reports

**VPN-Fixes (Session 2026-06-07/08) — alle auf diesem Branch:**

| Commit | Fix |
|--------|-----|
| `442fbe4` | `is_historical` false positive + AXFR socket timeout + dns_timeout 10→5s |
| `e62d9e7` | DNS-Nameserver-Probe: filtert geblockte DNS-Server aus (ProtonVPN-Fix) |
| `66fd8f9` | OPSEC-Terminologie: `Proxy/VPN: Not Detected` → `VPN/Proxy Signals: No known provider signatures observed` |

**Root Cause VPN-Fix (dokumentiert):**
dnspython liest auf Windows ALLE Adapter-DNS aus der Registry (physischer Adapter + VPN-Adapter).
ProtonVPN blockt Port 53 zu physischem Adapter (192.168.0.1 = Router-DNS → dropped).
Fix: `_probe_nameservers()` in `DNSAnalyzer.__init__` prüft jeden NS per TCP-Port-53-Connect (1s timeout).
Reachable = TCP-connect oder RST. Blocked = timeout. Nur reachable NS werden verwendet.

**Verifiziert:**
- Windows + kein VPN: 11/11, 57s
- Windows + ProtonVPN USA: 11/11, 68s  (war: 6/11 TIMEOUT)
- Windows + ProtonVPN Norwegen: 11/11, 31s  (war: 6/11 TIMEOUT)

**Noch ausstehend:**
1. User pullt Branch auf Linux-Server
2. `bash docs/scenario_a.sh` (Linux + kein VPN) → `docs/examples/scenario_a_linux_direct.json`
3. `bash docs/scenario_b.sh` (Linux + VPN) → `docs/examples/scenario_b_linux_vpn.json`
4. Windows-Scans: `docs\scenario_c.bat` + `docs\scenario_d.bat`
5. Agent liest alle 4 JSON-Reports → füllt `docs/VALIDATION_REPORT.md`
6. PR `feature/phase-4-validation` → `main` mergen

---

## What Was Implemented (Session 2026-06-08)

### 44. VPN-Kompatibilität — DNS-Nameserver-Probe
**File:** `src/analyzers/dns_analyzer.py` — `DNSAnalyzer.__init__`, `_probe_nameservers()`, `_create_resolver()`

- `_probe_nameservers()`: TCP-Port-53-Connect mit 1s Timeout pro Kandidat; filtert geblockte Server aus
- `_create_resolver()`: `resolver.timeout=2` (per-server) getrennt von `resolver.lifetime=dns_timeout` (total budget)
- Ergebnis: Bei aktivem VPN schlägt jede Query sofort zum VPN-DNS durch statt alle anderen zu probieren

### 45. `is_historical` False Positive unter VPN
**File:** `src/core/result_formatter.py` — `_build_display_context()`

```python
# Vorher — triggerte bei DNS-Timeout (VPN) fälschlicherweise:
is_historical = bool(hist_ip and not dns_result.get("ipv4"))

# Nachher — unterscheidet Netzwerkfehler von echtem Domain-inaktiv:
dns_module_network_failure = dns_result.get("failure_type") in ("timeout", "error")
is_historical = bool(hist_ip and not dns_result.get("ipv4") and not dns_module_network_failure)
```

### 46. AXFR Socket-Timeout
**File:** `src/analyzers/dns_analyzer.py` — `_analyze_zone_transfer()`

- `socket.setdefaulttimeout(3)` + `lifetime=3` für AXFR-Versuch
- Verhindert TCP-SYN-Hang wenn VPN Port 53 zu autoritativen NS blockiert

### 47. DNS-Timeout Konfiguration
**File:** `config/settings.py`

- `dns_timeout` Dataclass-Default: 10 → 5
- Env-Var-Default liest jetzt den Dataclass-Default statt hardcoded `'10'`

### 48. OPSEC-Terminologie
**File:** `src/core/result_formatter.py` — `display_forensic_header()`

- `Proxy/VPN: Not Detected` → `VPN/Proxy Signals: No known provider signatures observed`
- `Proxy/VPN: Detected` → `VPN/Proxy Signals: VPN provider detected (rDNS match)`
- `Stealth Level: MEDIUM` → `Stealth Level: MEDIUM (aggregated external signals)`

**Bekannte Limitierung (für Phase 5 Dokumentation):**
VPN-Erkennung basiert ausschließlich auf rDNS-Keyword-Matching gegen Hostnamen der External-IP.
ProtonVPN verwendet Infrastruktur von Drittanbietern (Datapacket, M247) → kein "protonvpn" im rDNS → Not Detected.
Das ist korrektes Verhalten — das Tool macht kein aktives VPN-Fingerprinting.

---

## Next Session To-Do

**Roadmap-Stand: Phase 4 (Teil 2) — Linux-Tests auf Server + Reports verarbeiten**

Ablauf (nächste Session):
1. User hat Branch auf Linux-Server gepullt und scenario_a.sh + scenario_b.sh ausgeführt
2. User gibt 4 JSON-Reports (Linux A+B, Windows C+D) an Agent
3. Agent füllt `docs/VALIDATION_REPORT.md` mit Vergleichsmatrix
4. PR `feature/phase-4-validation` → `main` mergen
5. Phase 5: CONTRIBUTING.md, SECURITY.md, README-Erweiterungen
6. Phase 6: Final-Check, GitHub Release

**Offene Phasen laut RELEASE_V1_0_0_ROADMAP.md:**
- Phase 4: Cross-Platform OPSEC — **IN PROGRESS** (Linux-Tests ausstehend)
- Phase 5: Dokumentation (CONTRIBUTING.md, SECURITY.md, README-Erweiterung)
- Phase 6: Finalisierung & Release (Final-Check, GitHub Release)

---

## API Keys Required

```
WHOISXML_API_KEY       — registration intelligence (500/month free)
VIRUSTOTAL_API_KEY     — domain + IP reputation, resolutions history
ABUSEIPDB_API_KEY      — IP reputation
SECURITYTRAILS_API_KEY — DNS history (quota currently exhausted)
```

Keys loaded from env var first, then `config/api_keys.json` (git-ignored).

---

## Development Notes

- Windows UTF-8 encoding: `run.py` calls `sys.stdout.reconfigure(encoding='utf-8')` at startup; box-drawing chars (`├──`) are safe
- `ThreadAwareStdoutRouter` isolates print output per module thread; always use `print()` in display functions, never in analyzer business logic
- dnspython `resolver.rrset.ttl` gives authoritative TTL; nslookup does not
- RobTex PDNS forward (`/pdns/forward/{domain}`) returns newline-delimited JSON, one object per line
- RobTex reverse IP (`/ipquery/{ip}`) returns JSON with `pas` (passive) and `act` (active) arrays
- VirusTotal reverse IP uses `/api/v3/ip_addresses/{ip}/resolutions` (different from domain resolutions)
