# CLAUDE.md — Domain Forensic Analyzer

Developer context for Claude Code sessions. Keep this file up to date at the end of each session.

---

## Project Overview

Terminal-based domain OSINT tool. Runs 10 modules in sequence, renders a structured forensic report. Python 3, Windows-primary (PowerShell), venv at project root.

Entry point: `python run.py [domain]` — domain argument skips interactive prompt.

---

## Architecture

```
run.py                          Entry point (CLI arg support added)
src/core/domain_analyzer.py     Orchestrator, ThreadAwareStdoutRouter, display_forensic_summary()
src/analyzers/
    dns_analyzer.py             DNS resolution + hardening checks
    whois.py                    WHOIS via WhoisXML API + python-whois fallback
    dns_history_analyzer.py     Historical DNS timeline (RobTex, VT, crt.sh, SecurityTrails)
    cdn_detector.py             CDN/cloud provider detection via IP prefix matching
    ip_history_analyzer.py      Reverse-IP lookup (VT, RobTex, HackerTarget) — NEW
    network_intelligence.py     Ping + traceroute
    subdomain_scanner.py        DNS-based subdomain discovery
    securitytrails_client.py    SecurityTrails domain intelligence
    abuseipdb_client.py         IP reputation
    virustotal_client.py        Domain reputation
src/utils/colors.py             Terminal color helpers
config/api_keys.json            API keys (git-ignored)
```

Module execution order: `dns → whois → dns_history → cdn → network → subdomain → securitytrails → abuseipdb → virustotal → ip_history`

---

## What Was Implemented (Session 2026-05-07)

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

---

## Current Report Block Order

```
SUMMARY
TARGET
WHOIS REGISTRATION
DNS FORENSICS
DNS HISTORY TIMELINE
INFRASTRUCTURE
NETWORK PATH
ATTACK SURFACE
THREAT INTELLIGENCE
IP & DOMAIN HISTORY          ← new
RISK ASSESSMENT
EXECUTION
```

---

## Open Gaps / Known Issues

| Issue | File | Notes |
|-------|------|-------|
| MX FQDN truncated | `dns_analyzer.py` `_parse_mx_records()` | nslookup output returns bare hostname (e.g. "mail" not "mail.domain.com"). Pre-existing. dnspython would solve this. |
| crt.sh intermittent | `dns_history_analyzer.py` `_collect_certificate_transparency()` | Sometimes returns 60 certs, sometimes times out. No retry logic. |
| SecurityTrails always FAILED | `securitytrails_client.py` | API quota exhausted. Better quota-exceeded messaging needed. |
| "multiple nameserver changes" over-fires | `dns_history_analyzer.py` `_analyze_patterns()` | Threshold `>= 4` NS events flags long-lived legitimate domains. Needs per-year normalization. |
| `analysis_status` missing from whois fallback | `domain_analyzer.py` `_get_fallback_result()` | WHOIS fallback dict lacks `analysis_status: 'abgeschlossen'`. Low impact. |

---

## Next Session To-Do

**Priority 1 — MX FQDN fix:**
Replace nslookup-based `_parse_mx_records()` in `dns_analyzer.py` with dnspython `resolver.resolve(domain, 'MX')` to get full FQDNs. Pattern identical to `_resolve_a_ttl()` already in the file.

**Priority 2 — crt.sh retry:**
Add `max_retries=2, backoff=1s` to `_collect_certificate_transparency()` in `dns_history_analyzer.py`.

**Priority 3 — SecurityTrails messaging:**
Surface quota-exceeded state visibly in THREAT INTELLIGENCE block instead of generic "FAILED".

**Priority 4 — NS change threshold:**
In `_analyze_patterns()`, normalize NS event count by timeline years before firing "multiple nameserver changes". Threshold: more than 2 NS migrations per 3-year window.

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

- Windows cp1252 encoding constraints apply — keep report output ASCII-safe
- `ThreadAwareStdoutRouter` isolates print output per module thread; always use `print()` in display functions, never in analyzer business logic
- dnspython `resolver.rrset.ttl` gives authoritative TTL; nslookup does not
- RobTex PDNS forward (`/pdns/forward/{domain}`) returns newline-delimited JSON, one object per line
- RobTex reverse IP (`/ipquery/{ip}`) returns JSON with `pas` (passive) and `act` (active) arrays
- VirusTotal reverse IP uses `/api/v3/ip_addresses/{ip}/resolutions` (different from domain resolutions)
