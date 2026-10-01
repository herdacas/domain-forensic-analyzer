# Changelog

All notable changes to Domain Forensic Analyzer are documented here.

---

## [Unreleased] — v1.0 production polish

- Track all 11 module sources and per-module confidence; distinguish skipped, demo and failed results.
- Missing API keys skip live intelligence clients instead of returning fabricated demonstration findings.
- Share domain risk assessment between JSON and terminal output, with module-to-factor provenance.
- Read emitted connectivity fields, hop responses and route classification correctly; preserve unknown states.
- Detect Linux tracepath/traceroute, retain partial timeout results, and enforce silent Windows tracert deadlines.
- Make missing ASN and inconclusive DNSSEC/path checks explicit; DNSSEC presence does not imply signature validation.
- Unify API key loading, placeholder fallback and defensive config parsing; remove unsupported integrations from templates.
- Raw console capture is a standard output again: CLI and batch runs write `reports/raw/<id>_<domain>.txt` next to the JSON report (`ReportExporter(debug=False)` for JSON only). Export failures are reported on stderr; per-domain batch exports are restored.
- Document variable coverage and heuristic limits; enable CI on refactor branches.

## [1.0.0] — 2026-06-04

First v1.0 release of the operational reconnaissance pipeline, with heuristic findings and the limitations below.

### Highlights

- **11-module forensic pipeline** running in sequence: DNS, WHOIS, DNS History, CDN/GEO, Network Path, Subdomain, SSL/TLS, SecurityTrails, AbuseIPDB, VirusTotal, IP & Domain History
- **Historical analysis mode** — inactive or expired domains fall back to passive-source reconstruction automatically
- **Cross-platform** — Windows (PowerShell) and Linux; tracert/tracepath auto-detected
- **Zero-config start** — active probes + free APIs provide baseline coverage without API keys; depth varies by source availability
- **Batch mode** — `python run.py --list domains.txt` with per-domain JSON export and a consolidated batch report
- **Structured exports** — `reports/<id>_<domain>.json` plus raw console capture in `reports/raw/<id>_<domain>.txt`.

### New in this release (vs. earlier internal builds)

- `src/core/` split into focused modules: `stdout_router`, `metadata`, `cli`, `result_formatter`, `domain_analyzer`
- Input validation: IP rejection, file-path rejection, IDN→Punycode conversion, compound ccTLD preservation
- SSL/TLS module using `cryptography` library (two-pass verified/unverified connection)
- HTTP/S Behavior block: redirect chain, HSTS, CSP, X-Frame-Options
- CT log fallback chain: crt.sh → CertSpotter
- Mnemonic PDNS as additional passive DNS source
- GEO & ASN block via ip-api.com (no API key)
- CDN/WAF detection for 13+ providers including OVHcloud, Hetzner, IONOS, Deutsche Telekom, Outscale
- Registry policy awareness for redacting ccTLDs (DENIC, SIDN, SWITCH, and others)
- Privacy proxy / WHOIS shield detection
- Domain age risk flag (< 30 days → HIGH, 30–90 days → MEDIUM)
- Wildcard/catch-all DNS detection
- Test suite: 291 tests, 70% coverage
- GitHub Actions CI: Python 3.10–3.12 × Ubuntu / Windows

### Known Limitations

- WHOIS registrant fields are redacted for several ccTLDs by registry policy — shown explicitly in the report.
- SecurityTrails and VirusTotal history depth depends on account tier.
- Subdomain discovery is DNS-pattern based; wildcard DNS degrades to candidate-only mode.
- Certificate Transparency wildcard-only certs (`*.domain.com`) produce no subdomain entries by design.
- The risk model is heuristic — use it to guide investigation, not as a definitive verdict.

---

## [0.9.x] — internal builds

Pre-release development iterations. Not publicly tagged.
