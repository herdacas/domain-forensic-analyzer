# Changelog

All notable changes to Domain Forensic Analyzer are documented here.

---

## [Unreleased] — v1.0 production polish

- Track all 11 module sources and per-module confidence; distinguish skipped, demo and failed results.
- Missing API keys skip live intelligence clients instead of returning fabricated demonstration findings.
- Share domain risk assessment between JSON and terminal output, with module-to-factor provenance.
- Read emitted connectivity fields, hop responses and route classification correctly; preserve unknown states.
- Detect Linux tracepath/traceroute, retain partial timeout results, and enforce silent Windows tracert deadlines.
- Make missing ASN and inconclusive DNSSEC/path checks explicit; DNSSEC presence does not imply signature validation. JSON values changed: DNSSEC `check_failed` is now `inconclusive` (with a `note`), and missing ASN/organisation is `"unavailable"` instead of `null`. See `docs/KNOWN_LIMITATIONS.md`.
- Unify API key loading, placeholder fallback and defensive config parsing; remove unsupported integrations from templates.
- Raw console capture is a standard output again: CLI and batch runs write `reports/raw/<id>_<domain>.txt` next to the JSON report (`ReportExporter(debug=False)` for JSON only). Export failures are reported on stderr; per-domain batch exports are restored.
- Document variable coverage and heuristic limits; enable CI on refactor branches.
- README: production status badge, "When to Use This Tool" and "Coverage" sections, and a link to `docs/KNOWN_LIMITATIONS.md`; v1.0.0 notes restructured into Capabilities and Known Limitations.

## [1.0.0] — 2026-06-04

First production release. Operationally stable and feature-complete, with known limitations.

### Capabilities
- 11-module forensic analysis pipeline (DNS, WHOIS, TLS, network, threat intel, historical data)
- ~70% coverage without API keys; full historical depth with optional API access
- Cross-platform support (Windows, Linux; macOS untested)
- Batch processing and structured JSON export
- Heuristic risk scoring and OPSEC assessment

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
- ASN/geolocation coverage limited by free GeoIP provider
- Subdomain discovery is DNS-pattern based, not exhaustive
- Risk scoring is heuristic; use as a guide, not a definitive verdict
- DNSSEC status may vary across DNS servers (inconclusive in edge cases)
- Traceroute results depend on target network configuration
- WHOIS registrant fields are redacted for several ccTLDs by registry policy — shown explicitly in the report
- SecurityTrails and VirusTotal history depth depends on account tier
- Certificate Transparency wildcard-only certs (`*.domain.com`) produce no subdomain entries by design

See docs/KNOWN_LIMITATIONS.md for details.

---

## [0.9.x] — internal builds

Pre-release development iterations. Not publicly tagged.
