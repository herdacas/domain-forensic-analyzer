# Architecture

## Overview

Domain Forensic Analyzer runs 11 analyzer modules in a fixed sequence against a target domain, aggregates their output into a single result object, and renders a structured terminal report. Every scan exports a JSON report automatically. Raw console capture is a developer-only facility requiring `capture_console()` and `ReportExporter(debug=True)`; normal CLI runs do not write raw text.

```
run.py  ─┬─▶ src/core/cli.py            entry point: parses domain, drives the scan, prints summary
         │
         ├─▶ src/core/domain_analyzer.py   DomainAnalyzer — orchestrates module execution
         │       └─▶ src/core/stdout_router.py   per-module thread-safe stdout isolation
         │
         ├─▶ src/analyzers/*.py          11 analyzer modules (see below)
         │
         ├─▶ src/core/result_aggregator.py   merges module outputs into UnifiedResult
         │
         ├─▶ src/core/result_formatter.py    renders the terminal report + display helpers
         │
         └─▶ src/core/report_exporter.py     writes reports/<id>_<domain>.json
```

## Module execution order

```
dns → whois → dns_history → cdn → network → subdomain → ssl → securitytrails → abuseipdb → virustotal → ip_history
```

Each module gets its own timeout (`MODULE_TIMEOUTS` in `config/settings.py`) and runs in its own thread via `ThreadAwareStdoutRouter`, so a slow or hanging module can't block the others indefinitely or interleave their print output.

| Module | File | Role |
|---|---|---|
| DNS | `src/analyzers/dns_analyzer.py` | Resolution, record types, SPF/DMARC/DKIM/CAA/DNSSEC, zone transfer probe |
| WHOIS | `src/analyzers/whois.py` | Registration data via WhoisXML API, falls back to `python-whois` |
| DNS History | `src/analyzers/dns_history_analyzer.py` | Historical timeline from Mnemonic, RobTex, VirusTotal, crt.sh/CertSpotter |
| CDN/GEO | `src/analyzers/cdn_detector.py` | CDN/cloud/gov-cloud detection, geolocation, ASN |
| Network | `src/analyzers/network_intelligence.py` | Ping, traceroute/tracepath, HTTP/S behavior (redirects, HSTS, CSP) |
| Subdomain | `src/analyzers/subdomain_scanner.py` | DNS-pattern subdomain discovery, wildcard detection |
| SSL/TLS | `src/analyzers/ssl_analyzer.py` | Certificate chain inspection (stdlib `ssl` + `cryptography`) |
| SecurityTrails | `src/analyzers/securitytrails_client.py` | Domain intelligence, historical subdomains |
| AbuseIPDB | `src/analyzers/abuseipdb_client.py` | IP reputation |
| VirusTotal | `src/analyzers/virustotal_client.py` | Domain/IP reputation |
| IP History | `src/analyzers/ip_history_analyzer.py` | Reverse-IP co-hosted domains |

Every analyzer returns a plain `dict` with an `analysis_status` field (`abgeschlossen`, `demo_abgeschlossen`, `fehlgeschlagen`, `failed`, `quota_exceeded`, or `skipped`). The orchestrator catches module exceptions and creates a failed fallback result.

## `src/core/` layout

The orchestrator/display layer was split (2026-06-04) from a single large file into:

| File | Contents |
|---|---|
| `stdout_router.py` | `ModuleExecutionResult`, `ThreadAwareStdoutRouter` |
| `domain_analyzer.py` | `DomainAnalyzer` — module execution orchestration only |
| `metadata.py` | External/local IP, system metadata, OPSEC risk assessment |
| `result_aggregator.py` | `UnifiedResult`, asset/risk standardization across modules |
| `risk_assessment.py` | Shared domain risk logic for JSON and terminal reports |
| `result_formatter.py` | All terminal report rendering (`display_forensic_summary` and friends) |
| `report_exporter.py` | JSON + raw-text export, batch export |
| `cli.py` | `get_domain_input`, `main()` |

Dependency direction is one-way: `stdout_router` has no local dependencies; `domain_analyzer` uses the router, aggregator, formatter and analyzer modules; the aggregator and formatter share `risk_assessment`; `cli` ties the scan, display and exporter together. `risk_assessment` imports `UnifiedResult` only for type checking, avoiding a runtime import cycle.

## Report lifecycle

1. `cli.main()` collects the domain (CLI arg or interactive prompt), normalizes it (`DomainValidator.preprocess_domain()` — apex-stripping, punycode, reserved-TLD/IP/file-path rejection).
2. `DomainAnalyzer.analyze_domain()` runs the 11 modules in order with per-thread stdout isolation. No raw console capture is enabled in production.
3. `result_aggregator.create_result_aggregator()` merges the 11 module dicts into a `UnifiedResult`, computing `overall_risk_level`, `risk_factors`, and standardized asset lists.
4. `result_formatter.display_forensic_summary()` renders the terminal report block-by-block (see the report block order in `README.md`). Domains with no current DNS resolution but historical A-records short-circuit into `_display_historical_blocks()` — a reduced report that skips blocks requiring live connectivity.
5. `report_exporter.ReportExporter.export()` writes `reports/<id>_<domain>.json` (the full `UnifiedResult` plus analyst/session metadata). Batch mode (`--list`) additionally writes one consolidated `reports/batch/BATCH_<id>_<listname>.json`. Paths are relative to the project root. Export failures are reported to stderr without interrupting analysis.

## Where to look for common changes

- **New report field on an existing module:** edit the analyzer in `src/analyzers/`, then add the display line in the matching `_render_*_section()` function in `result_formatter.py`.
- **New analyzer module:** see the "Adding a new analyzer module" checklist in `CONTRIBUTING.md`.
- **Risk scoring change:** `assess_domain_risk()` in `risk_assessment.py` supplies the same domain-level risk and module-tagged factors to JSON and terminal output. `_infer_risk_level()` in `result_aggregator.py` estimates individual asset candidates. Network OPSEC assessment is separate because it describes analyst exposure rather than target risk.
- **Timeout tuning:** `MODULE_TIMEOUTS` in `config/settings.py`.
