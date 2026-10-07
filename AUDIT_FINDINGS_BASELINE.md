# Audit Findings Baseline

## Issue 1: ResultAggregator missing modules
- Executed: dns, whois, dns_history, cdn, network, subdomain, ssl, securitytrails, abuseipdb, virustotal, ip_history (11 total)
- Aggregator supported_modules: dns, whois, dns_history, cdn, subdomain, network, securitytrails (7 total)
- Missing from aggregator: ssl, abuseipdb, virustotal, ip_history
- Impact: Result metadata does not reflect all data sources

## Issue 2: Network connectivity field mismatch
- network_intelligence.py produces: ping_reachable, http_accessible, https_accessible
- result_aggregator.py reads: connectivity.get("ping")
- Mismatch causes: connectivity_status defaults to "unknown" incorrectly

## Issue 3: Raw export documentation mismatch
- README, ARCHITECTURE, SECURITY docs describe raw export as standard feature
- Implementation: ReportExporter(debug=False) is default, raw only written if debug=True
- Actual behavior: raw exports NOT generated in production path

## Issue 4: Traceroute tool inconsistency
- Code prefers: tracepath (Linux)
- CI installs: traceroute, iputils-ping (no tracepath)
- Docs mention: both traceroute and tracepath inconsistently
- Risk: Tool detection may fail on CI or user systems

## Issue 5: API config model drift
- tests/test_api_clients.py uses: APIConfig(api_key=..., base_url=..., rate_limit=...)
- config/settings.py uses: securitytrails_api_key, virustotal_api_key, shodan_api_key
- Mismatch causes: Potential config loading failures if both used simultaneously

## Issue 6: Known quality issues
- ASN field null across all scenarios
- DNSSEC status inconsistent for same domain (A: not_detected, B/C/D: enabled)
- Traceroute connectivity_status: unknown, responsive_hops: 0 across all platforms

## Issue 7: Marketing language too absolute
- README: "complete intelligence picture of any domain"
- Reality: Broad but not complete; risk scoring heuristic; passive sources only 70%
- Better phrasing: "broad domain reconnaissance and forensic enrichment tool"

---

## Verified state at branch HEAD `74c53c2` (2026-10-01)

The audit above was written against `origin/main` (`e748188`). The branch already
carries one earlier polish commit (`74c53c2`, see `docs/PRODUCTION_POLISH_REPORT.md`).
Baseline test run on this HEAD: **337 passed, exit code 0**
(`.venv` Python 3.12.3, pytest 9.1.1).

| # | Status on HEAD | Exact location | Remaining gap vs. this refactor brief |
|---|---|---|---|
| 1 | Fixed: all 11 modules listed and mapped | `src/core/result_aggregator.py:179` (`supported_modules`), `:23` (`DataSource`), `:504` (`_identify_intelligence_sources`) | Enum members are named `SSL`, `ABUSEIPDB`, `VIRUSTOTAL`, `IP_HISTORY`; brief expects `SSL_ANALYSIS`, `ABUSEIPDB_REPUTATION`, `VIRUSTOTAL_REPUTATION`, `IP_HISTORY` with descriptive values. No dedicated coverage test file. |
| 2 | Fixed: reads `ping_reachable`/`http_accessible`/`https_accessible` | `src/core/result_aggregator.py:406` (`_aggregate_network_intelligence`) | Responsive hops are only counted from `hops[]`; an explicit `responsive_hops` count is ignored. No `http_accessible` / `unreachable` distinction. No dedicated test file. |
| 3 | Not aligned: code is debug-only (`debug=False`), console capture is not wired into the CLI or batch path at all | `src/core/report_exporter.py:170`, `src/core/cli.py:59`, `run.py:70` | Brief makes raw capture standard: flip default, wire `capture_console()` back into `cli.main()` and `run.py --list`, align README/ARCHITECTURE/SECURITY/CHANGELOG (SECURITY.md already says "by default"). |
| 4 | Mostly fixed: tracepath → traceroute fallback, CI installs `iputils-tracepath traceroute` | `src/analyzers/network_intelligence.py:326`, `.github/workflows/test.yml:32` | Tool selection is inline, not a testable `_detect_traceroute_tool()`. "Unavailable" message has no install hint. README table merges both tools into one row. |
| 5 | Fixed for runtime: `Settings` loads via `SecureAPIManager`; no Shodan keys remain | `config/settings.py:41` (`APISettings`), `:208` (`get_settings`) | `tests/test_api_clients.py` builds `src.config.api_config.APIConfig` directly; no test asserts the `get_settings()` contract. |
| 6 | Partly fixed: DNSSEC query failures report `check_failed`; missing ASN stays `null` with a warning | `src/analyzers/dns_analyzer.py:583` (`_analyze_dnssec`), `src/core/result_aggregator.py:374` (`_aggregate_infrastructure`) | Brief wants the explicit status `inconclusive` plus a note, and the explicit ASN sentinel `unavailable`. No `docs/KNOWN_LIMITATIONS.md`. |
| 7 | Partly fixed: "complete intelligence picture" already removed | `README.md:1-12`, `README.md:228`, `CHANGELOG.md:21` | No status badge, no "When to Use" / "Coverage" sections. README still contains the phrase "definitive verdict" (in negated form), which the brief's alignment test forbids. |
