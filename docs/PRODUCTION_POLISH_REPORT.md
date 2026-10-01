# v1.0 production polish — validation report

Date: 2026-10-01. Working branch: `refactor/v1.0-production-polish`.
Baseline: `e748188` (same commit as origin/main when work started).
An isolated worktree was used; the original checkout and its untracked files were preserved.

## Findings and fixes

- The 11-module pipeline had only seven aggregation source mappings. SSL, AbuseIPDB, VirusTotal and IP History now have provenance and per-module confidence. Live, skipped, quota, demo and failed outcomes are distinguished. Empty scans have unknown confidence.
- Network aggregation consumed `ping` instead of `ping_reachable`, read hop counts and route types from the wrong structures, and overstated confidence. It now consumes emitted ping/HTTP/HTTPS fields, counts responsive hop records, reads route classification, and retains unknown states without positive evidence.
- Terminal domain risk included threat intelligence, WHOIS age, SSL and HTTP evidence that JSON omitted. Both now use the existing logic in `risk_assessment.py`; factors are attributed through `module_risk_factors`. High severity cannot be lowered by a later medium asset finding. Critical asset candidates trigger high heuristic risk. Numeric scores retain asset counts with documented severity anchors, not calibrated probabilities.
- Missing API keys previously returned invented demonstration findings from three clients. Normal execution now skips these clients without synthetic intelligence. Explicit demo helpers remain available for development; aggregation excludes demo data from live provenance and scoring.
- Production raw export claims contradicted the existing debug-only implementation. Documentation now describes JSON-only production output and explicit debug capture. Batch mode now writes the documented individual reports as well as the consolidated batch report. Export failures are visible on stderr.
- Linux installed dependencies did not match the hard-coded tracepath command. Runtime prefers tracepath, falls back to traceroute, and handles absent tools. Timeout output is partial; routes without the destination are partial. Windows tracert deadlines now work even when the subprocess emits no lines. A tracepath LOCALHOST header no longer hides a real hop of the same number.
- API settings now use the same loader as clients, with process environment > project-root .env > JSON, placeholder fallback, flat/nested JSON support, defensive value handling, and current VirusTotal v3 URLs. Unsupported Shodan/Censys template entries were removed.
- Missing ASN stays null with reduced confidence and a warning. Existing DNSSEC timeout handling was retained; per-query failure flags and `validation: not_performed` make its limits explicit. Unclassified paths do not establish privacy or anonymity.
- README, architecture, changelog and historical validation notes now describe variable coverage, heuristic confidence and honest limits. CI also runs on refactor branches.

## Step validation

| Step | Written expectation | Observed result |
|---|---|---|
| 1 — baseline | Establish reproducible tests and concrete mismatches | 299 baseline tests passed; defects identified from emitted/consumed fields and docs |
| 2 — aggregation | Cover all 11 modules without claiming unavailable sources | Aggregator/integration tests passed; mapping, freshness and confidence regressions added |
| 3 — connectivity | Positive emitted evidence means reachable; absent evidence means unknown | Targeted tests and full suite passed; live JSON reports reachable and six responsive hops |
| 4 — export | Production JSON exists; no raw directory; debug is explicit | Export tests passed; live report written without raw capture; batch lifecycle regression passed |
| 5 — path tools | Deterministic tool selection, graceful absence and partial timeouts | Both Linux tools and neither-installed cases tested; real environment has tracepath and traceroute |
| 6 — configuration | All loaders agree on priority, placeholders and defensive parsing | API tests and full suite passed, including .env priority and settings availability |
| 7 — uncertainty | Missing/failed observations cannot imply validated data or anonymity | DNSSEC, ASN, path, silent Windows timeout and status tests passed; live DNSSEC check is inconclusive, path is partial |
| 8 — maturity | Release wording reflects actual coverage and reports agree | Absolute completeness/percentage claims removed; domain-risk parity regressions passed |

## Final automated and live checks

Executed with Python 3.12 through the existing project virtual environment:

- `python -m pytest tests/ -q`: passed, 337 tests.
- `python -m pytest tests/ -v --maxfail=1`: 337 passed in 2.02 seconds.
- `pylint src/ --fail-under=8.0 --output-format=colorized`: passed, 9.40/10. Pylint 4.1.1 was installed separately under /tmp because the project environment lacked it. Existing style warnings remain above the required threshold.
- `python run.py example.com`: exit 0; valid JSON report written. Eight live modules completed, three APIs skipped for missing credentials, no failed modules and no demo output. Connectivity reachable, six responsive hops. JSON and terminal risk factors match.
- Report assertions confirmed the absence of invented API fields, correct skipped lists, risk parity, no production raw directory, and no CLI/export failure messages.
- `git diff --check`: passed.

The targeted live DNSSEC check returned failed DS/DNSKEY query flags, not evidence that DNSSEC is absent. The route was partial. Both were explicitly reported and are environmental observation limits, not failed test gates. No reports containing analyst metadata were committed.

## Changed files

- Core: `src/core/domain_analyzer.py`, `result_aggregator.py`, `risk_assessment.py` (new), `result_formatter.py`, `report_exporter.py`; `run.py`.
- Analyzers: `src/analyzers/network_intelligence.py`, `dns_analyzer.py`, `abuseipdb_client.py`, `virustotal_client.py`, `securitytrails_client.py`.
- Configuration: `config/settings.py`, `config/.env.template`, `config/api_keys.json.template`, `src/config/api_config.py`, `src/utils/api_key_reader.py`.
- Tests: `tests/test_result_aggregator.py`, `test_network_intelligence.py`, `test_integration.py`, `test_api_clients.py`, `test_report_exporter.py` (new).
- Documentation/CI: `README.md`, `CHANGELOG.md`, `docs/ARCHITECTURE.md`, `docs/VALIDATION_REPORT.md`, this report, `.github/workflows/test.yml`.

## Remaining limits and recommendation

No real Windows or VPN rerun was performed; Windows behavior is covered by mocked command/timeout tests, with historical scenarios preserved. Paid API integrations were tested with mocks rather than live credentials. Coverage percentage was not recomputed. Upstream availability, resolver restrictions, WHOIS redaction and VPN detection limits remain. DNSSEC signature validation, new intelligence providers and a statistically calibrated scoring model are intentionally outside scope.

The JSON schema adds skipped/demo/module-risk metadata; successful module counts and risk values intentionally change to reflect actual evidence. Consumers should review these semantics. Review the patch and repeat Windows/VPN and credentialed API smoke checks before deciding whether to merge. No PR merge or default-branch update was performed.

No merge to main occurred without explicit user approval.
