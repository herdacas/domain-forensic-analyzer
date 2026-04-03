# Domain Forensic Analyzer

## Purpose
This repository currently contains a terminal-based forensic domain analysis workflow for investigating a user-provided domain across DNS, infrastructure, network path, attack surface, and external threat-intelligence sources.

This README is intentionally written as an internal orientation document. It reflects the code as it exists now and is meant to help future restructuring, report refinement, and feature integration.

## Current End-to-End Flow
The main execution path is:

1. User enters a domain in `src/core/domain_analyzer.py` via `get_domain_input()`.
2. `display_forensic_header()` collects session metadata:
   - external IP
   - local IP
   - hostname / username
   - coarse OPSEC assessment
3. `DomainAnalyzer.analyze_domain()` validates and normalizes the domain.
4. `_execute_analysis_workflow()` runs the analysis modules sequentially.
5. `_call_module_function()` dispatches each module according to dependency order.
6. `ResultAggregator.aggregate_results()` converts module output into a `UnifiedResult`.
7. `display_forensic_summary()` renders the final forensic report.

## Module Execution Order
The current execution order in `src/core/domain_analyzer.py` is:

1. `dns`
2. `cdn`
3. `network`
4. `subdomain`
5. `securitytrails`
6. `abuseipdb`
7. `virustotal`

Dependency notes:
- `cdn` depends on the IPv4 result from `dns`.
- `network` depends on the IPv4 result from `dns`.
- `abuseipdb` depends on the IPv4 result from `dns`.
- `virustotal` analyzes the domain directly.
- `securitytrails` analyzes the domain directly.
- `subdomain` analyzes the domain directly.

## Active Core Components
### `src/core/domain_analyzer.py`
Responsibilities:
- CLI entrypoint
- orchestration
- timeout handling
- progress reporting
- report rendering
- forensic session metadata collection

Important functions:
- `get_domain_input()`
- `display_forensic_header()`
- `DomainAnalyzer.analyze_domain()`
- `_execute_analysis_workflow()`
- `_execute_module_with_timeout()`
- `_call_module_function()`
- `display_forensic_summary()`

### `src/core/result_aggregator.py`
Responsibilities:
- merges raw module outputs into `UnifiedResult`
- standardizes asset, infrastructure, and network fields
- calculates risk metrics, warnings, errors, and confidence metadata

Important structures:
- `UnifiedResult`
- `StandardizedAsset`
- `StandardizedInfrastructure`
- `StandardizedNetworkPath`
- `ResultAggregator`

## Analyzer Modules and Their Current Function
### `src/analyzers/dns_analyzer.py`
Current function:
- IPv4 resolution
- IPv6 resolution
- reverse DNS lookup
- MX lookup
- NS lookup

Currently represented in final report:
- yes, mostly complete

### `src/analyzers/cdn_detector.py`
Current function:
- CDN / cloud / platform / direct-hosting detection
- protection level estimation
- geolocation / ASN context
- internal security assessment helper (`get_security_assessment`)

Currently represented in final report:
- provider
- provider type
- protection level
- edge/WAF summary
- location

Partially represented:
- internal security-assessment logic exists but is not directly surfaced as a structured report section

### `src/analyzers/network_intelligence.py`
Current function:
- ICMP reachability / ping timing
- HTTP / HTTPS reachability checks
- traceroute collection
- hop parsing with RTT extraction
- hop classification
- route classification
- OPSEC assessment
- hop-intelligence summary

Currently represented in final report:
- connectivity latency
- traceroute status
- hop list
- RTT per hop

Not fully represented yet:
- HTTP / HTTPS status
- route classification
- OPSEC assessment details
- hop-intelligence aggregate summary

### `src/analyzers/subdomain_scanner.py`
Current function:
- wildcard DNS detection
- DNS-based subdomain enumeration
- category assignment
- sensitive pattern assignment

Important semantic note:
- when wildcard DNS is enabled, DNS resolution alone does not confirm real host existence
- in that case the current report should treat findings as candidates, not confirmed subdomains

Currently represented in final report:
- wildcard status
- candidate or subdomain counts
- category counts
- sensitive candidate / asset counts
- discovered list or sample list depending on wildcard state

### `src/analyzers/securitytrails_client.py`
Current function:
- domain details
- historical DNS summary
- historical MX data
- subdomain intelligence
- intelligence summary

Currently represented in final report:
- only a compact SecurityTrails history line

Data computed but not yet surfaced properly:
- historical A-record changes
- historical MX changes
- categorized SecurityTrails subdomain intelligence
- intelligence summary risk indicators

### `src/analyzers/abuseipdb_client.py`
Current function:
- IP abuse confidence lookup
- country / usage type
- report volume / last report
- threat-category extraction
- reputation intelligence classification

Currently represented in final report:
- abuse confidence summary
- country code

Data computed but not yet surfaced properly:
- usage type
- report count
- threat categories
- reputation intelligence reasoning

### `src/analyzers/virustotal_client.py`
Current function:
- domain reputation
- vendor detection summary
- category extraction
- consensus calculation
- DNS intelligence extraction
- related threat extraction

Currently represented in final report:
- compact domain-reputation summary

Data computed but not yet surfaced properly:
- vendor consensus
- categories
- DNS intelligence
- related threats

## Additional Files Present but Not in Main Workflow
### `src/analyzers/whois.py`
- exists
- not currently integrated into the main analysis workflow

### `src/core/security_manager.py`
- imported in `domain_analyzer.py`
- not currently used in the active main execution path

## Report Coverage Findings
The current final report is strongest in these areas:
- DNS foundation
- infrastructure overview
- traceroute visibility
- subdomain / candidate presentation
- basic threat-intelligence summary

The current final report is weaker in these areas:
- historical intelligence depth
- route / OPSEC interpretation
- abuse / threat category detail
- VirusTotal category and consensus detail
- explicit distinction between confirmed assets and DNS-only candidates in every relevant block

## Structural Findings
### Good current properties
- module execution is explicit and easy to follow
- timeout handling exists per module
- module dependency ordering is clear
- final report now adapts to wildcard, CDN/WAF, and timeout scenarios
- traceroute RTT values are preserved in the report

### Important design findings
- wildcard DNS is not automatically a risk condition; it can be an intentional anti-enumeration measure
- DNS-only subdomain enumeration becomes semantically weak under wildcard DNS and must be framed as candidate generation
- some modules compute substantially more intelligence than the final report currently exposes
- report semantics are improving, but the risk model is still partly heuristic and not yet fully source-aware

### Codebase findings to keep in mind
- `ResultAggregator.supported_modules` does not currently reflect every module that the orchestrator executes
- analyzer modules still contain extensive internal terminal output logic even though the orchestration layer now suppresses worker-thread console noise during normal runs
- main workflow remains CLI-first and report-first; there is no separate structured export pipeline connected to a stable public interface yet

## Current Reporting Rules
### Standard-resolution domains
- treat DNS-based findings as discovered subdomains
- show top exposures plus the discovered list

### Wildcard domains
- treat DNS-based findings as candidates only
- show only a short candidate sample
- attach a validation note explaining that DNS resolution alone is insufficient
- do not frame wildcard DNS itself as a risk factor by default

### Timeout cases
- continue analysis
- preserve timeout in execution summary
- show timeout explicitly in the affected report section instead of collapsing it into a generic failure state

## Recommended Next Work
1. Expose route classification, HTTPS reachability, and OPSEC assessment in the final report.
2. Add a dedicated historical-intelligence block for SecurityTrails.
3. Add richer AbuseIPDB and VirusTotal details without overwhelming the report.
4. Reconcile `ResultAggregator` module metadata with the real orchestrator execution set.
5. Define a clearer confidence model for wildcard-based candidate findings.
6. Add structured export formats that mirror the final report semantics.

## Working Interpretation
At this stage the project already performs a real multi-source domain investigation, but the output layer is still catching up to the amount of intelligence already being gathered.

That means the current priority is not more raw collection first, but consistent semantics:
- what is confirmed
- what is inferred
- what is candidate-only
- what timed out
- what is computed but not yet shown
