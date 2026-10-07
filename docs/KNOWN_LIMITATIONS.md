# Known Limitations and Uncertainties

## ASN Information
- ip-api.com free tier may return null for some IP ranges.
- Status: Inconclusive. Use premium geolocation service for complete coverage.
- In the JSON report a missing value is written as `"asn": "unavailable"` / `"organization": "unavailable"`, infrastructure confidence drops to `unknown`, and a `cdn: ASN unavailable` warning is added.

## DNSSEC Status
- DNSSEC queries may return inconsistent results across different DNS servers.
- Status: `inconclusive` when a DS or DNSKEY query fails (timeout, no reachable nameserver). The report adds the note "Status may vary across DNS servers", lowers DNS confidence and excludes the result from hardening findings. Cross-reference with authoritative NS.
- `enabled` means DS/DNSKEY indicators were found. Signatures and the chain of trust are not validated (`validation: not_performed`).

## Traceroute Connectivity
- Test domains (example.com) may not respond to traceroute probes.
- Status: Use real-world domain testing for accurate connectivity assessment.
- Firewall or ICMP filtering can suppress responsive hops.
- `connectivity_status` is `reachable` (ping answered), `http_accessible` (only HTTP/S answered), `unreachable` (every probe explicitly failed) or `unknown` (no evidence).
- Without `tracepath`/`traceroute` (Linux) or `tracert` (Windows) the NETWORK PATH block reports `unavailable` with an install hint; other modules are unaffected.

## Subdomain Discovery
- DNS-pattern-based discovery is not exhaustive.
- Wildcard DNS can cause false positives or incomplete results.
- Status: Supplementary only; use active reconnaissance for critical assessment.
