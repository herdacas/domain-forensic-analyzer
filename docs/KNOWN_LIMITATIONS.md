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

## VPN Detection (OPSEC block)
- Linux: a VPN is recognised when the interface that carries internet traffic is a WireGuard, tun or PPP device, or has a typical VPN name (`ip route get`, no packet sent). Works for any provider.
- Windows/macOS: only the rDNS keyword match on your external IP is available. Providers without branded reverse DNS (e.g. Proton) show "No known provider signatures observed" even while connected.
- `Attribution Risk` is `LOW` only with a VPN signal. NAT alone does not lower it.
- Status: Check `External IP` in the scan header to confirm the VPN exit address; the JSON report records the signal as `analyst.opsec.vpn_signal`.

## SecurityTrails Quota
- One scan uses up to 10 SecurityTrails requests: 4 from the SecurityTrails module (domain info, A and MX history, subdomains) and 6 from DNS history (A, AAAA, MX, NS, TXT, CNAME history).
- The free tier (50 requests/month) is therefore used up after roughly 5 scans.
- Status: When the quota is exhausted the module is reported as skipped (`quota_exceeded`) with a warning; all other modules continue.
