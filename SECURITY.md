# Security Policy

## Reporting a vulnerability

If you find a security issue in this tool itself (not in a domain you scanned with it), open a GitHub issue or contact the maintainer directly for anything sensitive (credential handling, code execution, etc.) rather than filing it publicly. Include reproduction steps and the affected module/file.

This is an OSINT/reconnaissance tool, not a hardened multi-tenant service — the threat model below assumes a single analyst running it locally or on a controlled server, not exposure as a public API.

---

## OPSEC: what this tool exposes to the target

Domain Forensic Analyzer mixes **active probes** (the target's infrastructure sees your IP) with **passive API lookups** (only the API provider sees your IP, never the target). Know which is which before scanning something sensitive.

### Active probes — target sees your IP

| Probe | What it touches |
|---|---|
| DNS resolution | Direct query to the domain's authoritative nameservers |
| Zone transfer (AXFR) attempt | Direct TCP connection to authoritative nameservers |
| Traceroute / tracepath | ICMP/UDP packets routed toward the target IP |
| Ping | ICMP echo to the target IP |
| HTTP/S connectivity check | Direct HTTP(S) request to the domain |
| Subdomain DNS probes | DNS queries for candidate subdomains |
| SSL/TLS handshake | Direct TCP connection to `target:443` |

### Passive sources — target never sees your IP

VirusTotal, AbuseIPDB, WhoisXML, SecurityTrails, RobTex, HackerTarget, Mnemonic PDNS, crt.sh, CertSpotter, ip-api.com. These query third-party databases, not the target's own infrastructure.

The tool reports this split explicitly in the **OPSEC Assessment** block of every scan (`Active Probes` / `Passive Sources` sub-lists), and computes an `Attribution Risk` / `Stealth Level` from it. `Stealth Level` has a floor of `MEDIUM`, never `LOW` — active probes always run, so a scan is never fully passive, and the tool doesn't claim otherwise.

### Reducing your footprint

- Route the whole scan through a VPN at the **OS level** before starting — the tool has no built-in proxy support, so anything less than an OS-level route (env vars, `requests` proxy config, etc.) will not cover the raw-socket probes (ping, traceroute, zone transfer).
- VPN/proxy detection in the OPSEC block is **rDNS keyword matching only** (looks for known provider strings — `nordvpn`, `protonvpn`, etc. — in the reverse DNS of your own external IP). Providers that route through third-party infrastructure without provider-branded hostnames (e.g. ProtonVPN via Datapacket/M247) will **not** be detected — this is a known, accepted limitation, not a bug. Don't rely on the tool's own OPSEC block to confirm your VPN is active; verify independently (`curl https://ipinfo.io`) before scanning.
- Expired/inactive domains automatically fall back to **historical analysis mode**, which skips all active probes (no current IP to probe) and relies entirely on passive sources.

---

## API keys and secrets

- Keys are read from environment variables first, then `config/api_keys.json`.
- `config/api_keys.json` and `.env` are git-ignored — **never commit them**. If you accidentally commit one, rotate the key immediately; removing it from a later commit does not remove it from git history.
- A placeholder value left in `.env` (e.g. `VIRUSTOTAL_API_KEY=your_key_here`) silently overrides a real key set elsewhere, because `.env` is loaded via `load_dotenv()` and `os.getenv()` prefers it — if a module reports "no API key" unexpectedly, check `.env` for a stale placeholder line before assuming the key in `config/api_keys.json` is broken.
- No key is ever printed in report output or logs. Modules without a configured key are marked `skipped` in the execution summary, not silently degraded.

## Data handling

- Every scan writes a JSON report to `reports/` and a raw console capture to `reports/raw/` by default — both are git-ignored. These contain the full scan output, including any WHOIS/registrant data returned by upstream sources. Treat `reports/` as sensitive working data, not something to share or commit.
- The tool makes outbound requests to third-party APIs (listed above) with the target domain/IP as a parameter. Read each provider's own privacy policy if that matters for your engagement.

## Known security-relevant limitations

- **No rate limiting or backoff beyond per-source retry logic** — running this against a target that actively monitors for reconnaissance (WAF, IDS) may trigger alerts. This is a single-scan tool, not designed for stealth against a defended target.
- **Zone transfer (AXFR) probe** is a legitimate, standard reconnaissance technique but will appear in a target's DNS logs as an AXFR attempt from your IP.
- **No authentication or access control** on the tool itself — it runs locally under whatever permissions the invoking user has. Don't run it as a shared service without adding your own access layer.
- **Subdomain DNS probing** sends DNS queries for a wordlist of common subdomain candidates — this is passive-looking traffic to the target's DNS infrastructure but is still active querying, not a passive lookup.

## Scope

This tool is intended for domains you are authorized to investigate — your own infrastructure, engagements with explicit client authorization, or public research targets where active probing (DNS, ping, traceroute, TLS handshake) is not itself a policy violation. Zone transfer attempts and subdomain enumeration are standard OSINT techniques but can look like reconnaissance to a defended target; use judgment.
