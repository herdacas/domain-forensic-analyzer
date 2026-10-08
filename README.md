# Domain Forensic Analyzer

[![Tests (main)](https://github.com/herdacas/domain-forensic-analyzer/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/herdacas/domain-forensic-analyzer/actions/workflows/test.yml)
[![Python](https://img.shields.io/badge/python-3.10%20|%203.11%20|%203.12-blue)](https://www.python.org)
[![Branch: dfapentesting](https://img.shields.io/badge/branch-dfapentesting-blue)](#scope-configuration-dfapentesting)

A terminal-based OSINT tool for comprehensive domain reconnaissance and forensic investigation.
This README describes **`dfapentesting`**, based on version 1.1.0, with UTC timestamps, redacted action traces and engine scope checks. See [Scope Configuration](#scope-configuration-dfapentesting) before a customer scan.

Local implementation validation: **447 tests passed**, including 43 security regressions. The current workflow triggers pushes to `main`, `feature/**`, `fix/**` and `refactor/**`, or pull requests to `main`; a push to `dfapentesting` alone does not trigger it. The badge above refers to `main`. Historical platform validation is listed below.

It provides broad domain forensic intelligence — from DNS configuration and certificate history to infrastructure fingerprinting, threat intelligence, and network path analysis. Coverage depends on resolvers, installed tools, provider availability, and API credentials. Designed for security analysts, incident responders, and researchers; findings require analyst interpretation.

See [SECURITY.md](SECURITY.md) for the OPSEC threat model (what this tool exposes to a scanned target), [CONTRIBUTING.md](CONTRIBUTING.md) if you want to work on it, and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for module layout and the report lifecycle.

---

## When to Use This Tool

**Good fit:**

- Broad initial reconnaissance of a domain
- OSINT research with transparent logging
- Forensic analysis of domain configuration
- Historical DNS change tracking
- Infrastructure and hosting provider assessment

**Not a fit:**

- Vulnerability scanning (use dedicated scanners)
- Deep subdomain enumeration (use specialized tools like subfinder)
- Social engineering assessment
- Real-time threat detection (use SOCs or IDS)

## Coverage

Eleven analyzer modules cover these areas of domain reconnaissance:

- **Active Probes:** DNS, TLS, HTTP/S, ping, traceroute and subdomain queries; AXFR is blocked by default and requires explicit scope permission
- **Passive APIs:** VirusTotal, AbuseIPDB, SecurityTrails, RobTex, Mnemonic, crt.sh, CertSpotter and HackerTarget
- **WHOIS Queries:** optional WhoisXML API with `python-whois` network fallback
- **Local Analysis:** certificate inspection and interpretation of DNSSEC/SPF/DMARC/DKIM records

Baseline DNS, TLS, HTTP, network and free-source history data can be available without API keys when the scope permits the required actions. Coverage depends on source availability. API keys unlock additional history and reputation data.

---

## What you get

A single structured report combining the available evidence for a domain investigation:

- **Who registered it** — registrar, creation date, expiry, registrant disclosure or privacy proxy detection, registry policy flags (DENIC, SIDN, and others that redact by policy)
- **Where it lives** — IP, ASN, hosting provider, CDN/WAF detection (Cloudflare, Akamai, Fastly, OVH, Hetzner, and more), geographic risk assessment
- **How it's configured** — supported DNS records with TTLs, SPF chain resolution, DMARC/DKIM/CAA and DNSSEC indicators; zone transfer testing is opt-in
- **What changed over time** — historical DNS timeline across Mnemonic PDNS, RobTex, VirusTotal, and certificate transparency logs; nameserver and MX migration events grouped by date
- **How it behaves** — HTTP→HTTPS redirect, HSTS, CSP, X-Frame-Options, TLS certificate metadata (issuer, SANs, expiry, negotiated version)
- **Who else is on that IP** — reverse-IP co-hosted domains from three passive sources
- **What the threat intel says** — VirusTotal domain reputation, AbuseIPDB IP score, AlienVault OTX passive DNS, observed hostnames and threat pulses
- **What the network path looks like** — traceroute with hop classification, ping latency
- **Risk summary** — heuristic score with specific factors listed (expired cert, newly registered, no HTTPS redirect, high geographic risk, etc.)

Inactive or expired domains fall into **historical analysis mode** automatically — the tool reconstructs what it can from passive sources without failing noisily.

---

## Quick Start

**Linux / Ubuntu:**

```bash
git clone --branch dfapentesting https://github.com/herdacas/domain-forensic-analyzer.git
cd domain-forensic-analyzer
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
sudo apt install iputils-ping iputils-tracepath traceroute   # optional network tools
python3 run.py example.com
```

**Windows:**

```powershell
git clone --branch dfapentesting https://github.com/herdacas/domain-forensic-analyzer.git
cd domain-forensic-analyzer
python -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt
python run.py example.com
```

No API keys are required for the example. Configure the scope for an approved customer engagement before changing the target. The supplied empty allowlists do not impose a positive target restriction; default hard exclusions and AXFR prohibition still apply. Available sources and results depend on the scope.

---

## Usage

```bash
# Single domain — argument or interactive prompt
python3 run.py example.com
python3 run.py

# Batch mode — one domain per line, # comments supported
python3 run.py --list domains.txt
```

**Input handling:**

- Subdomains are automatically stripped to apex (`aws.amazon.com` → `amazon.com`)
- Compound ccTLDs are preserved (`bbc.co.uk` stays `bbc.co.uk`)
- Internationalized domains are converted to punycode (`münchen.de` → `xn--mnchen-3ya.de`)
- IP addresses and file paths are rejected with a clear error

---

## Scope Configuration (`dfapentesting`)

The engine reads **`config/scope.json` in the project root** before metadata
collection and module initialization. The same rules apply to single-domain,
interactive and batch scans, including calls started through the OPSEC scripts.
There is currently **no `--scope` CLI option**. Edit the file before starting a
scan; changes are loaded at the next scan start (per domain in batch mode), not
by an already running worker.

### 1. Configure the engagement

Start with the supplied file. Replace the illustrative domain, documentation
IPs and dates below with the approved engagement values. The file must contain
valid JSON, without comments or trailing commas.

```json
{
  "engagement_id": "PT-2026-07",
  "valid_from_utc": "2026-10-20T08:00:00Z",
  "valid_until_utc": "2026-10-24T18:00:00Z",
  "source_ips_allowed": ["203.0.113.5/32"],
  "targets_allowed": {
    "domains": ["kunde-beispiel.de", "api.ipify.org"],
    "ips": ["192.0.2.10", "192.0.2.53", "203.0.113.5"],
    "ports": [43, 53, 80, 443],
    "paths": []
  },
  "targets_denied": {
    "domains": ["admin.kunde-beispiel.de"],
    "ips": ["192.0.2.99"]
  },
  "hard_exclusions": {
    "domains": ["payments.kunde-beispiel.de"],
    "ips": [],
    "cidrs": ["192.0.2.240/28"]
  },
  "methods_allowed": ["dns", "http_get", "tls", "ping", "traceroute", "whois", "route"],
  "methods_forbidden": ["dos", "ddos", "brute_force", "fuzzing", "axfr", "persistent_access"],
  "rate_limit_req_per_sec": 20,
  "notes": "Example only: replace every engagement value before use."
}
```

In this example, `192.0.2.10` represents a target IP, `192.0.2.53` a permitted
DNS resolver, and `203.0.113.5` the approved public source IP. The source appears
in the target list only to permit the metadata reverse-DNS lookup of that
address. `api.ipify.org` permits discovery of the current public source IP.
These IPs are documentation placeholders, not working scan destinations.

The example permits the customer domain and its subdomains, then excludes
`admin.kunde-beispiel.de` and `payments.kunde-beispiel.de`. It deliberately omits
other intelligence providers; their requests will be blocked until explicitly
approved and added. A denied IP is blocked when checked as an IP; the current
guard does not resolve every allowed hostname to enforce IP rules on its actual
connection peer. See the limitations below.

### 2. Add, remove or exclude targets

| Operation | Setting | Effect |
|---|---|---|
| Permit a domain | Add it to `targets_allowed.domains` | Permits the domain and all its subdomains, subject to other rules |
| Permit an IP/network | Add an IPv4/IPv6 address or CIDR to `targets_allowed.ips` | Permits matching IP targets; does not automatically permit their domains |
| Remove a permission | Remove the entry from `targets_allowed` | Blocks it only if another rule does not still permit it and the combined domain/IP allowlist remains nonempty |
| Exclude a domain | Add it to `targets_denied.domains` | Overrides allowed rules, including for its subdomains |
| Exclude an IP/network | Add an address or CIDR to `targets_denied.ips` | Overrides allowed IP rules |
| Add an absolute exclusion | Add a domain, IP or CIDR to `hard_exclusions` | Checked before engagement permissions; cannot be overridden by allowed |

**Important:** empty domain **and** IP allowlists mean unrestricted targets,
except denied and hard-excluded targets. Clearing the last allowed entry does
not disable scanning. Empty source, port, path and method allowlists also mean
no restriction of that kind; method prohibitions and the AXFR opt-in rule still
apply. The supplied template has empty allowlists and no time window. A missing
scope file produces a warning and `no_scope_loaded` trace entries, while default
hard exclusions and the default AXFR prohibition remain active.

Domain matching uses label boundaries: `kunde-beispiel.de` includes
`www.kunde-beispiel.de`, not `badkunde-beispiel.de`. This version cannot express
an apex-only domain permission through this field. The CLI also reduces entered
subdomains to their apex: entering `api.kunde-beispiel.de` scans
`kunde-beispiel.de`. A subdomain-only engagement therefore does not authorize the
effective apex target; do not broaden the allowlist just to make that scan run.

The default exclusion file is [`config/hard_exclusions_default.json`](config/hard_exclusions_default.json).
It protects the configured gateway, nameservers, payment, identity, messaging
and AI-service hosts. Defaults are combined with engagement exclusions. A
minimum list is also retained in code, so removing it from either JSON file or
adding it to allowed does not release those destinations.

### 3. Permit required services and set action restrictions

The guard checks the host actually named in the application call. A customer
domain permission does not permit its resolved IP, DNS resolver or API providers
automatically. Add the approved target IPs and infrastructure needed for the
selected investigation. For domain rules, paths and ports are separate fields,
not part of a `https://...` domain-list entry.

| Purpose | Hosts/addresses used by the current engine |
|---|---|
| Public source-IP discovery | `api.ipify.org`; fallback `checkip.amazonaws.com`, then `ipinfo.io` |
| DNS transport | Actual resolver IPs for the machine or VPN namespace; normally port 53 |
| Target probes | Resolved target IPs, target domain and permitted HTTP redirect hosts |
| Geolocation | `ip-api.com` (HTTP, port 80) |
| Optional keyed APIs | `whoisxmlapi.com`, `www.virustotal.com`, `api.abuseipdb.com`, `api.securitytrails.com` |
| Free history and reverse-IP sources | `freeapi.robtex.com`, `api.mnemonic.no`, `crt.sh`, `api.certspotter.com`, `api.hackertarget.com` |
| Analyst metadata | Observed public source IP for reverse DNS; `8.8.8.8` is used for local route selection, without sending a probe packet |

API base URLs can be configured separately, so approve the hosts actually used
by your configuration. Allowing `8.8.8.8` in the general target list is a general
IP permission, not a route-only permission. It may instead remain blocked; that
can leave local-IP or VPN metadata incomplete.

`source_ips_allowed` accepts addresses and CIDRs for the **public** egress IP,
not merely a private WireGuard interface address. When set, an unknown or
nonmatching source blocks normal actions. The initial fixed source-IP discovery
GET can run before its source is known; all other applicable scope rules still
apply. Direct and VPN runs may need different source permissions.

`valid_from_utc` and `valid_until_utc` accept ISO 8601 values with a timezone.
`Z` means UTC; offsets such as `+02:00` are also accepted. Empty bounds impose
no limit on that side. Outside the time window, new guarded actions are skipped.
`engagement_id` and `notes` are descriptive fields, not additional permissions.

Methods use these exact guard labels:

| Label | Action |
|---|---|
| `dns` | DNS records, resolver probes and subdomain DNS queries, including `nslookup` |
| `http_get` / `http_post` | HTTP request and redirect hops; current analyzer calls use GET |
| `tls` | TLS handshake, including certificate-verification fallback |
| `ping` / `traceroute` | External network tools |
| `whois` | The `python-whois` lookup; WhoisXML uses `http_get` |
| `route` | Local `ip route get` metadata query |
| `axfr` | Zone transfer; requires explicit permission |

An entry in `methods_forbidden` wins over `methods_allowed`. Method rules use the
labels assigned by the application: forbidding `brute_force` alone does not
disable the existing common-name subdomain queries, which use `dns`.
AXFR is blocked by default. To enable it, an engagement must explicitly permit
`axfr`, remove it from `methods_forbidden`, and permit the required DNS queries
and nameserver targets. Skipped AXFR is reported as `blocked_by_scope`, not as
proof that the server refuses zone transfers.

`targets_allowed.ports` contains integer ports. It applies when a guarded action
supplies a port; it does not restrict every internal packet of an external tool.
`targets_allowed.paths` restricts checked HTTP URL paths: `/api` includes `/api`
and `/api/...`, not `/apix`. Paths do not select a scan starting URL: the current
HTTP probe starts at `/`, so an `/api`-only policy blocks that root request.
These rules apply globally, including to provider APIs and source-IP discovery.
`rate_limit_req_per_sec` must be positive and limits admission of guarded actions
across workers, not network packets. Very low rates can cause module timeouts.

### 4. Check configuration, start the scan and inspect decisions

Validate the file without starting network activity:

```bash
python -m json.tool config/scope.json
python -c "from pathlib import Path; from src.core.scope_config import ScopeConfig; ScopeConfig(Path('config/scope.json')); print('Scope configuration valid')"
```

Use the project environment (`.venv/bin/python` on Linux or
`.venv\Scripts\python.exe` on Windows) if `python` is not its interpreter.
Then use the existing commands with the approved effective domain:

```bash
python run.py kunde-beispiel.de
python run.py --list domains.txt
```

No extra scope flag is required. Check `trace_file` in the JSON report, or open
`logs/<target>_<UTC-date-time>_<id>/trace.jsonl`. Each line contains
`timestamp_utc`, `action_type`, `tool`, redacted `command`, `target`, known
`source_ip`, `scope_decision` and `block_reason`.

| Trace reason | What to check |
|---|---|
| `not_in_allowlist` | Effective domain, resolved IP, resolver or provider host lacks permission |
| `denied: ...` / `hard_exclusion: ...` | Explicit or absolute exclusion matched |
| `outside_timewindow` | Current time and configured timezone-aware bounds |
| `source_ip_unknown` / `source_ip_not_allowed` | Approved egress IP and permission for source-IP discovery |
| `method_forbidden: ...` / `method_not_in_allowlist: ...` | Method rules; forbidden always wins |
| `port_not_allowed` / `path_not_allowed` | Global port/path restrictions, including root requests and APIs |

A blocked action is skipped; the scan can continue with partial results. A
`COMPLETE` batch status does not prove every action was allowed. Some older
result fields still represent unavailable data without a dedicated scope-skip
status, so read the trace before interpreting missing results. Invalid JSON or
invalid scope values prevent that scan from starting; a failed trace write
prevents the affected guarded action.

**Limits:** source metadata is an observed egress address, not a per-socket
verification or source binding. Application guards do not fully control hidden
DNS/WHOIS referrals, proxy traffic, transport-internal lookups or DNS rebinding.
Running workers are not forcibly terminated on timeout or policy-file edits.
For implementation details and the remaining limitations, see
[`docs/PENTESTING_IMPLEMENTATION.md`](docs/PENTESTING_IMPLEMENTATION.md).
`config/scope.json` is a tracked template: keep real engagement data out of
public commits. Direct `run.py` uses the engine scope but does not run the
separate OPSEC baseline gate or load `opsec-iprange/freigaben.json`.

---

## Report Output

Completed scans are exported to `reports/<id>_<domain>.json`. Console stdout is captured and redacted to `reports/raw/<id>_<domain>.txt`. Aborted scans and export failures may not produce a complete report set.

Reports are written automatically—no flags needed.

Every new measurement has its own directory under `logs/`, named with the
effective scan target, UTC date/time and a collision-resistant ID. Both the
session log and trace are stored there:

```text
logs/
  example.com_2026-10-13_17-30-00Z_1a2b3c4d5e6f/
    domain_analyzer.log
    trace.jsonl
```

Batch scans create one such directory per domain. Repeated scans of the same
domain receive separate directories even within the same second. The JSON
report's `trace_file` points to the trace in its measurement directory.


### File formats and report references

| File | Format and contents |
|---|---|
| `domain_analyzer.log` | UTF-8 plaintext session messages with UTC time, level and context |
| `trace.jsonl` | UTF-8 JSON Lines; one standalone JSON object per recorded action/scope decision before execution |
| `reports/<id>_<domain>.json` | Structured result with `scan_id`, `timestamp`, `domain`, `session_id`, `trace_file`, `scan_duration_seconds`, `analyst` and `result` |
| `reports/raw/<id>_<domain>.txt` | Redacted captured console stdout, including ANSI codes |
| `reports/batch/BATCH_<id>_<listname>.json` | Batch summary and per-domain entries under `scans` |

`trace_file` is a top-level field in individual JSON reports and a field under
`scans[]` in batch reports. It contains the trace path; the session log is in the
same directory. JSON/TXT reports remain under `reports/`. Older files directly
under `logs/` are not automatically migrated.

A trace line has this schema (formatted here for readability; IPs are
illustrative documentation addresses):

```json
{
  "timestamp_utc": "2026-10-13T17:30:00Z",
  "action_type": "subprocess",
  "tool": "ping",
  "command": "ping -c 3 192.0.2.10",
  "target": "192.0.2.10",
  "source_ip": "203.0.113.5",
  "scope_decision": "allowed",
  "block_reason": ""
}
```

`allowed` records admission, not command success. `blocked` skips the action and
records its reason. `no_scope_loaded` means engagement rules were not loaded,
while default exclusions still apply. `source_ip` may be empty before discovery.
The trace does not contain complete stdout, stderr, return codes or response
bodies. Session messages, scope decisions and aggregated findings are separate
artifacts.

With Loguru, the session log rotates at 50 MB; additional rotated log files stay
in the same measurement directory. The JSONL trace has no configured rotation.

Optional OPSEC helper packages keep their own `ergebnisse/` measurement JSON,
console logs and source-disclosure Markdown documents. Those outputs are
separate from the engine's `logs/` and `reports/` directories.

- Batch mode (`--list`) writes the same per-domain JSON and raw files, plus one consolidated `reports/batch/BATCH_<id>_<listname>.json`.
- The console capture retains ANSI color codes but applies credential redaction. Muted worker output and separate stderr are not fully captured; it is not a complete subprocess trace.
- `logs/<target>_<UTC-date-time>_<id>/trace.jsonl` records pre-action scope decisions. JSON reports include `trace_file`.
- `logs/<target>_<UTC-date-time>_<id>/domain_analyzer.log` contains session messages and context, including with the standard-logging fallback.
- Timestamps are UTC with a timezone indication: report ISO timestamps include an offset, trace timestamps end in `Z`.
- The CLI uses fixed project-root `reports/` and `logs/` paths; `OUTPUT_DIRECTORY` is not wired into the exporter.
- `reports/` and `logs/` are git-ignored. They retain target, registrant and analyst metadata, including IPs. Redaction is not anonymization; treat them as engagement working data.
- Programmatic callers can use `ReportExporter(debug=False)` to write JSON only.
- Export failures are reported to stderr and never interrupt the scan.

---

## Running Through a VPN

Permitted active probes use the route selected by your system or namespace. A VPN can provide its exit address when routing and DNS are correctly configured; the header alone does not prove every connection uses it. AXFR is blocked by default. Passive API requests expose your source IP to the API provider, generally not to the investigated target.

| Setup | Best for | What goes through the VPN |
|---|---|---|
| **A: VPN app on your machine** | Windows, Linux desktop, laptop | All traffic of that machine |
| **B: Linux network namespace** | A server you manage over SSH | Only the analyzer. SSH and every other service keep their normal route |

### Option A: VPN app (Windows, Linux desktop)

1. Connect your VPN client (for example Proton VPN).
2. Run the scan as usual: `python run.py example.com`.
3. Check the report header (see [Checking that the VPN is used](#checking-that-the-vpn-is-used)).

Check that the scope permits the VPN resolver, approved public VPN egress and required services. The DNS module first probes permitted configured resolvers on TCP port 53. When none responds, it can fall back to the permitted configured set; reachability and scope restrictions still affect results.

### Option B: Linux server, VPN for the analyzer only

Turning on a system-wide VPN on a remote server replaces its default route and can cut your own SSH session. Instead, the WireGuard tunnel lives in a separate Linux network namespace, and only the analyzer is started inside it. The host's routing table is never touched.

**Tech stack**

| Component | Role |
|---|---|
| WireGuard (kernel module + `wireguard-tools`) | The VPN tunnel. Any provider that offers WireGuard config files works; validated with Proton VPN |
| `iproute2` (`ip netns`) | The network namespace that holds the tunnel |
| `/etc/netns/<name>/resolv.conf` | DNS server used inside the namespace (the VPN's resolver, e.g. `10.2.0.1` for Proton) |
| `nftables` (optional) | Rule that only allows DNS to the VPN resolver, so no DNS query can leak past the tunnel |
| `sudo` | `ip netns exec` needs root; the scan itself runs as your normal user again |

<details>
<summary><b>One-time setup</b> (root; take address, DNS and file name from the <code>[Interface]</code> section of your WireGuard config)</summary>

```bash
sudo apt install wireguard-tools iproute2
sudo ip netns add vpn
sudo ip link add wg0 type wireguard        # created on the host, so the tunnel's own UDP traffic uses the normal uplink
sudo ip link set wg0 netns vpn             # then moved into the namespace
sudo bash -c 'wg-quick strip /etc/wireguard/proton.conf | ip netns exec vpn wg setconf wg0 /dev/stdin'
sudo ip -n vpn addr add 10.2.0.2/32 dev wg0          # [Interface] Address
sudo ip -n vpn link set lo up
sudo ip -n vpn link set wg0 up
sudo ip -n vpn route add default dev wg0
sudo mkdir -p /etc/netns/vpn
echo "nameserver 10.2.0.1" | sudo tee /etc/netns/vpn/resolv.conf   # [Interface] DNS
```

The namespace is gone after a reboot. To keep it permanently, put these commands into a systemd oneshot service.
</details>

**Optional check before scanning.** It should show a recent handshake, an IP that is not your server's, and the VPN resolver:

```bash
sudo ip netns exec vpn sh -c 'wg show wg0 latest-handshakes; curl -s https://api.ipify.org; echo; cat /etc/resolv.conf'
```

**Run a scan through the tunnel:**

```bash
sudo ip netns exec vpn sudo -u "$USER" /path/to/domain-forensic-analyzer/.venv/bin/python /path/to/domain-forensic-analyzer/run.py example.com
```

`ip netns exec vpn` moves only this one process into the tunnel. `sudo -u "$USER"` drops root again, so the files in `reports/` and `logs/` belong to you. Batch mode works the same way with `--list domains.txt`.

### Checking that the VPN is used

The header printed at the start of every scan (and the `analyst` block of the JSON report) shows it right away:

| Field | Without VPN | Through the VPN |
|---|---|---|
| `External IP` | your own public IP | the VPN exit IP |
| `Local IP` | your LAN address (e.g. `192.168.x.x`) or, on a server, its public IP | the tunnel address (e.g. `10.2.0.2`) |
| `VPN/Proxy Signals` (Linux) | No known provider signatures observed | VPN tunnel detected (internet route via `wg0`) |
| `Attribution Risk` | MEDIUM | LOW, as soon as a VPN signal is present |

`External IP` is the address observed by an allowed discovery service. It may be `Unknown` when that service is blocked or unavailable, and is not a per-connection source guarantee. Scope restrictions can also suppress local route or reverse-DNS metadata. The remaining fields depend on what the tool can detect:

- **Linux:** the tool asks the kernel which interface carries internet traffic. A WireGuard, tun or PPP interface (or a typical VPN name such as `wg*`, `tun*`, `proton*`) is shown as "VPN tunnel detected" and lowers `Attribution Risk` to LOW. This works for any provider and for the namespace setup above. The JSON report stores it as `analyst.opsec.vpn_signal: "tunnel_interface"`.
- **Windows and macOS:** only a reverse-DNS keyword check is available. Many providers (Proton included) don't use such names, so the line often stays at "No known provider signatures observed" and `Attribution Risk` stays MEDIUM even while the VPN is on.
- `Network Topology: Behind NAT` only means your machine has a private address. It does not hide you: the target still sees your router's public IP, so NAT alone never lowers `Attribution Risk`.

These differences are expected and not errors: a CDN-hosted target may resolve to a different edge IP, the traceroute is usually shorter, and DNSSEC is checked through whichever resolver is active. A resolver that does not answer DS/DNSKEY queries gives `inconclusive`, never "not enabled".

---

## API Keys (optional)

Add keys to unlock historical DNS, reputation data, and deeper WHOIS intelligence.

**Option A — environment variables:**

```bash
export VIRUSTOTAL_API_KEY="your_key"
export ABUSEIPDB_API_KEY="your_key"
export WHOISXML_API_KEY="your_key"
export OTX_API_KEY="your_key"
# optional, no longer in the default pipeline:
# export SECURITYTRAILS_API_KEY="your_key"
```

**Option B — config file** (`config/api_keys.json`, git-ignored):

```json
{
  "virustotal":     { "api_key": "YOUR_KEY" },
  "abuseipdb":      { "api_key": "YOUR_KEY" },
  "whoisxml":       { "api_key": "YOUR_KEY" },
  "otx":            { "api_key": "YOUR_KEY" }
}
```

The project-root `.env` is also loaded without overwriting process environment variables. Valid environment keys take priority over the JSON file; empty values and template placeholders fall back to JSON. Both flat (`"virustotal": "key"`) and nested entries are supported. Shodan and Censys are not integrated modules.

| Source | Key | Use |
|--------|-----|-----|
| WHOIS enrichment | `WHOISXML_API_KEY` | Registration data |
| Domain & IP reputation | `VIRUSTOTAL_API_KEY` | Reputation and resolutions |
| IP abuse score | `ABUSEIPDB_API_KEY` | Reported abuse |
| Passive DNS, hostnames, threat pulses | `OTX_API_KEY` | AlienVault OTX (free account); default passive-intel source |
| Historical DNS (optional, not in default pipeline) | `SECURITYTRAILS_API_KEY` | Domain details, history and subdomains |

Quotas and available datasets depend on the provider account. Check your account's allowance before batch runs; the configured request-admission rate is not a provider quota counter.

Dedicated keyed clients without a configured key are skipped. WHOIS can fall back to `python-whois`; history modules can still use free sources. Scope permission remains required in every case.

---

## Report Structure

```
SUMMARY           — overall risk, key factors, recommendation
TARGET            — resolved IPs, nameservers, mail servers
GEO & ASN         — country, city, ASN, ISP, hosting type, geographic risk
WHOIS             — registration details, privacy proxy, registry policy
DNS FORENSICS     — full record set, email security, DNSSEC
DNS HISTORY       — IP/NS/MX change timeline across passive sources
NETWORK PATH      — traceroute with hop classification, latency
HTTP/S BEHAVIOR   — redirect chain, HSTS, CSP, X-Frame-Options
SSL / TLS         — certificate issuer, validity, SANs, TLS version
INFRASTRUCTURE    — CDN/WAF/hosting provider, edge protection
ATTACK SURFACE    — discovered subdomains, sensitive asset candidates
THREAT INTELLIGENCE — VT domain score, AbuseIPDB IP score, AlienVault OTX
IP & DOMAIN HISTORY — reverse-IP co-hosted domains, historical IPs
RISK ASSESSMENT   — heuristic score with specific risk factors
EXECUTION         — module timing, API coverage, log reference
```

---

## Platform Compatibility

The table records historical 1.1.0 baseline validation. The new `dfapentesting` scope integration has been tested locally; these entries do not claim a fresh manual Windows/VPN validation of this branch.

| Platform | Python | Status |
|---|---|---|
| Windows 10/11 (PowerShell) | 3.10 – 3.12 | ✅ Validated — CI + manual cross-platform scenarios (direct + VPN) |
| Linux (Ubuntu) | 3.10 – 3.12 | ✅ Validated — CI + manual cross-platform scenarios (direct + VPN) |
| macOS | 3.10 – 3.12 | ⚠️ Should work (no OS-specific code paths beyond the Windows/Linux traceroute split) but not covered by CI or manual validation — report issues if you hit one |

Windows uses `tracert`; Linux prefers `tracepath` and falls back to `traceroute` (auto-detected). Missing path tools degrade the NETWORK PATH block gracefully instead of failing the scan. See [`docs/VALIDATION_REPORT.md`](docs/VALIDATION_REPORT.md) for the historical cross-platform validation results (4 scenarios: Windows/Linux × direct connection/VPN).

## Network Dependencies (Linux)

The tool uses `tracepath` or `traceroute` for network path analysis.

| Binary | Used for | Install |
|--------|----------|---------|
| `ping` | Latency check | `sudo apt install iputils-ping` |
| `tracepath` | Network path (preferred) | `sudo apt install iputils-tracepath` |
| `traceroute` | Network path (fallback) | `sudo apt install traceroute` |

If neither traceroute tool is available, the NETWORK PATH module gracefully reports unavailable. All other modules continue normally. CI installs all three binaries.

---

## Security Notes

- Active probes can be visible to the target, its authoritative DNS infrastructure and network intermediaries. They are subject to the engine scope; AXFR is blocked by default.
- Passive APIs (VirusTotal, AbuseIPDB, AlienVault OTX, RobTex, Mnemonic, crt.sh) do not expose your IP to the target.
- For low-footprint investigations, run the scan through a VPN. See [Running Through a VPN](#running-through-a-vpn).
- VPN detection in the OPSEC block checks the tunnel interface of the internet route (Linux) and the reverse DNS of your external IP (all platforms). On Windows and macOS it misses providers without branded hostnames (see [SECURITY.md](SECURITY.md)). Don't treat "not detected" as proof no VPN is active.
- Do not commit `config/api_keys.json` or `.env` files. Review the tracked `config/scope.json` for real engagement data before publishing.
- Trace, JSON and console-file redaction covers defined credential patterns and known keys; unusual encodings may require additional filters.

Full threat model, data-handling notes, and known security-relevant limitations: [SECURITY.md](SECURITY.md).

---

## Example Reports

Real scan output (`example.com`) from the Phase 4 cross-platform validation, one per platform/network combination:

| Scenario | File |
|---|---|
| Linux, direct connection | [`docs/examples/scenario_a_linux_direct.json`](docs/examples/scenario_a_linux_direct.json) |
| Linux, VPN | [`docs/examples/scenario_b_linux_vpn.json`](docs/examples/scenario_b_linux_vpn.json) |
| Windows, direct connection | [`docs/examples/scenario_c_windows_direct.json`](docs/examples/scenario_c_windows_direct.json) |
| Windows, VPN | [`docs/examples/scenario_d_windows_vpn.json`](docs/examples/scenario_d_windows_vpn.json) |

These are historical structured exports. They illustrate the baseline field set; they predate `trace_file` and the new scope-decision JSONL trace. A raw console capture (what you'd see in the terminal, ANSI codes included) is at [`docs/vpn_pretest_windows.txt`](docs/vpn_pretest_windows.txt).

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `UnicodeEncodeError: 'charmap' codec can't encode characters` | Legacy Windows console (cp1252) rendering `├──` box-drawing characters | Fixed as of the UTF-8 console reconfiguration in `run.py` — if you still see this, make sure you're running `run.py` directly (not importing `domain_analyzer` in a script without the same startup) |
| Module marked `FAILED` immediately after starting a VPN | DNS query sent to a nameserver blocked by the VPN's routing (commonly seen with ProtonVPN, which blocks port 53 to the physical adapter's DNS) | Check both resolver scope permissions and VPN routing. Permitted resolvers are probed first; a fallback set is used if none responds. Inspect the trace for blocked resolver calls before interpreting unavailable DNS data |
| Inside a network namespace: DNS module fails, `Temporary failure in name resolution` | `/etc/netns/<name>/resolv.conf` is missing, so the namespace has no usable resolver | Create it with the VPN's DNS server (see [Option B](#option-b-linux-server-vpn-for-the-analyzer-only)) |
| Inside a network namespace: ping shows not reachable, everything else works | Started from a systemd service with `NoNewPrivileges`, which ignores ping's `cap_net_raw` capability | Allow unprivileged ICMP in the namespace: `sudo ip netns exec vpn sysctl -w net.ipv4.ping_group_range="0 2147483647"` |
| `DNS History: UNAVAILABLE` or a `NameError` in `dns_history_analyzer.py` | Missing `import json` (fixed in a past release) or a source returning malformed data | Use the current `dfapentesting` checkout — this was a known bug fixed pre-1.0 |
| A module reports "no API key" even though one is set in `config/api_keys.json` | Invalid JSON, a placeholder key, or a different project checkout | Check the project-root config file and key; placeholders in `.env` fall back to JSON |
| `192.168.0.1` or similar gets scanned instead of rejected | You're on an older build — IP-address rejection was added in a later 1.0.x-track fix | Use the current `dfapentesting` checkout |
| Traceroute/ping section shows "not available" | `traceroute`/`tracepath`/`ping` binary not installed (Linux) or blocked by a firewall | `sudo apt install iputils-ping traceroute` — the rest of the report is unaffected either way |
| `SecurityTrails` is skipped or quota exceeded | Missing key, provider allowance exhausted, or request blocked by scope | Check the key, account allowance and trace; the configured scope rate does not replenish provider quotas |
| `crt.sh` certificate history missing | crt.sh is a shared community service and occasionally rate-limits or times out | The tool retries automatically, then falls back to CertSpotter. If both fail, `Certificate History` shows `not available (all sources failed)` — this is upstream flakiness, not a bug |
| Domain shows `HISTORICAL ANALYSIS (domain inactive)` but you know it's live | DNS resolution unavailable, blocked by scope, or affected by network/VPN problems | Check scope decisions in the trace before treating missing DNS data as proof of an inactive domain |
| Actions are skipped or data is missing despite `COMPLETE` | Scope restriction or unavailable source | Open `trace_file` and inspect `scope_decision` / `block_reason` |
| `source_ip_unknown` | Source discovery blocked/unavailable while source allowlist is set | Permit an approved discovery service and verify the observed public egress |
| `outside_timewindow` | Current time is outside the configured bounds | Check approved UTC/offset bounds; change them only to the agreed window |
| `method_forbidden: axfr` | Default AXFR prohibition | Keep it blocked unless explicitly permitted; opt-in also requires DNS/nameserver permission |

## FAQ

**Do I need API keys to use this?**
No. Permitted active probes and free APIs can provide baseline coverage. Configure the scope for the engagement and allow the required providers/resolvers; coverage varies. API keys unlock additional WHOIS, reputation and history data.

**Does this tool actively exploit or attack the target?**
It performs reconnaissance: DNS queries (including common subdomain-name candidates), HTTP requests, TLS handshakes and network probes. It has no exploit or password-guessing module. AXFR is disabled by default and requires explicit scope permission. Method labels are not an automatic classifier of every testing technique; consult the scope trace and the baseline [SECURITY.md](SECURITY.md) threat model.

**Will the target know I scanned them?**
Possibly. Allowed DNS, HTTP, TLS and network probes can appear in the target's or its infrastructure providers' logs. AXFR is blocked unless explicitly enabled. Passive lookups contact intelligence providers, which can observe your source and the submitted target.

**Why does GEO & ASN sometimes show empty or `null` fields?**
Geolocation and ASN data come from `ip-api.com` (free tier, no key). Coverage varies by IP range and CDN provider — some anycast/CDN IPs don't carry meaningful ASN data through that API. ASN fields showing as `null` even when `ip-api.com` did return them was a field-mapping bug in the result aggregator (fixed in a post-1.0 release); use the current `dfapentesting` checkout if you still see this.

**Can I run this against a batch of domains unattended?**
Yes — `python run.py --list domains.txt`. Scope and trace are initialized per domain. `MODULE_TIMEOUTS` limits how long the orchestrator waits, but a timed-out worker is not forcibly cancelled and can finish later. Low scope rates may exhaust a module's wait budget.

**Does it work on macOS?**
Almost certainly, since there's no macOS-specific code path missing, but it hasn't been part of CI or the manual cross-platform validation — see the Platform Compatibility table above.

---

## Known Limitations

- WHOIS registrant fields are redacted by registry policy for several ccTLDs (DENIC/DE, SIDN/NL, SWITCH/CH, and others) — the report flags this explicitly rather than showing empty fields.
- AlienVault OTX and VirusTotal history depth depends on account tier and provider PDNS coverage.
- Subdomain discovery uses common-name DNS patterns. Wildcard detection narrows the candidate list; responses may still be wildcard results and need verification.
- Certificate Transparency shows issuance history, not authoritative DNS. Wildcard-only certs (`*.domain.com`) produce no subdomain entries by design.
- The risk model is heuristic — treat it as a starting point for investigation, not as a conclusive judgement.
- JSON and terminal reports use the same domain risk assessment. The numeric score uses severity anchors (medium ≥5, high ≥8) and asset counts; it is not a calibrated probability. `module_risk_factors` records the contributing module. Network OPSEC risk assesses analyst exposure separately from target-domain risk.
- `modules_successful` means a completed live module, not validated correctness of every field. `modules_skipped` includes missing-key and quota states; demo output is tracked in `modules_demo` and excluded from live provenance and risk scoring. Confidence values describe heuristic coverage, not statistical certainty.
- DNSSEC `enabled` means DS/DNSKEY indicators were found, not that signatures or the trust chain were validated. Failed queries report `inconclusive`. Missing ASN values are reported as `unavailable` with a warning; partial traceroutes do not establish anonymity or target unreachability. Details: [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md).
- Empty scope allowlists remain permissive. Denied and hard-exclusion rules still apply; configure the engagement before customer scans.
- Scope skips can leave partial data even when the batch status is `COMPLETE`; inspect the trace. Hostname permissions do not guarantee that a resolved peer IP is allowed.
- Application guards do not fully control transport-internal DNS/WHOIS referrals, proxies or DNS rebinding. Trace records admission, not full stdout/stderr/return-code results.
- This branch's scope behavior is documented above and in [docs/PENTESTING_IMPLEMENTATION.md](docs/PENTESTING_IMPLEMENTATION.md); older security/architecture documents describe the baseline and may predate it.
