"""
Module Performance Benchmark
=============================
Runs each of the 11 analyzer modules individually against a real domain,
measures wall-clock time, and validates against the configured MODULE_TIMEOUTS.

Usage:
    python tests/test_module_performance.py [domain]

Default test domain: github.com
"""

import sys
import time
import traceback
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))

from config.settings import MODULE_TIMEOUTS

# ── colour helpers (no external deps) ─────────────────────────────────────────
RESET = "\033[0m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
DIM = "\033[2m"
BOLD = "\033[1m"

def ok(s):    return f"{GREEN}{s}{RESET}"
def warn(s):  return f"{YELLOW}{s}{RESET}"
def fail(s):  return f"{RED}{s}{RESET}"
def info(s):  return f"{CYAN}{s}{RESET}"
def dim(s):   return f"{DIM}{s}{RESET}"
def bold(s):  return f"{BOLD}{s}{RESET}"

# ── module imports ─────────────────────────────────────────────────────────────
def _import_modules():
    from src.analyzers.dns_analyzer import DNSAnalyzer
    from src.analyzers.whois import get_whois
    from src.analyzers.dns_history_analyzer import DNSHistoryAnalyzer
    from src.analyzers.cdn_detector import CDNDetector
    from src.analyzers.network_intelligence import NetworkIntelligence
    from src.analyzers.subdomain_scanner import SubdomainScanner
    from src.analyzers.ssl_analyzer import SSLAnalyzer
    from src.analyzers.securitytrails_client import SecurityTrailsClient
    from src.analyzers.abuseipdb_client import AbuseIPDBClient
    from src.analyzers.virustotal_client import VirusTotalClient
    from src.analyzers.ip_history_analyzer import IPHistoryAnalyzer
    return {
        'dns':            DNSAnalyzer(),
        'whois':          get_whois,
        'dns_history':    DNSHistoryAnalyzer(),
        'cdn':            CDNDetector(),
        'network':        NetworkIntelligence(),
        'subdomain':      SubdomainScanner(),
        'ssl':            SSLAnalyzer(),
        'securitytrails': SecurityTrailsClient(),
        'abuseipdb':      AbuseIPDBClient(),
        'virustotal':     VirusTotalClient(),
        'ip_history':     IPHistoryAnalyzer(),
    }

# ── run one module and capture time + status ──────────────────────────────────
def _run(name: str, module: Any, domain: str, ip: Optional[str],
         rdns: Optional[str]) -> Tuple[float, str, str, Optional[Dict]]:
    """Returns (elapsed_seconds, status, detail, result_dict)."""
    start = time.monotonic()
    detail = ""
    r: Optional[Dict] = None
    try:
        if name == 'dns':
            r = module.analyze_domain(domain)
        elif name == 'whois':
            r = module(domain)
        elif name == 'dns_history':
            r = module.analyze_dns_history(domain)
        elif name == 'cdn':
            if not ip:
                return 0.0, 'SKIP', 'no IP (dns failed)', None
            r = module.analyze_infrastructure(ip, domain, rdns)
        elif name == 'network':
            if not ip:
                return 0.0, 'SKIP', 'no IP (dns failed)', None
            r = module.analyze_network(ip, domain)
        elif name == 'subdomain':
            r = module.scan_subdomains(domain)
        elif name == 'ssl':
            r = module.analyze_ssl(domain)
        elif name == 'securitytrails':
            r = module.analyze_domain_intelligence(domain)
        elif name == 'abuseipdb':
            if not ip:
                return 0.0, 'SKIP', 'no IP (dns failed)', None
            r = module.analyze_ip_reputation(ip, domain)
        elif name == 'virustotal':
            r = module.analyze_domain_reputation(domain)
        elif name == 'ip_history':
            if not ip:
                return 0.0, 'SKIP', 'no IP (dns failed)', None
            r = module.analyze_reverse_ip(ip, domain)
        else:
            return 0.0, 'SKIP', 'unknown module', None

        elapsed = time.monotonic() - start
        status = r.get('analysis_status', 'unknown') if isinstance(r, dict) else 'ok'
        if status in ('abgeschlossen', 'ok', 'unknown', 'quota_exceeded', 'skipped'):
            status = 'OK'
        elif status == 'failed':
            detail = str(r.get('error', ''))[:60]
            status = 'FAIL'
        return elapsed, status, detail, r

    except Exception as exc:
        elapsed = time.monotonic() - start
        return elapsed, 'ERROR', str(exc)[:80], None


# ── verdict based on elapsed vs timeout ───────────────────────────────────────
WARN_THRESHOLD = 0.75   # yellow at 75 % of timeout
FAIL_THRESHOLD = 1.00   # red at 100 % of timeout

def _verdict(elapsed: float, timeout: int, run_status: str) -> str:
    ratio = elapsed / timeout if timeout else 0
    if run_status in ('SKIP', 'ERROR', 'FAIL'):
        return run_status
    if ratio >= FAIL_THRESHOLD:
        return 'TIMEOUT'
    if ratio >= WARN_THRESHOLD:
        return 'SLOW'
    return 'OK'

# ── pretty bar ────────────────────────────────────────────────────────────────
def _bar(elapsed: float, timeout: int, width: int = 20) -> str:
    ratio = min(elapsed / timeout, 1.0) if timeout else 0
    filled = int(ratio * width)
    bar = '█' * filled + '░' * (width - filled)
    return bar

# ── main ──────────────────────────────────────────────────────────────────────
def main():
    domain = sys.argv[1] if len(sys.argv) > 1 else 'github.com'

    print(f"\n{bold('MODULE PERFORMANCE BENCHMARK')}")
    print(f"Domain : {info(domain)}")
    print(f"Limits : from config/settings.py MODULE_TIMEOUTS")
    print("─" * 72)

    # load modules
    print("Loading modules...", end=" ", flush=True)
    try:
        modules = _import_modules()
        print(ok("OK"))
    except Exception as exc:
        print(fail(f"FAILED — {exc}"))
        sys.exit(1)

    # execution order mirrors domain_analyzer.py
    ORDER = ['dns', 'whois', 'dns_history', 'cdn', 'network',
             'subdomain', 'ssl', 'securitytrails', 'abuseipdb', 'virustotal', 'ip_history']

    ip: Optional[str] = None
    rdns: Optional[str] = None

    results: Dict[str, Tuple[float, str, str, str]] = {}  # name → (elapsed, run_status, detail, verdict)

    print(f"\nRunning {len(ORDER)} modules against {bold(domain)}…\n")
    print(f"  {'Module':<14} {'Time':>6}  {'Limit':>5}  {'Bar':<22}  {'Verdict'}")
    print(f"  {'─'*14} {'─'*6}  {'─'*5}  {'─'*22}  {'─'*8}")

    for name in ORDER:
        module = modules.get(name)
        if module is None:
            results[name] = (0.0, 'SKIP', 'not loaded', 'SKIP')
            print(f"  {name:<14} {'—':>6}s {'—':>5}s  {'':22}  {dim('SKIP')}")
            continue

        print(f"  {name:<14}", end=" ", flush=True)
        elapsed, run_status, detail, result_dict = _run(name, module, domain, ip, rdns)
        timeout = MODULE_TIMEOUTS.get(name, 60)
        verdict = _verdict(elapsed, timeout, run_status)
        results[name] = (elapsed, run_status, detail, verdict)

        # extract IP from DNS result for dependent modules (no double-run)
        if name == 'dns' and result_dict and isinstance(result_dict, dict):
            ip = result_dict.get('ipv4')
            rdns = result_dict.get('reverse_dns')

        bar = _bar(elapsed, timeout)
        time_str = f"{elapsed:5.1f}s"
        limit_str = f"{timeout}s"

        if verdict == 'OK':
            vstr = ok('OK')
            bar_col = ok(bar)
        elif verdict == 'SLOW':
            vstr = warn('SLOW')
            bar_col = warn(bar)
        elif verdict == 'TIMEOUT':
            vstr = fail('TIMEOUT')
            bar_col = fail(bar)
        elif verdict in ('ERROR', 'FAIL'):
            vstr = fail(verdict)
            bar_col = fail(bar)
        else:
            vstr = dim(verdict)
            bar_col = dim(bar)

        detail_str = f"  {dim(detail)}" if detail else ""
        print(f" {time_str}  {limit_str:>5}  {bar_col}  {vstr}{detail_str}")

    # ── summary ───────────────────────────────────────────────────────────────
    print(f"\n{'─' * 72}")
    total = len([r for r in results.values() if r[1] != 'SKIP'])
    ok_count    = sum(1 for r in results.values() if r[3] == 'OK')
    slow_count  = sum(1 for r in results.values() if r[3] == 'SLOW')
    fail_count  = sum(1 for r in results.values() if r[3] in ('TIMEOUT', 'ERROR', 'FAIL'))
    skip_count  = sum(1 for r in results.values() if r[3] == 'SKIP')
    total_time  = sum(r[0] for r in results.values())

    print(f"  Modules run : {total}   "
          f"{ok(f'OK: {ok_count}')}  "
          f"{warn(f'SLOW: {slow_count}')}  "
          f"{fail(f'FAIL/TIMEOUT: {fail_count}')}  "
          f"{dim(f'SKIP: {skip_count}')}")
    print(f"  Total time  : {total_time:.1f}s")

    # thresholds explanation
    print(f"\n  {dim('SLOW = ≥75% of module timeout limit')}")
    print(f"  {dim('TIMEOUT = reached or exceeded limit')}")

    # flag slow/failed modules
    flagged = [(n, r) for n, r in results.items() if r[3] in ('SLOW', 'TIMEOUT', 'ERROR', 'FAIL')]
    if flagged:
        print(f"\n  {bold('Modules requiring attention:')}")
        for name, (elapsed, _, detail, verdict) in flagged:
            timeout = MODULE_TIMEOUTS.get(name, 60)
            pct = int(elapsed / timeout * 100) if timeout else 0
            line = f"  • {name:<14} {elapsed:5.1f}s / {timeout}s ({pct}%)"
            if detail:
                line += f"  — {detail}"
            if verdict in ('TIMEOUT', 'ERROR', 'FAIL'):
                print(fail(line))
            else:
                print(warn(line))
    else:
        print(f"\n  {ok('All modules within acceptable time bounds.')}")

    print()
    return 0 if fail_count == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
