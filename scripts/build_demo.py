"""Build the data file for the browser demo in demo/.

The demo replays the validation scans in docs/examples/. Each stored module
result is re-aggregated and re-rendered with the current header and report
code, so the terminal replay matches what this version prints for the same
evidence. Analyst metadata (IPs, hostname, username) is masked before it
reaches the page.

Usage:
  python scripts/build_demo.py              # writes demo/data/scenarios.js
  python scripts/build_demo.py --out PATH
"""

import argparse
import contextlib
import io
import json
import sys
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# pylint: disable=wrong-import-position
from src.core import result_aggregator, result_formatter, risk_assessment
from src.core.domain_analyzer import DomainAnalyzer
from src.core.report_exporter import _SafeEncoder
from src.core.stdout_router import ModuleExecutionResult

EXAMPLES_DIR = PROJECT_ROOT / "docs" / "examples"
DEFAULT_OUT = PROJECT_ROOT / "demo" / "data" / "scenarios.js"

# Scenario id -> how the scan was run. The tunnel interface is what
# detect_tunnel_interface() reports for the WireGuard namespace setup in the
# README; Windows has no interface check, so it stays None there. The reports
# store no Linux kernel release, so the header shows a dash in its place.
SCENARIOS = {
    "A": {"file": "scenario_a_linux_direct.json", "label": "Linux, direct connection",
          "tunnel_interface": None, "release": "-"},
    "B": {"file": "scenario_b_linux_vpn.json", "label": "Linux, VPN (WireGuard namespace)",
          "tunnel_interface": "wg0", "release": "-"},
    "C": {"file": "scenario_c_windows_direct.json", "label": "Windows, direct connection",
          "tunnel_interface": None, "release": "10"},
    "D": {"file": "scenario_d_windows_vpn.json", "label": "Windows, VPN (desktop client)",
          "tunnel_interface": None, "release": "10"},
}

# RFC 5737 documentation addresses stand in for the analyst's public IPs.
MASKED_EXTERNAL_IP = {"A": "203.0.113.24", "B": "198.51.100.71",
                      "C": "203.0.113.58", "D": "198.51.100.93"}
MASKED_HOSTNAME = {"Linux": "analyst-server", "Windows": "ANALYST-LAPTOP"}
MASKED_USERNAME = "analyst"

MODULE_LABELS = {
    "dns": "DNS", "whois": "WHOIS", "dns_history": "DNS history", "cdn": "CDN / Geo",
    "network": "Network path", "subdomain": "Subdomains", "ssl": "SSL / TLS",
    "securitytrails": "SecurityTrails", "abuseipdb": "AbuseIPDB",
    "virustotal": "VirusTotal", "ip_history": "IP history",
}


def _frozen_datetime(moment: datetime) -> type:
    """Return a datetime subclass whose now() is pinned to *moment*."""

    class FrozenDatetime(datetime):
        """datetime with a fixed now()."""

        @classmethod
        def now(cls, tz=None):  # pylint: disable=arguments-differ
            return moment.replace(tzinfo=tz) if tz else moment

    return FrozenDatetime


def _module_status(result: Dict[str, Any]) -> str:
    status = result.get("analysis_status")
    if status in {"skipped", "quota_exceeded"}:
        return "SKIPPED"
    if status == "demo_abgeschlossen":
        return "DEMO"
    if status == "abgeschlossen":
        return "COMPLETE"
    return "FAILED"


def _progress(module_results: Dict[str, Any], total_time: float) -> Dict[str, Any]:
    """Progress lines in the format DomainAnalyzer prints while modules run.

    Per-module run times are not stored in the JSON reports, so the lines
    carry status only. The summary line uses DomainAnalyzer's own counters.
    """
    modules = list(module_results)
    analyzer = DomainAnalyzer.__new__(DomainAnalyzer)
    analyzer.current_analysis = {"results": module_results}
    analyzer.execution_metrics = {
        name: ModuleExecutionResult(success=_module_status(res) != "FAILED",
                                    result=res, execution_time=0.0)
        for name, res in module_results.items()
    }
    successful, failed, timeout, skipped, api_success, api_total = (
        analyzer._compute_execution_statistics(modules)  # pylint: disable=protected-access
    )
    skipped_part = f" | {skipped} skipped (passive)" if skipped else ""
    lines = [
        {"module": name, "label": name.replace("_", " ").title(),
         "status": _module_status(module_results[name])}
        for name in modules
    ]
    done = (
        f"   [done] Analysis complete: {successful}/{len(modules)} successful{skipped_part} | "
        f"{failed} failed | {timeout} timeout | APIs: {api_success}/{api_total} | "
        f"Total: {total_time:.1f}s"
    )
    return {"lines": lines, "done": done}


def _render(func, *args) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        func(*args)
    return buf.getvalue()


def _mask(value: Any, replacements: Dict[str, str]) -> Any:
    """Replace analyst identifiers anywhere in a JSON-compatible structure."""
    text = json.dumps(value, cls=_SafeEncoder, ensure_ascii=False)
    for old, new in replacements.items():
        text = text.replace(old, new)
    return json.loads(text)


def build_scenario(scenario_id: str) -> Dict[str, Any]:  # pylint: disable=too-many-locals
    """Re-render one stored validation scan as masked demo data."""
    spec = SCENARIOS[scenario_id]
    record = json.loads((EXAMPLES_DIR / spec["file"]).read_text(encoding="utf-8"))
    analyst = record["analyst"]
    system = analyst["system"]
    os_name = system["platform"]
    scan_start = datetime.strptime(record["session_id"], "%Y%m%d-%H%M%S")
    stored = record["result"]
    module_results = stored["results"]

    masked_external = MASKED_EXTERNAL_IP[scenario_id]
    masked_local = masked_external if analyst["local_ip"] == analyst["external_ip"] \
        else analyst["local_ip"]
    replacements = {
        analyst["external_ip"]: masked_external,
        system["hostname"]: MASKED_HOSTNAME.get(os_name, "analyst-host"),
        system["username"]: MASKED_USERNAME,
    }
    masked_system = {
        "hostname": MASKED_HOSTNAME.get(os_name, "analyst-host"),
        "username": MASKED_USERNAME,
        "platform": os_name,
        "platform_version": system["platform_version"],
        "architecture": system["architecture"],
    }

    frozen = _frozen_datetime(scan_start)
    patches = [
        mock.patch.object(result_formatter, "datetime", frozen),
        mock.patch.object(risk_assessment, "datetime", frozen),
        mock.patch.object(result_aggregator, "datetime", frozen),
        mock.patch.object(result_formatter, "get_external_ip", return_value=masked_external),
        mock.patch.object(result_formatter, "get_local_ip", return_value=masked_local),
        mock.patch.object(result_formatter, "get_system_metadata", return_value=masked_system),
        mock.patch.object(result_formatter, "platform",
                          SimpleNamespace(system=lambda: os_name,
                                          release=lambda: spec["release"])),
        mock.patch("src.core.metadata.detect_tunnel_interface",
                   return_value=spec["tunnel_interface"]),
        mock.patch("src.core.metadata.socket.getfqdn", return_value=masked_external),
    ]
    with contextlib.ExitStack() as stack:
        for patch in patches:
            stack.enter_context(patch)
        result = result_aggregator.create_result_aggregator().aggregate_results(
            domain=record["domain"], module_results=module_results,
            execution_time=stored["total_execution_time"],
        )
        header_buf = io.StringIO()
        with contextlib.redirect_stdout(header_buf):
            metadata = result_formatter.display_forensic_header(record["domain"], scan_start)
        report = _render(result_formatter.display_forensic_summary, result)

    progress = _progress(module_results, stored["total_execution_time"])
    opsec = metadata["opsec_assessment"]
    report_dict = result.to_dict()

    return _mask({
        "id": scenario_id,
        "label": spec["label"],
        "os": os_name,
        "vpn": bool(record["scenario"].get("vpn")),
        "vpn_country": record["scenario"].get("vpn_country"),
        "domain": record["domain"],
        "session_id": metadata["session_id"],
        "scanned_at": scan_start.isoformat(),
        "scan_duration_seconds": record["scan_duration_seconds"],
        "terminal": {
            "command": f"python{'3' if os_name != 'Windows' else ''} run.py {record['domain']}",
            "header": header_buf.getvalue(),
            "progress": progress,
            "report": report,
            "footer": (f"\nForensic session {metadata['session_id']} complete.\n"
                       "Check logs for detailed technical information and audit trail.\n"),
        },
        "analyst": {
            "external_ip": masked_external,
            "local_ip": masked_local,
            "system": masked_system,
            "opsec": {k: opsec[k] for k in ("attribution_risk", "stealth_level", "behind_nat",
                                              "potential_vpn", "vpn_signal", "tunnel_interface")},
        },
        "modules": [
            {"id": name, "label": MODULE_LABELS.get(name, name),
             "status": _module_status(res)}
            for name, res in module_results.items()
        ],
        "report": report_dict,
    }, replacements)


def build(out_path: Path) -> List[Dict[str, Any]]:
    """Write all scenarios to *out_path* as a script that sets window.DFA_DEMO."""
    scenarios = [build_scenario(sid) for sid in SCENARIOS]
    payload = {
        "generated_from": "docs/examples/*.json",
        "scenarios": scenarios,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        "// Generated by scripts/build_demo.py. Do not edit by hand.\n"
        "window.DFA_DEMO = "
        + json.dumps(payload, cls=_SafeEncoder, ensure_ascii=False, separators=(",", ":"))
        + ";\n",
        encoding="utf-8",
    )
    return scenarios


def main(argv: Optional[List[str]] = None) -> None:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)
    scenarios = build(args.out)
    size_kb = args.out.stat().st_size / 1024
    print(f"Wrote {len(scenarios)} scenarios to {args.out} ({size_kb:.0f} KB)")


if __name__ == "__main__":
    main()
