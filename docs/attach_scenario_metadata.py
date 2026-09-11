#!/usr/bin/env python3
"""
PHASE 4 — Helper: attaches scenario metadata to the latest scan report.

Used by scenario_a.sh / scenario_b.sh / scenario_c.bat / scenario_d.bat
instead of embedding fragile multi-line `python -c "..."` blocks directly
in shell/batch files (cmd.exe in particular mishandles multi-line quoted
strings unpredictably).

Usage:
    python docs/attach_scenario_metadata.py \
        --id C --label "Windows + Direktverbindung" --os Windows \
        --external-ip 1.2.3.4 [--vpn] [--vpn-country DE] \
        --output docs/examples/scenario_c_windows_direct.json \
        [--reports-dir reports]
"""

import argparse
import glob
import json
import os
import sys
from datetime import datetime, timezone


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--id", required=True, help="Scenario id, e.g. A/B/C/D")
    parser.add_argument("--label", required=True, help="Human-readable scenario label")
    parser.add_argument("--os", required=True, help="Linux / Windows")
    parser.add_argument("--external-ip", default="unknown")
    parser.add_argument("--vpn", action="store_true", help="Set if VPN was active")
    parser.add_argument("--vpn-country", default=None)
    parser.add_argument("--output", required=True, help="Path to write the scenario JSON to")
    parser.add_argument("--reports-dir", default="reports", help="Directory holding scan reports")
    args = parser.parse_args()

    reports = sorted(
        glob.glob(os.path.join(args.reports_dir, "*.json")),
        key=os.path.getmtime,
        reverse=True,
    )
    if not reports:
        print(f"ERROR: Kein Report in {args.reports_dir}/")
        return 1

    latest = reports[0]
    with open(latest, encoding="utf-8") as f:
        data = json.load(f)

    scenario = {
        "id": args.id,
        "label": args.label,
        "os": args.os,
        "vpn": bool(args.vpn),
        "external_ip": args.external_ip,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if args.vpn_country:
        scenario["vpn_country"] = args.vpn_country
    data["scenario"] = scenario

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)

    meta = data.get("analyst", {})
    opsec = meta.get("opsec", {})
    asn = data.get("result", {}).get("results", {}).get("cdn", {}).get("asn_info", {})

    print(f"Report gespeichert: {args.output}")
    print(f"Quelle   : {latest}")
    print(f"Domain   : {data.get('domain', 'unknown')}")
    print(f"External : {args.external_ip}")
    print(f"VPN det. : {opsec.get('potential_vpn', 'n/a')}")
    print(f"ASN      : {asn.get('asn', 'n/a')} {asn.get('organization', '')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
