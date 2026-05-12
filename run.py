"""Entry point for Domain Forensic Analyzer.

Usage:
  python run.py                      # interactive prompt
  python run.py example.com          # single domain, skip prompt
  python run.py --list domains.txt   # batch mode from file
"""
import io
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

if isinstance(sys.stdout, io.TextIOWrapper):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if isinstance(sys.stderr, io.TextIOWrapper):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


def _parse_domain_list(path_str: str):
    """Read domains from file, skipping comments (#) and blank lines."""
    from src.utils.validators import DomainValidator

    path = Path(path_str)
    if not path.exists():
        print(f"Error: file not found: {path_str!r}")
        sys.exit(1)

    domains = []
    seen = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        domain, msg = DomainValidator.preprocess_domain(line)
        if msg:
            print(f"  [input] {msg}")
        if domain and domain not in seen:
            seen.add(domain)
            domains.append(domain)
    return domains


def run_list_mode(file_path: str) -> None:
    from src.core.domain_analyzer import (
        DomainAnalyzer,
        display_forensic_header,
        display_forensic_summary,
        _compute_risk_summary,
    )
    from src.core.report_exporter import ReportExporter

    domains = _parse_domain_list(file_path)
    if not domains:
        print("No valid domains found in list.")
        sys.exit(1)

    total = len(domains)
    list_start = datetime.now()

    print(f"\n{'=' * 80}")
    print(f"DOMAIN FORENSIC ANALYZER — LIST MODE")
    print(f"{'=' * 80}")
    print(f"Source : {file_path}  ({total} domains)")
    print(f"Started: {list_start.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'=' * 80}\n")

    analyzer = DomainAnalyzer()
    exporter = ReportExporter()
    summary_rows = []
    batch_records = []

    for idx, domain in enumerate(domains, 1):
        t0 = time.monotonic()
        domain_start = datetime.now()
        print(f"\n{'─' * 80}")
        print(f"  [{idx}/{total}] {domain.upper()}")
        print(f"{'─' * 80}")

        forensic_metadata: dict = {}
        result = None

        try:
            forensic_metadata = display_forensic_header(domain, domain_start)
            result = analyzer.analyze_domain(domain)
            display_forensic_summary(result)
            overall_risk, _, _ = _compute_risk_summary(result)
            elapsed = time.monotonic() - t0
            print(f"\nForensic session {forensic_metadata['session_id']} complete.")
            summary_rows.append((domain, "COMPLETE", int(elapsed), overall_risk))
            batch_records.append({
                "domain": domain,
                "status": "COMPLETE",
                "duration_s": elapsed,
                "risk": overall_risk,
                "forensic_metadata": forensic_metadata,
                "result": result,
            })
        except Exception as exc:
            elapsed = time.monotonic() - t0
            print(f"\n[!] {domain}: analysis failed — {exc}")
            summary_rows.append((domain, "FAILED", int(elapsed), "ERROR"))
            batch_records.append({
                "domain": domain,
                "status": "FAILED",
                "duration_s": elapsed,
                "risk": "ERROR",
                "forensic_metadata": forensic_metadata,
                "result": None,
            })

        _, status, elapsed, risk = summary_rows[-1]
        print(f"\n  [{idx}/{total}] {domain:<40} → {status:<9} ({elapsed}s)  Risk: {risk}")

    # --- Overall summary ---
    total_duration = (datetime.now() - list_start).total_seconds()
    total_s = int(total_duration)
    mins, secs = divmod(total_s, 60)
    completed = sum(1 for _, s, _, _ in summary_rows if s == "COMPLETE")

    risk_counts: dict = {}
    for _, _, _, risk in summary_rows:
        risk_counts[risk] = risk_counts.get(risk, 0) + 1

    risk_parts = " | ".join(
        f"Risk {k}: {v}" for k, v in sorted(risk_counts.items())
    )

    print(f"\n{'=' * 80}")
    print("LIST MODE COMPLETE")
    print(f"{'=' * 80}")
    print(f"Completed: {completed}/{total} | Total time: {mins}m{secs:02d}s | {risk_parts}")

    if summary_rows:
        print()
        for idx, (domain, status, elapsed, risk) in enumerate(summary_rows, 1):
            print(f"  [{idx:>2}/{total}] {domain:<40} {status:<9} {elapsed:>4}s  Risk: {risk}")

    print(f"{'=' * 80}\n")

    exporter.export_batch(
        source_file=file_path,
        scan_records=batch_records,
        list_start=list_start,
        total_duration_seconds=total_duration,
    )


def main():
    from src.core.domain_analyzer import main as single_main

    args = sys.argv[1:]

    if '--list' in args:
        list_idx = args.index('--list')
        if list_idx + 1 >= len(args):
            print("Error: --list requires a file path")
            sys.exit(1)
        run_list_mode(args[list_idx + 1])
    else:
        single_main()


if __name__ == "__main__":
    main()
