"""Entry point for Domain Forensic Analyzer.

Usage:
  python run.py                      # interactive prompt
  python run.py example.com          # single domain, skip prompt
  python run.py --list domains.txt   # batch mode from file
"""
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


def _parse_domain_list(path_str: str):
    """Read domains from file, skipping comments (#) and blank lines."""
    from src.utils.validators import DomainValidator

    path = Path(path_str)
    if not path.exists():
        print(f"Error: file not found: {path_str!r}")
        sys.exit(1)

    domains = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if DomainValidator.is_valid_domain(line):
            domains.append(DomainValidator.clean_domain(line))
        else:
            print(f"Warning: skipping invalid domain {line!r}")
    return domains


def run_list_mode(file_path: str) -> None:
    from src.core.domain_analyzer import (
        DomainAnalyzer,
        display_forensic_header,
        display_forensic_summary,
        _compute_risk_summary,
    )
    from src.core.report_exporter import ReportExporter, capture_console

    domains = _parse_domain_list(file_path)
    if not domains:
        print("No valid domains found in list.")
        sys.exit(1)

    total = len(domains)
    list_start = datetime.now()

    print(f"\n{'=' * 80}")
    print("DOMAIN FORENSIC ANALYZER — LIST MODE")
    print(f"{'=' * 80}")
    print(f"Source : {file_path}  ({total} domains)")
    print(f"Started: {list_start.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'=' * 80}\n")

    analyzer = DomainAnalyzer()
    exporter = ReportExporter()
    summary_rows = []

    for idx, domain in enumerate(domains, 1):
        t0 = time.monotonic()
        domain_start = datetime.now()
        print(f"\n{'─' * 80}")
        print(f"  [{idx}/{total}] {domain.upper()}")
        print(f"{'─' * 80}")

        forensic_metadata: dict = {}
        result = None

        try:
            with capture_console() as _console_buf:
                forensic_metadata = display_forensic_header(domain, domain_start)
                result = analyzer.analyze_domain(domain)
                display_forensic_summary(result)
                overall_risk, _, _ = _compute_risk_summary(result)
                elapsed = int(time.monotonic() - t0)
                print(f"\nForensic session {forensic_metadata['session_id']} complete.")
                summary_rows.append((domain, "COMPLETE", elapsed, overall_risk))

            exporter.export(
                domain=domain,
                result=result,
                forensic_metadata=forensic_metadata,
                raw_console_output=_console_buf.getvalue(),
                scan_duration=(datetime.now() - domain_start).total_seconds(),
            )
        except Exception as exc:
            elapsed = int(time.monotonic() - t0)
            print(f"\n[!] {domain}: analysis failed — {exc}")
            summary_rows.append((domain, "FAILED", elapsed, "ERROR"))

        _, status, elapsed, risk = summary_rows[-1]
        print(f"\n  [{idx}/{total}] {domain:<40} → {status:<9} ({elapsed}s)  Risk: {risk}")

    # --- Overall summary ---
    total_s = int((datetime.now() - list_start).total_seconds())
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


def main():
    from src.core.domain_analyzer import main as single_main

    if len(sys.argv) >= 3 and sys.argv[1] == "--list":
        run_list_mode(sys.argv[2])
    else:
        single_main()


if __name__ == "__main__":
    main()
