"""CLI entry point for Domain Forensic Analyzer (single-domain mode)."""

import sys
from datetime import datetime

from src.core.domain_analyzer import DomainAnalyzer
from src.core.result_formatter import display_forensic_header, display_forensic_summary
from src.utils.colors import Colors
from src.utils.validators import DomainValidator


def get_domain_input() -> str:
    """Get domain name from user input or CLI argument with validation."""
    domain_args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if domain_args:
        candidate = domain_args[0].strip()
        domain, msg = DomainValidator.preprocess_domain(candidate)
        if domain is None:
            print(msg)
            sys.exit(1)
        if msg:
            print(f"[input] {msg}")
        return domain

    print(Colors.header("DOMAIN FORENSIC ANALYZER"))
    print("Target Domain Selection")
    print(Colors.investigation_separator(40))

    while True:
        try:
            raw = input("Enter target domain: ").strip()

            if not raw:
                print("Please enter a domain.")
                continue

            if raw.lower() in ["exit", "quit", "q"]:
                print("Goodbye!")
                sys.exit(0)

            domain, msg = DomainValidator.preprocess_domain(raw)
            if domain is None:
                print(f"  {msg}")
                continue
            if msg:
                print(f"  [input] {msg}")
            return domain

        except KeyboardInterrupt:
            print("\nGoodbye!")
            sys.exit(0)


def main():
    """Main program entry point with forensic metadata collection"""
    from src.core.report_exporter import ReportExporter

    analysis_start_time = datetime.now()
    exporter = ReportExporter()
    forensic_metadata: dict = {}
    result = None

    try:
        domain = get_domain_input()

        forensic_metadata = display_forensic_header(domain, analysis_start_time)

        analyzer = DomainAnalyzer()

        if hasattr(analyzer, "logger"):
            analyzer.logger.info(
                "Forensic session started",
                session_id=forensic_metadata["session_id"],
                external_ip=forensic_metadata["external_ip"],
                target_domain=domain,
                opsec_risk=forensic_metadata["opsec_assessment"]["attribution_risk"],
            )

        result = analyzer.analyze_domain(domain)

        display_forensic_summary(result)

        print(f"\nForensic session {forensic_metadata['session_id']} complete.")
        print(f"Check logs for detailed technical information and audit trail.")

        if result is not None:
            exporter.export(
                domain=domain,
                result=result,
                forensic_metadata=forensic_metadata,
                scan_duration=(datetime.now() - analysis_start_time).total_seconds(),
            )

    except KeyboardInterrupt:
        print("\nAnalysis interrupted. Goodbye!")
    except Exception as error:
        print(f"Analysis failed: {error}")


if __name__ == "__main__":
    main()
