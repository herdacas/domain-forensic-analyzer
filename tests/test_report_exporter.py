"""Report export contracts: JSON always, raw console capture by default."""

import json
from unittest.mock import patch

from src.core.report_exporter import ReportExporter
from src.core.result_aggregator import create_result_aggregator


def test_default_export_writes_json_and_raw(tmp_path):
    result = create_result_aggregator().aggregate_results("example.com", {}, 0)
    exporter = ReportExporter(tmp_path)
    exporter.export("example.com", result, {}, 0, raw_console_output="console text")
    report = json.loads((tmp_path / "reports/0001_example.com.json").read_text())
    assert report["result"]["domain"] == "example.com"
    assert (tmp_path / "reports/raw/0001_example.com.txt").read_text() == "console text"
    exporter.export("example.com", result, {}, 0)
    assert (tmp_path / "reports/0002_example.com.json").exists()
    assert not (tmp_path / "reports/raw/0002_example.com.txt").exists()


def test_debug_false_writes_json_only(tmp_path):
    result = create_result_aggregator().aggregate_results("example.com", {}, 0)
    ReportExporter(tmp_path, debug=False).export(
        "example.com", result, {}, 0, raw_console_output="console text")
    assert (tmp_path / "reports/0001_example.com.json").exists()
    assert not (tmp_path / "reports/raw").exists()


def test_cli_main_passes_captured_console_to_exporter(tmp_path, monkeypatch):
    import src.core.cli as cli
    import src.core.report_exporter as exporter_module
    from unittest.mock import MagicMock
    result = create_result_aggregator().aggregate_results("example.com", {}, 0)
    analyzer = MagicMock(spec=["analyze_domain"])
    analyzer.analyze_domain.return_value = result
    exporter = ReportExporter(tmp_path)
    monkeypatch.setattr(exporter_module, "ReportExporter", lambda: exporter)
    monkeypatch.setattr(cli, "get_domain_input", lambda: "example.com")
    monkeypatch.setattr(cli, "DomainAnalyzer", lambda: analyzer)
    monkeypatch.setattr(cli, "display_forensic_header",
                        lambda *args: (print("HEADER-LINE") or {"session_id": "s1"}))
    monkeypatch.setattr(cli, "display_forensic_summary", lambda *args: print("SUMMARY-LINE"))
    cli.main()
    raw = (tmp_path / "reports/raw/0001_example.com.txt").read_text()
    assert "HEADER-LINE" in raw and "SUMMARY-LINE" in raw
    assert (tmp_path / "reports/0001_example.com.json").exists()


def test_export_failure_is_visible_without_raising(tmp_path, capsys):
    with patch("pathlib.Path.write_text", side_effect=OSError("disk full")):
        ReportExporter(tmp_path).export("example.com", None, {}, 0)
    assert "disk full" in capsys.readouterr().err


def test_batch_writes_individual_and_consolidated_reports(tmp_path, monkeypatch):
    from unittest.mock import MagicMock
    import run
    import src.core.domain_analyzer as domain_analyzer
    import src.core.result_formatter as formatter
    import src.core.report_exporter as exporter_module
    result = create_result_aggregator().aggregate_results("example.com", {}, 0)
    analyzer = MagicMock()
    analyzer.analyze_domain.return_value = result
    exporter = ReportExporter(tmp_path)
    monkeypatch.setattr(domain_analyzer, "DomainAnalyzer", lambda: analyzer)
    monkeypatch.setattr(exporter_module, "ReportExporter", lambda: exporter)
    monkeypatch.setattr(formatter, "display_forensic_header", lambda *args: {"session_id": "test"})
    monkeypatch.setattr(formatter, "display_forensic_summary",
                        lambda *args: print("BATCH-SUMMARY-LINE"))
    monkeypatch.setattr(run, "_parse_domain_list", lambda *args: ["example.com"])
    run.run_list_mode("domains.txt")
    assert (tmp_path / "reports/0001_example.com.json").exists()
    assert "BATCH-SUMMARY-LINE" in (tmp_path / "reports/raw/0001_example.com.txt").read_text()
    reports = list((tmp_path / "reports/batch").glob("*.json"))
    assert len(reports) == 1
    assert "example.com" in reports[0].read_text()
