"""Measurement folders retain target attribution and complete log/trace pairs."""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from src.core.action_tracer import trace
from src.core.scan_runtime import initialize_scan_runtime


@pytest.fixture
def project(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "scope.json").write_text("{}")
    return tmp_path


def test_same_target_and_second_create_distinct_pairs(project, monkeypatch):
    monkeypatch.setattr("src.core.scan_runtime.utc_now",
                        lambda: datetime(2026, 10, 13, 17, 30, tzinfo=timezone.utc))
    _, first = initialize_scan_runtime(project, target="example.com")
    trace("dns", "A example.com", "example.com")
    saved = first.read_text()
    _, second = initialize_scan_runtime(project, target="example.com")
    assert first.parent != second.parent
    assert first.parent.name.startswith("example.com_2026-10-13_17-30-00Z_")
    for path in (first, second):
        assert path.name == "trace.jsonl"
        assert path.with_name("domain_analyzer.log").exists()
        assert path.parent.parent == project / "logs"
    assert first.read_text() == saved


def test_target_text_cannot_escape_logs_directory(project):
    _, path = initialize_scan_runtime(project, target="../../target/with:unsafe characters")
    assert path.parent.parent == project / "logs"
    assert "unsafe_characters" in path.parent.name


@pytest.mark.parametrize("loguru_available", [True, False])
def test_logger_reuses_cli_trace_directory(project, monkeypatch, loguru_available):
    import src.core.domain_analyzer as module
    monkeypatch.setattr(module, "__file__", str(project / "src/core/domain_analyzer.py"))
    monkeypatch.setattr(module, "LOGURU_AVAILABLE", loguru_available)
    monkeypatch.setattr(module.DomainAnalyzer, "_initialize_system", lambda self: None)
    session, path = initialize_scan_runtime(project, target="example.com")
    analyzer = module.DomainAnalyzer(session_id=session, runtime_initialized=True)
    analyzer.logger.info("measurement log test")
    assert analyzer.logs_dir == path.parent
    assert "measurement log test" in path.with_name("domain_analyzer.log").read_text()


def test_direct_api_binds_startup_and_repeated_scans_to_targets(project, monkeypatch):
    import src.core.domain_analyzer as module
    monkeypatch.setattr(module, "__file__", str(project / "src/core/domain_analyzer.py"))
    monkeypatch.setattr(module, "LOGURU_AVAILABLE", False)
    monkeypatch.setattr(module.DomainAnalyzer, "_initialize_system", lambda self: None)
    analyzer = module.DomainAnalyzer()
    original = analyzer.logs_dir
    analyzer.logger.info("constructor message")
    trace("dns", "constructor probe", "resolver")
    analyzer._prepare_measurement("example.com")
    first = analyzer.logs_dir
    assert not original.exists()
    assert first.name.startswith("example.com_")
    assert "constructor message" in analyzer.log_file.read_text()
    assert "constructor probe" in analyzer.trace_file.read_text()
    analyzer._prepare_measurement("example.org")
    assert analyzer.logs_dir != first
    assert analyzer.logs_dir.name.startswith("example.org_")
    trace("dns", "A example.org", "example.org")
    assert "example.org" in analyzer.trace_file.read_text()
    assert "example.org" not in (first / "trace.jsonl").read_text()


def test_batch_passes_each_effective_target_to_runtime(project, monkeypatch):
    import run
    import src.core.domain_analyzer as analyzer_module
    import src.core.result_formatter as formatter
    from src.core.result_aggregator import create_result_aggregator
    from unittest.mock import MagicMock

    monkeypatch.setattr(run, "__file__", str(project / "run.py"))
    monkeypatch.setattr(run, "_parse_domain_list", lambda _: ["example.com", "example.org"])
    analyzer = MagicMock()
    analyzer.analyze_domain.side_effect = lambda domain: create_result_aggregator().aggregate_results(domain, {}, 0)
    monkeypatch.setattr(analyzer_module, "DomainAnalyzer", lambda **kwargs: analyzer)
    monkeypatch.setattr(formatter, "display_forensic_header", lambda *args: {})
    monkeypatch.setattr(formatter, "display_forensic_summary", lambda *args: None)
    run.run_list_mode("domains.txt")
    folders = list((project / "logs").iterdir())
    assert len(folders) == 2
    assert any(folder.name.startswith("example.com_") for folder in folders)
    assert any(folder.name.startswith("example.org_") for folder in folders)
    assert all((folder / "trace.jsonl").exists() for folder in folders)
