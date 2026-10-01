"""Raw console capture is a standard export, not a debug-only side path."""

import tempfile
from pathlib import Path

from src.core.report_exporter import ReportExporter


def test_raw_export_created_by_default():
    with tempfile.TemporaryDirectory() as tmpdir:
        exporter = ReportExporter(project_root=Path(tmpdir))

        class MockResult:
            def to_dict(self):
                return {"test": "data"}

        exporter.export(
            domain="example.com",
            result=MockResult(),
            forensic_metadata={"timestamp": None},
            scan_duration=1.5,
            raw_console_output="Test console output",
        )

        reports_dir = Path(tmpdir) / "reports"
        json_files = list(reports_dir.glob("*.json"))
        raw_files = list((reports_dir / "raw").glob("*.txt"))

        assert len(json_files) > 0, "JSON report not created"
        assert len(raw_files) > 0, "Raw console output not created"
        assert raw_files[0].read_text(encoding="utf-8") == "Test console output"
        assert raw_files[0].stem == json_files[0].stem
