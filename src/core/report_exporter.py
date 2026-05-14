"""Export forensic scan results to JSON.

Scan IDs auto-increment (0001, 0002, …) based on existing files in reports/.
JSON is the sole production output format.

capture_console() and the debug=True path on ReportExporter are available
for local debugging only and must not be enabled in normal execution.
"""
import io
import json
import re
import sys
from contextlib import contextmanager
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Generator, Optional

# ---------------------------------------------------------------------------
# JSON serialisation
# ---------------------------------------------------------------------------

class _SafeEncoder(json.JSONEncoder):
    """Handle datetime, date, Enum, and arbitrary objects gracefully."""

    def default(self, obj: Any) -> Any:
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        if isinstance(obj, Enum):
            return obj.value
        try:
            return super().default(obj)
        except TypeError:
            return str(obj)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sanitize_filename(domain: str) -> str:
    """Replace characters that are unsafe in filesystem names."""
    return re.sub(r'[<>:"/\\|?*\s]', '_', domain)


def _next_scan_id(reports_dir: Path) -> str:
    """Return the next zero-padded 4-digit scan ID.

    Reads existing file names in *reports_dir* that start with four digits
    and returns the next value (e.g. '0003' if '0002_…' is the highest).
    """
    pattern = re.compile(r'^(\d{4})_')
    max_id = 0
    try:
        for entry in reports_dir.iterdir():
            m = pattern.match(entry.name)
            if m:
                max_id = max(max_id, int(m.group(1)))
    except OSError:
        pass
    return f"{max_id + 1:04d}"


def _next_batch_id(batch_dir: Path) -> str:
    """Return the next zero-padded 4-digit batch ID (BATCH_NNNN).

    Reads existing file names in *batch_dir* that start with BATCH_NNNN_
    and returns the next value.
    """
    pattern = re.compile(r'^BATCH_(\d{4})_')
    max_id = 0
    try:
        for entry in batch_dir.iterdir():
            m = pattern.match(entry.name)
            if m:
                max_id = max(max_id, int(m.group(1)))
    except OSError:
        pass
    return f"BATCH_{max_id + 1:04d}"


# ---------------------------------------------------------------------------
# Stdout capture
# ---------------------------------------------------------------------------

@contextmanager
def capture_console() -> Generator[io.StringIO, None, None]:
    """Tee stdout into a StringIO buffer while keeping terminal output intact.

    Strategy: if sys.stdout is a ThreadAwareStdoutRouter (installed by
    domain_analyzer.py), replace its *_target* with a Tee writer.  This means
    the router's per-thread muting logic still fires first, so output that
    would be suppressed for worker threads is never written to the buffer.
    Fallback: replace sys.stdout directly.
    """
    buf = io.StringIO()
    router = sys.stdout

    if hasattr(router, '_target'):
        original_target = router._target

        class _Tee:
            def write(self, data: str) -> int:
                buf.write(data)
                return original_target.write(data)

            def flush(self) -> None:
                original_target.flush()

            def __getattr__(self, name: str) -> Any:
                return getattr(original_target, name)

        router._target = _Tee()
        try:
            yield buf
        finally:
            router._target = original_target

    else:
        original_stdout = sys.stdout

        class _Tee:
            def write(self, data: str) -> int:
                buf.write(data)
                return original_stdout.write(data)

            def flush(self) -> None:
                original_stdout.flush()

            def __getattr__(self, name: str) -> Any:
                return getattr(original_stdout, name)

        sys.stdout = _Tee()
        try:
            yield buf
        finally:
            sys.stdout = original_stdout


# ---------------------------------------------------------------------------
# Exporter
# ---------------------------------------------------------------------------

class ReportExporter:
    """Write per-scan JSON reports under reports/.

    JSON is the single production output format. Raw console capture is
    available only when debug=True and must not be used in normal execution.

    Directory layout (production)::

        reports/
            0001_example.com.json       <- single-domain scan
            batch/
                BATCH_0001_domains.json <- one file per --list run

    Directory layout (debug only)::

        reports/
            0001_example.com.json
            raw/
                0001_example.com.txt
    """

    def __init__(self, project_root: Optional[Path] = None, debug: bool = False) -> None:
        if project_root is None:
            project_root = Path(__file__).parent.parent.parent
        self.reports_dir = project_root / "reports"
        self.batch_dir = self.reports_dir / "batch"
        self.raw_dir = self.reports_dir / "raw"
        self.debug = debug

    def _ensure_dirs(self) -> None:
        self.reports_dir.mkdir(exist_ok=True)
        if self.debug:
            self.raw_dir.mkdir(exist_ok=True)

    def _ensure_batch_dir(self) -> None:
        self.reports_dir.mkdir(exist_ok=True)
        self.batch_dir.mkdir(exist_ok=True)

    def export(
        self,
        domain: str,
        result: Any,
        forensic_metadata: Dict[str, Any],
        scan_duration: float,
        raw_console_output: Optional[str] = None,
    ) -> None:
        """Persist JSON for one scan. Raw TXT is written only when debug=True.

        Never raises — any serialisation or I/O failure is silently discarded
        so the export can never interrupt or affect the scan.
        """
        try:
            self._ensure_dirs()
            scan_id = _next_scan_id(self.reports_dir)
            safe_domain = _sanitize_filename(domain)
            base = f"{scan_id}_{safe_domain}"

            # Raw console capture — debug only, never written in production
            if self.debug and raw_console_output:
                (self.raw_dir / f"{base}.txt").write_text(
                    raw_console_output, encoding="utf-8", errors="replace"
                )

            # Structured JSON report (always written)
            meta = forensic_metadata or {}
            ts = meta.get('timestamp')
            result_dict = result.to_dict() if hasattr(result, 'to_dict') else {}

            payload: Dict[str, Any] = {
                "scan_id": scan_id,
                "timestamp": ts.isoformat() if isinstance(ts, datetime) else str(ts),
                "domain": domain,
                "session_id": meta.get('session_id'),
                "scan_duration_seconds": round(scan_duration, 2),
                "analyst": {
                    "external_ip": meta.get('external_ip'),
                    "local_ip": meta.get('local_ip'),
                    "system": meta.get('system_metadata', {}),
                    "opsec": meta.get('opsec_assessment', {}),
                },
                "result": result_dict,
            }

            (self.reports_dir / f"{base}.json").write_text(
                json.dumps(payload, indent=2, ensure_ascii=False, cls=_SafeEncoder),
                encoding="utf-8",
            )

        except Exception:
            pass

    def export_batch(
        self,
        source_file: str,
        scan_records: list,
        list_start: datetime,
        total_duration_seconds: float,
    ) -> None:
        """Persist a single JSON file for a complete --list batch run.

        *scan_records* is a list of dicts, each produced by run_list_mode for
        one domain:
            {
                "domain": str,
                "status": "COMPLETE" | "FAILED",
                "duration_s": float,
                "risk": str,
                "forensic_metadata": dict,
                "result": UnifiedResult | None,
            }

        Never raises — any I/O or serialisation failure is silently discarded.
        """
        try:
            self._ensure_batch_dir()
            batch_id = _next_batch_id(self.batch_dir)
            list_name = re.sub(r'[<>:"/\\|?*\s]', '_', Path(source_file).stem)
            filename = f"{batch_id}_{list_name}.json"

            total = len(scan_records)
            completed = sum(1 for r in scan_records if r["status"] == "COMPLETE")
            failed = total - completed

            risk_dist: Dict[str, int] = {}
            summary_domains = []
            scans = []

            for rec in scan_records:
                risk = rec.get("risk", "ERROR")
                risk_dist[risk] = risk_dist.get(risk, 0) + 1

                summary_domains.append({
                    "domain": rec["domain"],
                    "status": rec["status"],
                    "risk": risk,
                    "duration_s": round(rec.get("duration_s", 0), 1),
                })

                result = rec.get("result")
                result_dict = result.to_dict() if hasattr(result, "to_dict") else {}
                meta = rec.get("forensic_metadata") or {}
                ts = meta.get("timestamp")

                scans.append({
                    "domain": rec["domain"],
                    "status": rec["status"],
                    "session_id": meta.get("session_id"),
                    "scan_duration_seconds": round(rec.get("duration_s", 0), 2),
                    "analyst": {
                        "external_ip": meta.get("external_ip"),
                        "local_ip": meta.get("local_ip"),
                        "system": meta.get("system_metadata", {}),
                        "opsec": meta.get("opsec_assessment", {}),
                    },
                    "timestamp": ts.isoformat() if isinstance(ts, datetime) else str(ts) if ts else None,
                    "result": result_dict,
                })

            payload: Dict[str, Any] = {
                "batch_id": batch_id,
                "timestamp": list_start.isoformat(),
                "source_file": source_file,
                "total_domains": total,
                "completed": completed,
                "failed": failed,
                "duration_seconds": round(total_duration_seconds, 1),
                "summary": {
                    "risk_distribution": risk_dist,
                    "domains": summary_domains,
                },
                "scans": scans,
            }

            (self.batch_dir / filename).write_text(
                json.dumps(payload, indent=2, ensure_ascii=False, cls=_SafeEncoder),
                encoding="utf-8",
            )

        except Exception:
            pass
