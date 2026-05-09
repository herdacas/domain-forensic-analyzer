"""Export forensic scan results to JSON and raw console TXT.

Scan IDs auto-increment (0001, 0002, …) based on existing files in reports/.
The capture_console() context manager tees stdout into a buffer without
changing what reaches the terminal. It cooperates with ThreadAwareStdoutRouter
so worker-thread muting still functions correctly.
"""
import io
import json
import re
import sys
from contextlib import contextmanager
from datetime import datetime, date
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
    """Write per-scan JSON and raw TXT reports under reports/.

    Directory layout::

        reports/
            0001_example.com.json
            raw/
                0001_example.com.txt
    """

    def __init__(self, project_root: Optional[Path] = None) -> None:
        if project_root is None:
            project_root = Path(__file__).parent.parent.parent
        self.reports_dir = project_root / "reports"
        self.raw_dir = self.reports_dir / "raw"

    def _ensure_dirs(self) -> None:
        self.reports_dir.mkdir(exist_ok=True)
        self.raw_dir.mkdir(exist_ok=True)

    def export(
        self,
        domain: str,
        result: Any,
        forensic_metadata: Dict[str, Any],
        raw_console_output: str,
        scan_duration: float,
    ) -> None:
        """Persist JSON and raw TXT for one scan.

        Never raises — any serialisation or I/O failure is silently discarded
        so the export can never interrupt or affect the scan.
        """
        try:
            self._ensure_dirs()
            scan_id = _next_scan_id(self.reports_dir)
            safe_domain = _sanitize_filename(domain)
            base = f"{scan_id}_{safe_domain}"

            # Raw console output (exact bytes as written to the terminal)
            (self.raw_dir / f"{base}.txt").write_text(
                raw_console_output, encoding="utf-8", errors="replace"
            )

            # Structured JSON report
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
            # Silently suppress — export failure must never reach the caller.
            pass
