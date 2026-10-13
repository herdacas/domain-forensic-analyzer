"""Append one redacted JSONL decision before each guarded action."""

import json
import threading
from contextvars import ContextVar
from pathlib import Path

from src.core.redactor import redact_data
from src.core.time_utils import utc_now_iso

TRACE_FILE: Path | None = None
_LOCK = threading.RLock()
_trace_context = ContextVar("dfa_trace_file", default=None)


def get_trace_file() -> Path | None:
    """Expose the scan-local artifact path to the session logger."""
    return _trace_context.get() or TRACE_FILE


def set_trace_file(path: Path):
    """Open eagerly so an unwritable audit trail cannot silently allow a scan."""
    global TRACE_FILE
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK:
        with path.open("a", encoding="utf-8"):
            pass
        TRACE_FILE = path
        _trace_context.set(path)


def trace(action_type: str, command: str, target: str, source_ip: str = "",
          tool: str = "", scope_decision: str = "allowed", block_reason: str = ""):
    entry = redact_data({
        "timestamp_utc": utc_now_iso(), "action_type": action_type,
        "tool": tool, "command": command, "target": target,
        "source_ip": source_ip, "scope_decision": scope_decision,
        "block_reason": block_reason,
    })
    # One lock covers file selection and the complete line across worker threads.
    with _LOCK:
        path = _trace_context.get() or TRACE_FILE
        if path is not None:
            with path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry
