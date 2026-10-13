"""Initialize scope and trace before metadata collection or module creation."""

import warnings
import re
from contextvars import ContextVar
from pathlib import Path
from uuid import uuid4

from src.core.action_tracer import set_trace_file
from src.core.scope_config import ScopeConfig
from src.core.scope_guard import set_scope, set_source_ip
from src.core.time_utils import utc_now

_target_context = ContextVar("dfa_measurement_target", default=None)


def get_scan_target():
    return _target_context.get()


def create_measurement_dir(project_root: Path, target: str | None = None) -> Path:
    """Safe target/date names plus atomic creation prevent run collisions."""
    safe_target = re.sub(r"[^A-Za-z0-9._-]+", "_", target or "unknown-target").strip("._-")[:120]
    safe_target = safe_target or "unknown-target"
    stamp = utc_now().strftime("%Y-%m-%d_%H-%M-%SZ")
    logs_root = project_root / "logs"
    logs_root.mkdir(parents=True, exist_ok=True)
    while True:
        path = logs_root / f"{safe_target}_{stamp}_{uuid4().hex[:12]}"
        try:
            path.mkdir()
            return path
        except FileExistsError:
            continue


def initialize_scan_runtime(project_root: Path, session_id: str | None = None,
                            target: str | None = None):
    session_id = session_id or utc_now().strftime("%Y%m%d-%H%M%S")
    # A measurement owns both files; the target is known before CLI metadata I/O.
    path = create_measurement_dir(project_root, target) / "trace.jsonl"
    set_trace_file(path)
    # Keep the artifact pair present even when startup stops before logger setup.
    path.with_name("domain_analyzer.log").touch(exist_ok=True)
    _target_context.set(target)
    set_source_ip("")
    scope_path = project_root / "config" / "scope.json"
    if scope_path.exists():
        set_scope(ScopeConfig(scope_path))
    else:
        # Missing engagement rules preserve legacy scans; baseline still applies.
        set_scope(None)
        warnings.warn("No scope.json loaded; default hard exclusions and AXFR prohibition still apply.",
                      RuntimeWarning, stacklevel=2)
    return session_id, path
