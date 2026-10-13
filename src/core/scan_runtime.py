"""Initialize scope and trace before metadata collection or module creation."""

import warnings
from pathlib import Path
from uuid import uuid4

from src.core.action_tracer import set_trace_file
from src.core.scope_config import ScopeConfig
from src.core.scope_guard import set_scope, set_source_ip
from src.core.time_utils import utc_now, utc_now_iso


def initialize_scan_runtime(project_root: Path, session_id: str | None = None):
    session_id = session_id or utc_now().strftime("%Y%m%d-%H%M%S")
    # UUID prevents collisions between multiple sessions in the same second.
    stamp = utc_now_iso().replace(":", "") + "_" + uuid4().hex[:8]
    path = project_root / "logs" / f"trace_{session_id}_{stamp}.jsonl"
    set_trace_file(path)
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
