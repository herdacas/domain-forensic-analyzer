"""
Shared helpers for API client modules.
"""

from typing import Any, Dict, Optional

# Central helpers keep action decisions and persisted metadata consistent.
from src.core.redactor import redact

from src.core.scope_guard import ScopeBlocked


def api_error_response(
    error: Exception, extra: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Standardised failed-response dict for API modules."""
    return {
        "analysis_status": "skipped" if isinstance(error, ScopeBlocked) else "failed",
        "error": redact(str(error)),
        "api_status": "blocked_by_scope" if isinstance(error, ScopeBlocked) else "error",
        **(extra or {}),
    }
