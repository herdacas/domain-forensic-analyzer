"""
Shared helpers for API client modules.
"""

from typing import Any, Dict, Optional


def api_error_response(
    error: Exception, extra: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Standardised failed-response dict for API modules."""
    return {
        "analysis_status": "failed",
        "error": str(error),
        "api_status": "error",
        **(extra or {}),
    }
