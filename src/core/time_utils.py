"""One UTC clock for scan metadata, reports and traces."""

from datetime import datetime, timezone


def utc_now() -> datetime:
    """Return timezone-aware UTC; never label local wall time as UTC."""
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    """Return UTC in ISO 8601 form with a trailing Z."""
    return utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")
