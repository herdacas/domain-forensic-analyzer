"""Redact credentials before they reach persistent forensic artifacts."""

import re
import threading

# Delimiters are preserved so URL parameters after a secret remain reviewable.
_KEY = r"(?:api[_-]?key|x-api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|token|password|passwd|secret|client_secret)"
_PATTERNS = (
    (re.compile(r"(?im)\b(authorization\s*:\s*)(?:bearer|basic)?\s*[^\r\n]+"), r"\1[REDACTED]"),
    (re.compile(r"(?im)\b((?:set-cookie|cookie)\s*[:=]\s*)[^\r\n]+"), r"\1[REDACTED]"),
    (re.compile(r'(?i)([\"\']?' + _KEY + r'[\"\']?\s*[:=]\s*)([\"\'])(.*?)\2'), r'\1\2[REDACTED]\2'),
    (re.compile(r"(?i)(\b" + _KEY + r"\s*[:=]\s*)[^\s&;,#}\]\"']+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\bbearer\s+[^\s&;]+"), "Bearer [REDACTED]"),
    (re.compile(r"(?i)(https?://)[^/@\s]+:[^/@\s]+@"), r"\1[REDACTED]@"),
)
_SECRETS = set()
_LOCK = threading.RLock()
_SENSITIVE_KEYS = re.compile(r"(?i)^(?:" + _KEY + r"|authorization|cookie|set-cookie)$")


def register_secret(value: str) -> None:
    """Known keys are also removed when exception text omits a field name."""
    if isinstance(value, str) and len(value.strip()) >= 8:
        from urllib.parse import quote, quote_plus
        with _LOCK:
            _SECRETS.update((value.strip(), quote(value.strip(), safe=""), quote_plus(value.strip())))


def redact(text: str) -> str:
    """Replace credentials with [REDACTED], accepting non-string errors."""
    text = text if isinstance(text, str) else str(text)
    with _LOCK:
        secrets = sorted(_SECRETS, key=len, reverse=True)
    for secret in secrets:
        text = text.replace(secret, "[REDACTED]")
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_data(value):
    """Apply the same policy to nested log context and JSON reports."""
    if isinstance(value, dict):
        return {key: "[REDACTED]" if _SENSITIVE_KEYS.fullmatch(str(key)) else redact_data(item)
                for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_data(item) for item in value]
    return redact(value) if isinstance(value, str) else value


def redact_loguru_record(record):
    """Keep log messages and structured context safe before sink formatting."""
    record["message"] = redact(record["message"])
    record["extra"] = redact_data(record["extra"])
    return True
