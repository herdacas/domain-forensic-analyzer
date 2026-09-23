"""
Central API key reader used by analyzer modules that manage their own
HTTP sessions (dns_history, ip_history, whois).

Priority: environment variable > config/api_keys.json > None
"""

import json
import os
from pathlib import Path
from typing import Optional


class APIKeyReader:
    """Read one API key from env var or config/api_keys.json."""

    _PLACEHOLDERS = ("your_", "_here", "placeholder", "demo", "test")
    _PROJECT_ROOT = Path(__file__).resolve().parents[2]

    def __init__(self, env_var: str, service_name: str) -> None:
        self.env_var = env_var
        self.service_name = service_name

    def get(self) -> Optional[str]:
        """Return the API key from env var or config file, or None if not found."""
        # 1. Environment variable
        env_val = os.getenv(self.env_var)
        if self._is_real_key(env_val):
            return env_val.strip()  # type: ignore[union-attr]

        # 2. config/api_keys.json
        config_path = self._PROJECT_ROOT / "config" / "api_keys.json"
        if not config_path.exists():
            return None
        try:
            with open(config_path, "r", encoding="utf-8") as fh:
                config_data = json.load(fh)
        except Exception:
            return None

        service_config = config_data.get(self.service_name)
        config_val = (
            service_config.get("api_key")
            if isinstance(service_config, dict)
            else service_config
        )
        return str(config_val).strip() if self._is_real_key(config_val) else None

    @classmethod
    def _is_real_key(cls, value: Optional[str]) -> bool:
        """Return True if value looks like a real key (not a placeholder)."""
        if not value:
            return False
        text = value.strip()
        return len(text) >= 10 and not any(m in text.lower() for m in cls._PLACEHOLDERS)
