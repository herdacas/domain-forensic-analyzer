"""
Secure API Configuration Loader
"""

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

_ENV_VAR_MAP = {
    "securitytrails": "SECURITYTRAILS_API_KEY",
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "virustotal": "VIRUSTOTAL_API_KEY",
    "whoisxml": "WHOISXML_API_KEY",
}

_DEFAULTS = {
    "securitytrails": ("https://api.securitytrails.com/v1", 50),
    "abuseipdb": ("https://api.abuseipdb.com/api/v2", 1000),
    "virustotal": ("https://www.virustotal.com/api/v3", 1000),
    "whoisxml": ("https://whoisxmlapi.com/whoisserver/WhoisService", 500),
}


@dataclass
class APIConfig:
    """API Configuration Container"""

    api_key: str
    base_url: str
    rate_limit: int

    def is_valid(self) -> bool:
        return bool(
            self.api_key
            and len(self.api_key) > 10
            and not self.api_key.upper().startswith("YOUR_")
        )


class SecureAPIManager:
    """
    Secure API Key Management System
    Priority: environment variable > config/api_keys.json
    """

    def __init__(self):
        # src/config/api_config.py -> parent = src/config -> parent = src -> parent = project root
        self.project_root = Path(__file__).parent.parent.parent
        self.config_file = self.project_root / "config" / "api_keys.json"
        self.api_configs: Dict[str, APIConfig] = {}
        self._load_configurations()

    def _load_configurations(self) -> None:
        """Load API keys from file and environment variables (env takes priority)."""
        # 1. Start from file (if it exists)
        file_keys: Dict[str, Dict] = {}
        try:
            if self.config_file.exists():
                with open(self.config_file, "r", encoding="utf-8") as f:
                    file_keys = json.load(f)
            else:
                self._create_config_template()
        except Exception as error:
            print(f"API Configuration Error reading {self.config_file}: {error}")

        # 2. Build configs, env vars override file
        for service, env_var in _ENV_VAR_MAP.items():
            default_url, default_rate = _DEFAULTS.get(service, ("", 100))
            file_entry = file_keys.get(service, {})

            # Support both flat format {"service": "key"} and nested {"service": {"api_key": "key"}}
            if isinstance(file_entry, str):
                file_key, base_url, rate_limit = file_entry, default_url, default_rate
            else:
                file_key = file_entry.get("api_key", "")
                base_url = file_entry.get("base_url", default_url)
                rate_limit = file_entry.get("rate_limit", default_rate)

            api_key = os.getenv(env_var) or file_key

            if api_key:
                self.api_configs[service] = APIConfig(
                    api_key=api_key,
                    base_url=base_url,
                    rate_limit=rate_limit,
                )

    def _create_config_template(self) -> None:
        """Create config directory and template file if missing."""
        self.config_file.parent.mkdir(exist_ok=True)
        template = {}
        for service, (base_url, rate_limit) in _DEFAULTS.items():
            env_var = _ENV_VAR_MAP[service]
            template[service] = {
                "api_key": f"YOUR_{env_var}_HERE",
                "base_url": base_url,
                "rate_limit": rate_limit,
            }
        with open(self.config_file, "w", encoding="utf-8") as f:
            json.dump(template, f, indent=2)

    def get_api_config(self, service: str) -> Optional[APIConfig]:
        """Return a validated APIConfig for the given service, or None."""
        config = self.api_configs.get(service)
        if config and config.is_valid():
            return config
        return None

    def is_service_available(self, service: str) -> bool:
        """Return True if the service has a valid API key configured."""
        return self.get_api_config(service) is not None

    def get_available_services(self) -> list:
        """Return list of service names with valid API keys."""
        return [s for s in self.api_configs if self.is_service_available(s)]
