"""
Configuration Management for Domain Forensic Analyzer.
"""

import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

MODULE_TIMEOUTS: Dict[str, int] = {
    'dns':            30,
    'whois':          30,
    'dns_history':    90,
    'cdn':            10,
    'network':        90,
    'subdomain':      30,
    'ssl':            25,
    'securitytrails': 30,
    'abuseipdb':      30,
    'virustotal':     30,
    'ip_history':     45,
}

@dataclass
class ScanSettings:
    """Timeout and threading parameters for scan modules."""

    dns_timeout: int = 10
    traceroute_timeout_regional: int = 50
    traceroute_timeout_international: int = 75
    api_timeout: int = 15
    max_subdomain_threads: int = 12
    subdomain_timeout: int = 5
    max_traceroute_hops: int = 15
    traceroute_encoding: str = 'cp850'  # Windows default console encoding
    api_rate_limit_delay: float = 0.5
    request_delay: float = 0.1

@dataclass
class APIConfig:
    """External API keys and base URLs."""

    securitytrails_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    shodan_api_key: Optional[str] = None
    
    # API-Endpunkte
    securitytrails_base_url: str = "https://api.securitytrails.com/v1"
    virustotal_base_url: str = "https://www.virustotal.com/vtapi/v2"
    ip_geolocation_url: str = "http://ip-api.com/json"

@dataclass
class OutputSettings:
    """Terminal output and report generation settings."""

    use_colors: bool = True
    verbose_mode: bool = False
    show_progress: bool = True
    generate_json: bool = True
    generate_pdf: bool = False
    output_directory: str = "reports"
    include_timestamps: bool = True
    include_investigation_id: bool = True

class Settings:
    """Central configuration for Domain Forensic Analyzer."""

    def __init__(self):
        self.scan_settings = ScanSettings()
        self.api_config = APIConfig()
        self.output_settings = OutputSettings()
        self._load_from_environment()
        self._validate_configuration()
    
    def _load_from_environment(self) -> None:
        """Load configuration overrides from environment variables."""
        self.api_config.securitytrails_api_key = os.getenv('SECURITYTRAILS_API_KEY')
        self.api_config.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.api_config.shodan_api_key = os.getenv('SHODAN_API_KEY')

        try:
            self.scan_settings.dns_timeout = int(os.getenv('DNS_TIMEOUT', '10'))
            self.scan_settings.api_timeout = int(os.getenv('API_TIMEOUT', '15'))
            self.scan_settings.traceroute_timeout_regional = int(os.getenv('TRACEROUTE_TIMEOUT_REGIONAL', '50'))
            self.scan_settings.traceroute_timeout_international = int(os.getenv('TRACEROUTE_TIMEOUT_INTERNATIONAL', '75'))
        except ValueError:
            pass

        try:
            self.scan_settings.max_subdomain_threads = int(os.getenv('MAX_SUBDOMAIN_THREADS', '12'))
        except ValueError:
            pass

        self.output_settings.use_colors = os.getenv('USE_COLORS', 'true').lower() == 'true'
        self.output_settings.verbose_mode = os.getenv('VERBOSE_MODE', 'false').lower() == 'true'
        self.output_settings.output_directory = os.getenv('OUTPUT_DIRECTORY', 'reports')
    
    def _validate_configuration(self) -> None:
        """Clamp timeouts and thread counts to sane bounds; ensure output dir exists."""
        if self.scan_settings.dns_timeout <= 0:
            self.scan_settings.dns_timeout = 10

        if self.scan_settings.api_timeout <= 0:
            self.scan_settings.api_timeout = 15

        if self.scan_settings.max_subdomain_threads <= 0:
            self.scan_settings.max_subdomain_threads = 8
        elif self.scan_settings.max_subdomain_threads > 50:
            self.scan_settings.max_subdomain_threads = 50

        if not os.path.exists(self.output_settings.output_directory):
            try:
                os.makedirs(self.output_settings.output_directory)
            except OSError:
                self.output_settings.output_directory = "."
    
    def has_securitytrails_api(self) -> bool:
        """Return True if SecurityTrails API key is configured."""
        return bool(self.api_config.securitytrails_api_key)

    def has_virustotal_api(self) -> bool:
        """Return True if VirusTotal API key is configured."""
        return bool(self.api_config.virustotal_api_key)

    def get_api_status(self) -> Dict[str, bool]:
        """Return availability status for each configured API."""
        return {
            'securitytrails': self.has_securitytrails_api(),
            'virustotal': self.has_virustotal_api(),
            'shodan': bool(self.api_config.shodan_api_key),
            'ip_geolocation': True,  # free, no key required
        }

    def get_active_features(self) -> list:
        """Return list of active feature names based on which API keys are present."""
        features = ['DNS Analysis', 'Network Intelligence', 'Asset Discovery']
        
        if self.has_securitytrails_api():
            features.extend(['Historical DNS', 'Domain Intelligence', 'Subdomain History'])
        
        if self.has_virustotal_api():
            features.extend(['Reputation Analysis', 'Malware Detection'])
        
        if self.api_config.shodan_api_key:
            features.append('Shodan Integration')
        
        return features
    
    def update_setting(self, category: str, setting: str, value: Any) -> bool:
        """Update a single setting by category name ('scan', 'api', 'output')."""
        try:
            if category == 'scan':
                if hasattr(self.scan_settings, setting):
                    setattr(self.scan_settings, setting, value)
                    return True
            elif category == 'api':
                if hasattr(self.api_config, setting):
                    setattr(self.api_config, setting, value)
                    return True
            elif category == 'output':
                if hasattr(self.output_settings, setting):
                    setattr(self.output_settings, setting, value)
                    return True
            
            return False
        except Exception:
            return False
    
    def get_configuration_summary(self) -> Dict[str, Any]:
        """Return full configuration overview (no API key values)."""
        return {
            'scan_settings': {
                'dns_timeout': self.scan_settings.dns_timeout,
                'traceroute_timeout_regional': self.scan_settings.traceroute_timeout_regional,
                'traceroute_timeout_international': self.scan_settings.traceroute_timeout_international,
                'max_subdomain_threads': self.scan_settings.max_subdomain_threads,
                'api_timeout': self.scan_settings.api_timeout
            },
            'api_status': self.get_api_status(),
            'active_features': self.get_active_features(),
            'output_settings': {
                'use_colors': self.output_settings.use_colors,
                'verbose_mode': self.output_settings.verbose_mode,
                'output_directory': self.output_settings.output_directory,
                'generate_json': self.output_settings.generate_json
            }
        }

_settings_instance = None


def get_settings() -> Settings:
    """Return the singleton Settings instance, creating it on first call."""
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = Settings()
    return _settings_instance


def reload_settings() -> Settings:
    """Force-reload settings (e.g. after editing the .env file)."""
    global _settings_instance
    _settings_instance = Settings()
    return _settings_instance
