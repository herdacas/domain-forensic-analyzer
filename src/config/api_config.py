"""
Secure API Configuration Loader
"""
import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass

@dataclass
class APIConfig:
    """API Configuration Container"""
    api_key: str
    base_url: str
    rate_limit: int
    
    def is_valid(self) -> bool:
        """Check if configuration is valid"""
        return bool(self.api_key and self.api_key != "YOUR_NEW_" and len(self.api_key) > 10)

class SecureAPIManager:
    """
    Secure API Key Management System
    """
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.config_file = self.project_root / "config" / "api_keys.json"
        self.api_configs = {}
        self._load_configurations()
    
    def _load_configurations(self) -> None:
        """Load API configurations from secure file"""
        try:
            if not self.config_file.exists():
                self._create_config_template()
                raise FileNotFoundError("Config file created. Please add your API keys.")
            
            with open(self.config_file, 'r') as f:
                config_data = json.load(f)
            
            for service_name, config in config_data.items():
                self.api_configs[service_name] = APIConfig(
                    api_key=config['api_key'],
                    base_url=config['base_url'], 
                    rate_limit=config['rate_limit']
                )
        
        except Exception as error:
            print(f"API Configuration Error: {error}")
            self.api_configs = {}
    
    def _create_config_template(self) -> None:
        """Create secure config directory and template"""
        self.config_file.parent.mkdir(exist_ok=True)
        
        template = {
            "securitytrails": {
                "api_key": "YOUR_NEW_SECURITYTRAILS_KEY_HERE",
                "base_url": "https://api.securitytrails.com/v1",
                "rate_limit": 50
            },
            "abuseipdb": {
                "api_key": "YOUR_NEW_ABUSEIPDB_KEY_HERE", 
                "base_url": "https://api.abuseipdb.com/api/v2",
                "rate_limit": 1000
            },
            "virustotal": {
                "api_key": "YOUR_NEW_VIRUSTOTAL_KEY_HERE",
                "base_url": "https://www.virustotal.com/api/v3",
                "rate_limit": 1000
            },
            "whoisxml": {
                "api_key": "YOUR_NEW_WHOISXML_API_KEY_HERE",
                "base_url": "https://whoisxmlapi.com/whoisserver/WhoisService",
                "rate_limit": 500
            }
        }
        
        with open(self.config_file, 'w') as f:
            json.dump(template, f, indent=2)
    
    def get_api_config(self, service: str) -> Optional[APIConfig]:
        """Get API configuration for service"""
        config = self.api_configs.get(service)
        if config and config.is_valid():
            return config
        return None
    
    def is_service_available(self, service: str) -> bool:
        """Check if service is configured and available"""
        config = self.get_api_config(service)
        return config is not None
    
    def get_available_services(self) -> list:
        """Get list of configured services"""
        return [service for service in self.api_configs.keys() 
                if self.is_service_available(service)]
