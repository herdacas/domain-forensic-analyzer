          
"""
Configuration Management for Domain Forensic Analyzer
Zentrale Konfigurationsverwaltung fuer API-Keys und Einstellungen
"""

import os
from typing import Dict, Optional, Any
from dataclasses import dataclass

@dataclass
class ScanSettings:
    """
    Konfiguration fuer Scan-Parameter
    """
    # Timeout-Einstellungen
    dns_timeout: int = 10
    traceroute_timeout_regional: int = 50
    traceroute_timeout_international: int = 75
    api_timeout: int = 15
    
    # Subdomain-Scanning
    max_subdomain_threads: int = 12
    subdomain_timeout: int = 5
    
    # Netzwerk-Analyse
    max_traceroute_hops: int = 15
    traceroute_encoding: str = 'cp850'  # Windows-Standard
    
    # Rate-Limiting
    api_rate_limit_delay: float = 0.5
    request_delay: float = 0.1

@dataclass
class APIConfig:
    """
    Konfiguration fuer externe APIs
    """
    securitytrails_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    shodan_api_key: Optional[str] = None
    
    # API-Endpunkte
    securitytrails_base_url: str = "https://api.securitytrails.com/v1"
    virustotal_base_url: str = "https://www.virustotal.com/vtapi/v2"
    ip_geolocation_url: str = "http://ip-api.com/json"

@dataclass
class OutputSettings:
    """
    Konfiguration fuer Output und Reporting
    """
    # Terminal-Output
    use_colors: bool = True
    verbose_mode: bool = False
    show_progress: bool = True
    
    # Report-Generation
    generate_json: bool = True
    generate_pdf: bool = False
    output_directory: str = "reports"
    
    # Investigation-Tracking
    include_timestamps: bool = True
    include_investigation_id: bool = True

class Settings:
    """
    Hauptkonfigurationsklasse fuer Domain Forensic Analyzer
    
    Verwaltet alle Konfigurationsaspekte und laedt Einstellungen
    aus Umgebungsvariablen und Konfigurationsdateien.
    """
    
    def __init__(self):
        """Initialisiert Settings und laedt Konfiguration"""
        self.scan_settings = ScanSettings()
        self.api_config = APIConfig()
        self.output_settings = OutputSettings()
        
        # Konfiguration aus Umgebungsvariablen laden
        self._load_from_environment()
        
        # Konfiguration validieren
        self._validate_configuration()
    
    def _load_from_environment(self) -> None:
        """
        Laedt Konfiguration aus Umgebungsvariablen (.env Datei)
        """
        # API-Keys aus Umgebungsvariablen
        self.api_config.securitytrails_api_key = os.getenv('SECURITYTRAILS_API_KEY')
        self.api_config.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.api_config.shodan_api_key = os.getenv('SHODAN_API_KEY')
        
        # Timeout-Einstellungen (mit Fallback-Werten)
        try:
            self.scan_settings.dns_timeout = int(os.getenv('DNS_TIMEOUT', '10'))
            self.scan_settings.api_timeout = int(os.getenv('API_TIMEOUT', '15'))
            self.scan_settings.traceroute_timeout_regional = int(os.getenv('TRACEROUTE_TIMEOUT_REGIONAL', '50'))
            self.scan_settings.traceroute_timeout_international = int(os.getenv('TRACEROUTE_TIMEOUT_INTERNATIONAL', '75'))
        except ValueError:
            # Bei ungültigen Werten Standardwerte verwenden
            pass
        
        # Threading-Einstellungen
        try:
            self.scan_settings.max_subdomain_threads = int(os.getenv('MAX_SUBDOMAIN_THREADS', '12'))
        except ValueError:
            pass
        
        # Output-Einstellungen
        self.output_settings.use_colors = os.getenv('USE_COLORS', 'true').lower() == 'true'
        self.output_settings.verbose_mode = os.getenv('VERBOSE_MODE', 'false').lower() == 'true'
        self.output_settings.output_directory = os.getenv('OUTPUT_DIRECTORY', 'reports')
    
    def _validate_configuration(self) -> None:
        """
        Validiert die geladene Konfiguration
        """
        # Timeout-Werte validieren
        if self.scan_settings.dns_timeout <= 0:
            self.scan_settings.dns_timeout = 10
        
        if self.scan_settings.api_timeout <= 0:
            self.scan_settings.api_timeout = 15
        
        # Thread-Anzahl validieren
        if self.scan_settings.max_subdomain_threads <= 0:
            self.scan_settings.max_subdomain_threads = 8
        elif self.scan_settings.max_subdomain_threads > 50:
            self.scan_settings.max_subdomain_threads = 50
        
        # Output-Verzeichnis erstellen falls nicht vorhanden
        if not os.path.exists(self.output_settings.output_directory):
            try:
                os.makedirs(self.output_settings.output_directory)
            except OSError:
                self.output_settings.output_directory = "."
    
    def has_securitytrails_api(self) -> bool:
        """
        Prueft ob SecurityTrails API-Key verfuegbar ist
        
        Returns:
            bool: True wenn API-Key konfiguriert ist
        """
        return bool(self.api_config.securitytrails_api_key)
    
    def has_virustotal_api(self) -> bool:
        """
        Prueft ob VirusTotal API-Key verfuegbar ist
        
        Returns:
            bool: True wenn API-Key konfiguriert ist
        """
        return bool(self.api_config.virustotal_api_key)
    
    def get_api_status(self) -> Dict[str, bool]:
        """
        Gibt Status aller konfigurierten APIs zurueck
        
        Returns:
            dict: API-Status als Boolean-Dictionary
        """
        return {
            'securitytrails': self.has_securitytrails_api(),
            'virustotal': self.has_virustotal_api(),
            'shodan': bool(self.api_config.shodan_api_key),
            'ip_geolocation': True  # Kostenloser Service
        }
    
    def get_active_features(self) -> list:
        """
        Gibt Liste der aktiven Features basierend auf Konfiguration zurueck
        
        Returns:
            list: Liste aktiver Features
        """
        features = ['DNS Analysis', 'Network Intelligence', 'Asset Discovery']
        
        if self.has_securitytrails_api():
            features.extend(['Historical DNS', 'Domain Intelligence', 'Subdomain History'])
        
        if self.has_virustotal_api():
            features.extend(['Reputation Analysis', 'Malware Detection'])
        
        if self.api_config.shodan_api_key:
            features.append('Shodan Integration')
        
        return features
    
    def update_setting(self, category: str, setting: str, value: Any) -> bool:
        """
        Aktualisiert eine spezifische Einstellung
        
        Args:
            category (str): Kategorie (scan, api, output)
            setting (str): Einstellungsname
            value (Any): Neuer Wert
            
        Returns:
            bool: True wenn erfolgreich aktualisiert
        """
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
        """
        Gibt vollstaendige Konfigurationsuebersicht zurueck
        
        Returns:
            dict: Konfigurationsuebersicht (ohne sensible API-Keys)
        """
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

# Globale Settings-Instanz
_settings_instance = None

def get_settings() -> Settings:
    """
    Singleton-Pattern fuer Settings
    
    Returns:
        Settings: Globale Settings-Instanz
    """
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = Settings()
    return _settings_instance

def reload_settings() -> Settings:
    """
    Laedt Settings neu (z.B. nach Aenderung der .env Datei)
    
    Returns:
        Settings: Neu geladene Settings-Instanz
    """
    global _settings_instance
    _settings_instance = Settings()
    return _settings_instance

# Test-Funktion fuer Settings
def main():
    """
    Test-Funktion fuer Configuration Management
    Zeigt aktuelle Konfiguration und API-Status
    """
    # Korrigierter Import-Pfad
    import sys
    import os
    
    # Pfad zum Hauptverzeichnis hinzufuegen
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    
    try:
        from src.utils.colors import Colors
    except ImportError:
        # Fallback ohne Farben wenn Import fehlschlaegt
        class Colors:
            @staticmethod
            def header(text): 
                return f"=== {text} ==="
            @staticmethod
            def success(text): 
                return f"[OK] {text}"
            @staticmethod
            def warning(text): 
                return f"[WARN] {text}"
            @staticmethod
            def info(text): 
                return f"[INFO] {text}"
            @staticmethod
            def highlight(text): 
                return text
            @staticmethod
            def format_status(text, status): 
                return text
            @staticmethod
            def section_header(text, width): 
                return f"--- {text} ---"
            @staticmethod
            def investigation_separator(width): 
                return "-" * width
    
    print(Colors.header("CONFIGURATION MANAGEMENT TEST"))
    print(Colors.investigation_separator(60))
    
    # Settings laden
    settings = get_settings()
    
    print(Colors.section_header("API STATUS", 50))
    api_status = settings.get_api_status()
    
    for api_name, is_active in api_status.items():
        status_text = Colors.success("ACTIVE") if is_active else Colors.warning("DISABLED")
        print(f"  {api_name}: {status_text}")
    
    print(f"\n{Colors.section_header('ACTIVE FEATURES', 50)}")
    features = settings.get_active_features()
    for feature in features:
        print(f"  + {feature}")
    
    print(f"\n{Colors.section_header('SCAN SETTINGS', 50)}")
    print(f"  DNS Timeout: {Colors.highlight(str(settings.scan_settings.dns_timeout))} seconds")
    print(f"  Traceroute Timeout (Regional): {Colors.highlight(str(settings.scan_settings.traceroute_timeout_regional))} seconds")
    print(f"  Traceroute Timeout (International): {Colors.highlight(str(settings.scan_settings.traceroute_timeout_international))} seconds")
    print(f"  Max Subdomain Threads: {Colors.highlight(str(settings.scan_settings.max_subdomain_threads))}")
    print(f"  API Timeout: {Colors.highlight(str(settings.scan_settings.api_timeout))} seconds")
    
    print(f"\n{Colors.section_header('OUTPUT SETTINGS', 50)}")
    print(f"  Use Colors: {Colors.format_status(str(settings.output_settings.use_colors), settings.output_settings.use_colors)}")
    print(f"  Verbose Mode: {Colors.format_status(str(settings.output_settings.verbose_mode), settings.output_settings.verbose_mode)}")
    print(f"  Output Directory: {Colors.highlight(settings.output_settings.output_directory)}")
    print(f"  Generate JSON: {Colors.format_status(str(settings.output_settings.generate_json), settings.output_settings.generate_json)}")
    
    print(f"\n{Colors.investigation_separator(60)}")
    print(Colors.success("Configuration Management Test completed successfully"))
    
    # Zusaetzlicher Test: Setting update
    print(f"\n{Colors.section_header('SETTING UPDATE TEST', 50)}")
    original_timeout = settings.scan_settings.dns_timeout
    update_success = settings.update_setting('scan', 'dns_timeout', 15)
    new_timeout = settings.scan_settings.dns_timeout
    
    print(f"Original DNS Timeout: {Colors.highlight(str(original_timeout))}")
    print(f"Update Success: {Colors.format_status(str(update_success), update_success)}")
    print(f"New DNS Timeout: {Colors.highlight(str(new_timeout))}")
    
    # Zuruecksetzen
    settings.update_setting('scan', 'dns_timeout', original_timeout)
    print("Settings reset to original values")

if __name__ == "__main__":
    main()
