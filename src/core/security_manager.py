          
"""
Security Manager for Domain Forensic Analyzer
Sichere API-Key-Verwaltung und Configuration-Handling

SECURITY-FIRST: Keine API-Keys im Code, Environment-Variables, sichere Fallbacks
"""

import os
import sys
from typing import Dict, Any, Optional
from pathlib import Path
import json

# Foundation-Module importieren
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.utils.colors import Colors

class SecurityManager:
    """
    Sichere Verwaltung von API-Keys und sensiblen Konfigurationen
    
    SECURITY-PRINCIPLES:
    - Keine API-Keys im Code
    - Environment-Variables First
    - Sichere Fallback-Strategien
    - Keine sensiblen Daten in Logs
    - Graceful Degradation bei fehlenden Keys
    """
    
    def __init__(self):
        """Initialisiert Security Manager mit sicheren Defaults"""
        self.config_dir = Path(__file__).parent.parent.parent / "config"
        self.secure_config = {}
        self.available_apis = {}
        
        # Security-Status
        self.security_status = {
            'api_keys_loaded': False,
            'environment_vars_available': False,
            'config_files_found': False,
            'security_warnings': []
        }
        
        # Load secure configuration
        self._load_secure_configuration()
    
    def _load_secure_configuration(self) -> None:
        """
        Lädt sichere Konfiguration in Prioritäts-Reihenfolge:
        1. Environment Variables (höchste Priorität)
        2. Local config files (falls vorhanden)
        3. Demo-Mode fallback (sichere Defaults)
        """
        print(f"{Colors.info('Security Manager:')} Lade sichere Konfiguration...")
        
        # 1. Environment Variables (Production-Ready)
        self._load_environment_variables()
        
        # 2. Local Config Files (Development)
        self._load_config_files()
        
        # 3. Validate und Setup
        self._validate_security_setup()
        
        # 4. Security Status anzeigen
        self._display_security_status()
    
    def _load_environment_variables(self) -> None:
        """
        Lädt API-Keys aus Environment Variables
        
        SUPPORTED ENVIRONMENT VARIABLES:
        - SECURITYTRAILS_API_KEY
        - VIRUSTOTAL_API_KEY  
        - SHODAN_API_KEY
        - etc.
        """
        env_keys = {
            'securitytrails': 'SECURITYTRAILS_API_KEY',
            'virustotal': 'VIRUSTOTAL_API_KEY',
            'shodan': 'SHODAN_API_KEY',
            'censys': 'CENSYS_API_KEY'
        }
        
        found_keys = 0
        for service, env_var in env_keys.items():
            api_key = os.getenv(env_var)
            if api_key and len(api_key) > 10:  # Basic validation
                self.secure_config[f'{service}_api_key'] = api_key
                self.available_apis[service] = True
                found_keys += 1
                print(f"  {Colors.success('✓')} {service.title()}: API-Key aus Environment geladen")
            else:
                self.available_apis[service] = False
        
        if found_keys > 0:
            self.security_status['environment_vars_available'] = True
            self.security_status['api_keys_loaded'] = True
            print(f"  {Colors.success('Environment Variables:')} {found_keys} API-Keys geladen")
        else:
            print(f"  {Colors.warning('Environment Variables:')} Keine API-Keys gefunden")
    
    def _load_config_files(self) -> None:
        """
        Lädt API-Keys aus lokalen Config-Files (Development-Mode)
        
        SICHERE CONFIG-FILES:
        - config/api_keys.json (git-ignored)
        - config/.env (git-ignored)
        """
        # api_keys.json (JSON-Format)
        api_keys_file = self.config_dir / "api_keys.json"
        if api_keys_file.exists():
            try:
                with open(api_keys_file, 'r') as f:
                    file_config = json.load(f)
                
                loaded_from_file = 0
                for service, api_key in file_config.items():
                    if service not in self.secure_config and api_key:  # Environment hat Priorität
                        self.secure_config[f'{service}_api_key'] = api_key
                        self.available_apis[service.replace('_api_key', '')] = True
                        loaded_from_file += 1
                
                if loaded_from_file > 0:
                    self.security_status['config_files_found'] = True
                    self.security_status['api_keys_loaded'] = True
                    print(f"  {Colors.success('Config-File:')} {loaded_from_file} zusätzliche API-Keys geladen")
                    
            except (json.JSONDecodeError, Exception) as error:
                self.security_status['security_warnings'].append(f"Config-File error: {error}")
                print(f"  {Colors.warning('Config-File:')} Fehler beim Laden - {error}")
        
        # .env-File (Environment-Format)
        env_file = self.config_dir / ".env"
        if env_file.exists():
            self._load_env_file(env_file)
    
    def _load_env_file(self, env_file: Path) -> None:
        """
        Lädt .env-File für Development
        
        Args:
            env_file (Path): Pfad zur .env-Datei
        """
        try:
            with open(env_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip().strip('"\'')
                        
                        # Nur API-Key-relevante Variables
                        if key.endswith('_API_KEY') and value:
                            service = key.replace('_API_KEY', '').lower()
                            config_key = f'{service}_api_key'
                            
                            if config_key not in self.secure_config:  # Environment hat Priorität
                                self.secure_config[config_key] = value
                                self.available_apis[service] = True
                                
            print(f"  {Colors.success('.env-File:')} Zusätzliche Konfiguration geladen")
            
        except Exception as error:
            self.security_status['security_warnings'].append(f".env file error: {error}")
            print(f"  {Colors.warning('.env-File:')} Fehler - {error}")
    
    def _validate_security_setup(self) -> None:
        """
        Validiert Security-Setup und identifiziert potenzielle Probleme
        """
        # Validiere API-Key-Formate
        for service, api_key in self.secure_config.items():
            if len(api_key) < 10:
                self.security_status['security_warnings'].append(f"Suspicious {service}: API-Key too short")
            elif api_key in ['test', 'demo', 'placeholder']:
                self.security_status['security_warnings'].append(f"Placeholder {service}: Not a real API-Key")
        
        # Prüfe git-ignore Status
        gitignore_file = self.config_dir.parent / ".gitignore"
        if gitignore_file.exists():
            try:
                with open(gitignore_file, 'r') as f:
                    gitignore_content = f.read()
                    
                if 'api_keys.json' not in gitignore_content:
                    self.security_status['security_warnings'].append("api_keys.json not in .gitignore")
                if '.env' not in gitignore_content:
                    self.security_status['security_warnings'].append(".env not in .gitignore")
                    
            except Exception:
                self.security_status['security_warnings'].append("Could not verify .gitignore")
    
    def _display_security_status(self) -> None:
        """
        Zeigt Security-Status und verfügbare APIs
        """
        print(f"\n{Colors.section_header('SECURITY STATUS', 40)}")
        
        # API-Verfügbarkeit
        total_apis = len(self.available_apis)
        available_apis = sum(self.available_apis.values())
        
        if available_apis > 0:
            print(f"  {Colors.success('API-Keys:')} {available_apis}/{total_apis} verfügbar")
        else:
            print(f"  {Colors.warning('API-Keys:')} Keine verfügbar (Demo-Mode aktiv)")
        
        # Service-spezifischer Status
        for service, available in self.available_apis.items():
            status_icon = Colors.success('✓') if available else Colors.dim('○')
            print(f"    {status_icon} {service.title()}: {'Verfügbar' if available else 'Demo-Mode'}")
        
        # Security-Warnings
        if self.security_status['security_warnings']:
            print(f"\n  {Colors.warning('Security-Warnings:')}")
            for warning in self.security_status['security_warnings']:
                print(f"    {Colors.warning('⚠')} {warning}")
        else:
            print(f"  {Colors.success('Security:')} Keine Warnungen")
    
    def get_api_key(self, service: str) -> Optional[str]:
        """
        Sicheres Abrufen von API-Keys
        
        Args:
            service (str): Service-Name (z.B. 'securitytrails')
            
        Returns:
            str: API-Key oder None (für Demo-Mode)
        """
        config_key = f'{service}_api_key'
        return self.secure_config.get(config_key)
    
    def is_api_available(self, service: str) -> bool:
        """
        Prüft ob API für Service verfügbar ist
        
        Args:
            service (str): Service-Name
            
        Returns:
            bool: True wenn API-Key verfügbar
        """
        return self.available_apis.get(service, False)
    
    def get_available_services(self) -> Dict[str, bool]:
        """
        Gibt Übersicht aller Services und deren Verfügbarkeit
        
        Returns:
            dict: Service-Name -> Verfügbar (bool)
        """
        return self.available_apis.copy()
    
    def create_secure_config_template(self) -> None:
        """
        Erstellt sichere Config-Templates für User-Setup
        """
        print(f"{Colors.info('Security Manager:')} Erstelle Config-Templates...")
        
        # api_keys.json Template
        template_file = self.config_dir / "api_keys.json.template"
        template_data = {
            "securitytrails": "YOUR_SECURITYTRAILS_API_KEY_HERE",
            "virustotal": "YOUR_VIRUSTOTAL_API_KEY_HERE",
            "shodan": "YOUR_SHODAN_API_KEY_HERE",
            "censys": "YOUR_CENSYS_API_KEY_HERE"
        }
        
        with open(template_file, 'w') as f:
            json.dump(template_data, f, indent=2)
        
        # .env Template
        env_template = self.config_dir / ".env.template"
        env_content = """# Domain Forensic Analyzer - API Configuration
# Copy to .env and add your real API keys

SECURITYTRAILS_API_KEY=your_securitytrails_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here
SHODAN_API_KEY=your_shodan_key_here
CENSYS_API_KEY=your_censys_key_here

# Note: These files are git-ignored for security
"""
        
        with open(env_template, 'w') as f:
            f.write(env_content)
        
        print(f"  {Colors.success('Templates erstellt:')} api_keys.json.template & .env.template")
        print(f"  {Colors.info('Setup-Hinweis:')} Kopieren Sie Templates und fügen Sie echte API-Keys hinzu")
    
    def sanitize_for_logging(self, text: str) -> str:
        """
        Entfernt sensible Daten aus Log-Nachrichten
        
        Args:
            text (str): Text für Logging
            
        Returns:
            str: Bereinigter Text ohne API-Keys
        """
        sanitized = text
        
        # API-Key-Pattern erkennen und maskieren
        for api_key in self.secure_config.values():
            if api_key and len(api_key) > 6:
                # Zeige nur erste und letzte 3 Zeichen
                masked = f"{api_key[:3]}...{api_key[-3:]}"
                sanitized = sanitized.replace(api_key, masked)
        
        return sanitized
    
    def get_security_report(self) -> Dict[str, Any]:
        """
        Generiert Security-Report für Audit-Zwecke
        
        Returns:
            dict: Security-Status-Report
        """
        return {
            'api_keys_loaded': self.security_status['api_keys_loaded'],
            'available_services': sum(self.available_apis.values()),
            'total_services': len(self.available_apis),
            'security_warnings_count': len(self.security_status['security_warnings']),
            'environment_vars_used': self.security_status['environment_vars_available'],
            'config_files_used': self.security_status['config_files_found'],
            'services_status': self.available_apis.copy()
        }

# Factory Function für sichere Security-Manager-Erstellung
def create_security_manager() -> SecurityManager:
    """
    Factory-Funktion für Security-Manager
    
    Returns:
        SecurityManager: Konfigurierter Security-Manager
    """
    return SecurityManager()

# Test-Funktion für Security Manager
def main():
    """
    Test-Funktion für Security Manager
    Demonstriert sichere API-Key-Verwaltung
    """
    print(Colors.header("SECURITY MANAGER TEST - STEP 2.1"))
    print(Colors.investigation_separator(60))
    
    # Security Manager erstellen
    security_manager = create_security_manager()
    
    # Config-Templates erstellen
    security_manager.create_secure_config_template()
    
    # Security-Report anzeigen
    report = security_manager.get_security_report()
    
    print(f"\n{Colors.section_header('SECURITY REPORT', 40)}")
    services_text = f'{report["available_services"]}/{report["total_services"]}'
    print(f"Available Services: {Colors.highlight(services_text)}")
    print(f"Security Warnings: {Colors.highlight(str(report['security_warnings_count']))}")
    print(f"Environment Variables: {Colors.success('Yes') if report['environment_vars_used'] else Colors.warning('No')}")
    
    # Demonstration: API-Key-Zugriff
    print(f"\n{Colors.section_header('API ACCESS TEST', 40)}")
    for service in ['securitytrails', 'virustotal', 'shodan']:
        available = security_manager.is_api_available(service)
        status = Colors.success('Available') if available else Colors.warning('Demo-Mode')
        print(f"  {service.title()}: {status}")
    
    print(f"\n{Colors.investigation_separator(60)}")
    print(Colors.success("SECURITY MANAGER STEP 2.1 - TESTING COMPLETE"))
    print(Colors.investigation_separator(60))

if __name__ == "__main__":
    main()
