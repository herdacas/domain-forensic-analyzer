          
"""
Subdomain Scanner Module for Domain Forensic Analyzer
Enhanced Asset Discovery und Subdomain-Enumeration

Step 2.3 Implementation - Extrahiert aus monolithischem Code
"""

import os
import random
import socket
import string
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Optional

# Foundation-Module importieren
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from config.settings import get_settings
from src.utils.colors import Colors
from src.utils.validators import DomainValidator


class SubdomainScanner:
    """
    Enhanced Subdomain-Discovery fuer Asset-Mapping
    
    Fuehrt umfassende Subdomain-Enumeration durch mit Kategorisierung
    von Admin-, API-, Dev- und Commerce-Interfaces. Erkennt Wildcard-DNS.
    """
    
    def __init__(self):
        """Initialisiert Subdomain-Scanner mit erweiterten Wortlisten"""
        self.results = {}
        self.domain = None
        self.settings = get_settings()
        self.subdomain_timeout = self.settings.scan_settings.subdomain_timeout
        self.max_threads = self.settings.scan_settings.max_subdomain_threads
        
        # Erweiterte Subdomain-Wortlisten nach Kategorien
        self.basic_subdomains = [
            'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'imap',
            'ns1', 'ns2', 'ns3', 'mx', 'email'
        ]
        
        self.admin_subdomains = [
            'admin', 'administrator', 'panel', 'control', 'manage', 'manager',
            'cpanel', 'plesk', 'webmin', 'backend', 'dashboard', 'console'
        ]
        
        self.api_subdomains = [
            'api', 'rest', 'graphql', 'webhook', 'callback', 'gateway',
            'service', 'ws', 'rpc', 'soap', 'json', 'xml'
        ]
        
        self.dev_subdomains = [
            'dev', 'development', 'test', 'testing', 'staging', 'stage',
            'beta', 'alpha', 'demo', 'sandbox', 'lab', 'preview'
        ]
        
        self.service_subdomains = [
            'auth', 'login', 'sso', 'oauth', 'accounts', 'profile', 'user',
            'users', 'account', 'session', 'portal', 'access'
        ]
        
        self.commerce_subdomains = [
            'shop', 'store', 'cart', 'checkout', 'payment', 'billing',
            'order', 'orders', 'purchase', 'buy', 'sell', 'ecommerce'
        ]
        
        self.content_subdomains = [
            'blog', 'news', 'forum', 'wiki', 'docs', 'documentation',
            'support', 'help', 'faq', 'kb', 'knowledgebase', 'community'
        ]
        
        self.infrastructure_subdomains = [
            'cdn', 'cache', 'static', 'assets', 'media', 'images',
            'files', 'download', 'uploads', 'storage', 'backup'
        ]
        
        # Alle Subdomains kombinieren
        self.all_subdomains = (
            self.basic_subdomains + self.admin_subdomains + self.api_subdomains +
            self.dev_subdomains + self.service_subdomains + self.commerce_subdomains +
            self.content_subdomains + self.infrastructure_subdomains
        )
        
        # Risk-kategorisierte Subdomains
        self.sensitive_subdomains = self.admin_subdomains + self.api_subdomains + self.dev_subdomains
    
    def scan_subdomains(self, domain: str) -> Dict[str, Any]:
        """
        Hauptfunktion fuer Enhanced Subdomain-Discovery
        
        Args:
            domain (str): Basis-Domain fuer Subdomain-Scan
            
        Returns:
            dict: Subdomain-Scan Ergebnisse mit Kategorisierung
        """
        print(Colors.header("ASSET DISCOVERY"))
        print(Colors.investigation_separator(60))
        
        # Domain-Validierung
        if not DomainValidator.is_valid_domain(domain):
            error_msg = f"Ungueltige Domain: {domain}"
            print(Colors.error(error_msg))
            return {'error': error_msg, 'analysis_status': 'fehlgeschlagen'}
        
        # Domain bereinigen und speichern
        clean_domain = DomainValidator.clean_domain(domain)
        self.domain = clean_domain
        print(f"Scanne Subdomains fuer: {Colors.format_domain(clean_domain)}")
        
        # Ergebnis-Dictionary initialisieren
        results = {
            'domain': clean_domain,
            'timestamp': datetime.now().isoformat(),
            'wildcard_detected': False,
            'total_subdomains_tested': 0,
            'discovered_assets': [],
            'categorized_assets': {
                'admin': [],
                'api': [],
                'dev': [],
                'service': [],
                'commerce': [],
                'content': [],
                'infrastructure': [],
                'basic': []
            },
            'sensitive_assets': [],
            'analysis_status': 'gestartet'
        }
        
        # Wildcard-DNS-Erkennung
        print(f"\n{Colors.section_header('DNS CONFIGURATION', 50)}")
        wildcard_detected = self._detect_wildcard(clean_domain)
        results['wildcard_detected'] = wildcard_detected
        
        if wildcard_detected:
            print(f"  {Colors.warning('DNS-Konfiguration:')} Wildcard aktiviert")
            print(f"  {Colors.info('Strategie:')} Reduzierte Subdomain-Liste verwenden")
            subdomains_to_test = self.basic_subdomains + self.admin_subdomains + self.api_subdomains
        else:
            print(f"  {Colors.success('DNS-Konfiguration:')} Standard (selektive Aufloesung)")
            print(f"  {Colors.info('Strategie:')} Vollstaendige Subdomain-Enumeration")
            subdomains_to_test = self.all_subdomains
        
        # Subdomain-Discovery
        print(f"\n{Colors.section_header('SUBDOMAIN ENUMERATION', 50)}")
        print(f"  {Colors.info('Zu testende Subdomains:')} {len(subdomains_to_test)}")
        print(f"  {Colors.info('Max. Threads:')} {self.max_threads}")
        print(f"  {Colors.info('Timeout pro Subdomain:')} {self.subdomain_timeout}s")
        
        discovered_assets = self._enumerate_subdomains(clean_domain, subdomains_to_test)
        results['discovered_assets'] = discovered_assets
        results['total_subdomains_tested'] = len(subdomains_to_test)
        
        # Asset-Kategorisierung
        print(f"\n{Colors.section_header('ASSET CATEGORIZATION', 50)}")
        categorized_assets = self._categorize_assets(discovered_assets)
        results['categorized_assets'] = categorized_assets
        
        # Sensitive Asset-Analyse
        sensitive_assets = self._analyze_sensitive_assets(discovered_assets)
        results['sensitive_assets'] = sensitive_assets
        
        # Analyse abschliessen
        results['analysis_status'] = 'abgeschlossen'
        self.results = results
        
        # Zusammenfassung anzeigen
        self._display_summary(results)
        return results
    
    def _detect_wildcard(self, domain: str) -> bool:
        """
        Erkennt Wildcard-DNS-Konfiguration durch Random-Subdomain-Tests
        
        Args:
            domain (str): Domain fuer Wildcard-Test
            
        Returns:
            bool: True wenn Wildcard-DNS erkannt
        """
        print(f"  {Colors.info('Wildcard-Erkennung:')} Teste Random-Subdomains...")
        
        # Generiere 3 zufaellige Subdomain-Namen
        test_subdomains = []
        for _ in range(3):
            random_name = ''.join(random.choices(string.ascii_lowercase, k=8))
            test_subdomains.append(f"{random_name}.{domain}")
        
        resolved_ips = []
        for test_subdomain in test_subdomains:
            try:
                old_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(3)  # Kurzer Timeout fuer Wildcard-Test
                
                ip = socket.gethostbyname(test_subdomain)
                resolved_ips.append(ip)
                
                socket.setdefaulttimeout(old_timeout)
            except socket.gaierror:
                socket.setdefaulttimeout(old_timeout)
                resolved_ips.append(None)
            except Exception:
                socket.setdefaulttimeout(old_timeout)
                resolved_ips.append(None)
        
        # Catch-all / wildcard: any 2+ random subdomains resolving = catch-all DNS.
        # IP uniformity is NOT required — load-balanced pools return different IPs
        # per query but still resolve every subdomain (false negative before this fix).
        valid_ips = [ip for ip in resolved_ips if ip is not None]

        if len(valid_ips) >= 2:
            unique_ips = set(valid_ips)
            if len(unique_ips) == 1:
                print(f"    {Colors.warning('Wildcard detected:')} random subdomains -> {valid_ips[0]}")
            else:
                print(f"    {Colors.warning('Catch-all detected:')} random subdomains resolve to IP pool {unique_ips}")
            return True

        print(f"    {Colors.success('No wildcard/catch-all:')} random subdomains did not resolve")
        return False
    
    def _enumerate_subdomains(self, domain: str, subdomains_to_test: List[str]) -> List[Dict[str, Any]]:
        """
        Multi-threaded Subdomain-Enumeration
        
        Args:
            domain (str): Basis-Domain
            subdomains_to_test (list): Liste zu testender Subdomains
            
        Returns:
            list: Entdeckte aktive Subdomains
        """
        discovered_assets = []
        
        def check_subdomain(subdomain: str) -> Optional[Dict[str, Any]]:
            """Testet einzelne Subdomain auf Existenz"""
            full_domain = f"{subdomain}.{domain}"
            
            try:
                old_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(self.subdomain_timeout)
                
                ip_address = socket.gethostbyname(full_domain)
                socket.setdefaulttimeout(old_timeout)
                
                return {
                    'subdomain': subdomain,
                    'full_domain': full_domain,
                    'ip_address': ip_address,
                    'status': 'active'
                }
            except socket.gaierror:
                socket.setdefaulttimeout(old_timeout)
                return None
            except Exception:
                socket.setdefaulttimeout(old_timeout)
                return None
        
        # Multi-threaded Scanning
        print(f"  {Colors.info('Scanning-Status:')} Starte Multi-Thread-Enumeration...")
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            # Alle Subdomain-Tests submiten
            future_to_subdomain = {
                executor.submit(check_subdomain, subdomain): subdomain 
                for subdomain in subdomains_to_test
            }
            
            # Ergebnisse sammeln
            for future in as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    discovered_assets.append(result)
        
        print(f"  {Colors.success('Enumeration abgeschlossen:')} {len(discovered_assets)} aktive Subdomains gefunden")
        return discovered_assets
    
    def _categorize_assets(self, discovered_assets: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Kategorisiert entdeckte Assets nach Funktionsbereichen
        
        Args:
            discovered_assets (list): Entdeckte Subdomains
            
        Returns:
            dict: Nach Kategorien gruppierte Assets
        """
        categorized = {
            'admin': [],
            'api': [],
            'dev': [],
            'service': [],
            'commerce': [],
            'content': [],
            'infrastructure': [],
            'basic': []
        }
        
        for asset in discovered_assets:
            subdomain = asset['subdomain'].lower()
            categorized_flag = False
            
            # Admin-Interfaces (hoechste Prioritaet)
            if subdomain in self.admin_subdomains:
                categorized['admin'].append(asset)
                categorized_flag = True
            
            # API-Endpoints
            elif subdomain in self.api_subdomains:
                categorized['api'].append(asset)
                categorized_flag = True
            
            # Development-Umgebungen
            elif subdomain in self.dev_subdomains:
                categorized['dev'].append(asset)
                categorized_flag = True
            
            # Service-Interfaces
            elif subdomain in self.service_subdomains:
                categorized['service'].append(asset)
                categorized_flag = True
            
            # Commerce-Funktionen
            elif subdomain in self.commerce_subdomains:
                categorized['commerce'].append(asset)
                categorized_flag = True
            
            # Content-Management
            elif subdomain in self.content_subdomains:
                categorized['content'].append(asset)
                categorized_flag = True
            
            # Infrastructure
            elif subdomain in self.infrastructure_subdomains:
                categorized['infrastructure'].append(asset)
                categorized_flag = True
            
            # Basic/Standard Subdomains
            else:
                categorized['basic'].append(asset)
        
        # Kategorisierungs-Ergebnisse anzeigen
        for category, assets in categorized.items():
            if assets:
                category_name = category.title()
                print(f"  {Colors.info(f'{category_name}:')} {len(assets)} Assets")
                
                # Erste 3 Assets der Kategorie anzeigen
                for asset in assets[:3]:
                    risk_indicator = ""
                    if category in ['admin', 'api', 'dev']:
                        risk_indicator = Colors.warning(" [SENSITIVE]")
                    
                    print(f"    {Colors.format_domain(asset['full_domain'])}{risk_indicator}")
        
        return categorized
    
    def _analyze_sensitive_assets(self, discovered_assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analysiert sensitive Assets mit Risk-Assessment
        
        Args:
            discovered_assets (list): Entdeckte Assets
            
        Returns:
            list: Sensitive Assets mit Risk-Level
        """
        sensitive_assets = []
        
        for asset in discovered_assets:
            subdomain = asset['subdomain'].lower()
            
            # Risk-Level bestimmen
            if subdomain in self.admin_subdomains:
                risk_level = 'critical'
                risk_reason = 'Administrative Interface'
            elif subdomain in self.api_subdomains:
                risk_level = 'high'
                risk_reason = 'API Endpoint'
            elif subdomain in self.dev_subdomains:
                risk_level = 'high'
                risk_reason = 'Development Environment'
            elif subdomain in self.service_subdomains:
                risk_level = 'medium'
                risk_reason = 'Service Interface'
            else:
                continue  # Nicht als sensitiv eingestuft
            
            sensitive_asset = {
                'asset': asset,
                'risk_level': risk_level,
                'risk_reason': risk_reason,
                'recommendations': self._get_risk_recommendations(risk_level, subdomain)
            }
            
            sensitive_assets.append(sensitive_asset)
        
        # Sensitive Assets anzeigen
        if sensitive_assets:
            print(f"\n  {Colors.warning('SENSITIVE ASSETS DETECTED:')} {len(sensitive_assets)} Interfaces")
            
            # Nach Risk-Level sortieren
            risk_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            sensitive_assets.sort(key=lambda x: risk_order.get(x['risk_level'], 4))
            
            for sensitive in sensitive_assets[:5]:  # Top 5 anzeigen
                asset = sensitive['asset']
                risk_level = sensitive['risk_level'].upper()
                risk_color = Colors.critical if risk_level == 'CRITICAL' else Colors.error if risk_level == 'HIGH' else Colors.warning
                
                print(f"    {risk_color(risk_level)}: {Colors.format_domain(asset['full_domain'])}")
                print(f"      Reason: {sensitive['risk_reason']}")
        else:
            print(f"\n  {Colors.success('SENSITIVE ASSETS:')} Keine kritischen Interfaces gefunden")
        
        return sensitive_assets
    
    def _get_risk_recommendations(self, risk_level: str, subdomain: str) -> List[str]:
        """
        Generiert Sicherheitsempfehlungen basierend auf Risk-Level
        
        Args:
            risk_level (str): Risk-Level des Assets
            subdomain (str): Subdomain-Name
            
        Returns:
            list: Sicherheitsempfehlungen
        """
        recommendations = []
        
        if risk_level == 'critical':
            recommendations.extend([
                'Implement strong authentication (MFA)',
                'Restrict access by IP whitelist',
                'Use VPN-only access',
                'Regular security audits'
            ])
        elif risk_level == 'high':
            recommendations.extend([
                'API authentication required',
                'Rate limiting implementation',
                'Access logging enabled',
                'Regular vulnerability scans'
            ])
        elif risk_level == 'medium':
            recommendations.extend([
                'Basic authentication required',
                'Monitor access patterns',
                'Regular updates'
            ])
        
        return recommendations
    
    def _display_summary(self, results: Dict[str, Any]) -> None:
        """
        Zeigt Enhanced Asset Discovery Zusammenfassung
        
        Args:
            results (dict): Scan-Ergebnisse
        """
        print(f"\n{Colors.investigation_separator(60)}")
        print(Colors.header("ASSET DISCOVERY SUMMARY"))
        print(Colors.investigation_separator(60))
        
        # Basis-Informationen
        print(f"Domain: {Colors.format_domain(results['domain'])}")
        print(f"Subdomains Tested: {Colors.highlight(str(results['total_subdomains_tested']))}")
        print(f"Active Assets Found: {Colors.success(str(len(results['discovered_assets'])))}")
        
        # Wildcard-Status
        if results['wildcard_detected']:
            print(f"DNS Configuration: {Colors.warning('Wildcard Enabled')}")
        else:
            print(f"DNS Configuration: {Colors.success('Standard Resolution')}")
        
        # Kategorie-Uebersicht
        categorized = results['categorized_assets']
        total_categorized = sum(len(assets) for assets in categorized.values())
        
        if total_categorized > 0:
            print(f"\nAsset Categories:")
            for category, assets in categorized.items():
                if assets:
                    category_name = category.title()
                    count = len(assets)
                    
                    if category in ['admin', 'api', 'dev']:
                        print(f"  {Colors.warning(f'{category_name}:')} {count} (Sensitive)")
                    else:
                        print(f"  {Colors.info(f'{category_name}:')} {count}")
        
        # Risk-Assessment
        sensitive_count = len(results['sensitive_assets'])
        if sensitive_count > 0:
            critical_count = sum(1 for asset in results['sensitive_assets'] if asset['risk_level'] == 'critical')
            high_count = sum(1 for asset in results['sensitive_assets'] if asset['risk_level'] == 'high')
            
            print(f"\nRisk Assessment:")
            if critical_count > 0:
                print(f"  Critical Risk Assets: {Colors.critical(str(critical_count))}")
            if high_count > 0:
                print(f"  High Risk Assets: {Colors.error(str(high_count))}")
            
            print(f"  Total Sensitive Assets: {Colors.warning(str(sensitive_count))}")
        else:
            print(f"\nRisk Assessment: {Colors.success('No sensitive interfaces exposed')}")
        
        print(Colors.investigation_separator(60))
        print(f"Analysis Status: {Colors.success('COMPLETE')}")
        print(Colors.investigation_separator(60))
    
    def get_results(self) -> Dict[str, Any]:
        """
        Gibt letzte Scan-Ergebnisse zurueck
        
        Returns:
            dict: Subdomain-Scan Ergebnisse
        """
        return self.results
    
    def get_sensitive_assets(self) -> List[Dict[str, Any]]:
        """
        Gibt nur sensitive Assets zurueck
        
        Returns:
            list: Sensitive Assets mit Risk-Assessment
        """
        return self.results.get('sensitive_assets', [])

# Test-Funktion fuer Subdomain-Scanner
