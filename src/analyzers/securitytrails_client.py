"""
SecurityTrails Client Module for Domain Forensic Analyzer
Historical DNS Intelligence und Enhanced Domain-Research

Step 2.5 Implementation - API-basierte erweiterte Domain-Intelligence
"""

import urllib.request
import urllib.error
import json
import sys
import os
from typing import Dict, List, Optional, Any
from datetime import datetime

# Foundation-Module importieren
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.utils.colors import Colors
from src.utils.validators import DomainValidator
from config.settings import get_settings

class SecurityTrailsClient:
    """
    SecurityTrails API-Client fuer erweiterte Domain-Intelligence
    
    Bietet Zugang zu Historical DNS-Daten, Domain-Intelligence und
    erweiterten OSINT-Funktionen durch SecurityTrails API-Integration.
    """
    
    def __init__(self):
        """Initialisiert SecurityTrails Client mit API-Konfiguration"""
        self.results = {}
        self.settings = get_settings()
        self.api_timeout = self.settings.scan_settings.api_timeout
        
        # API-Konfiguration
        self.api_key = self.settings.api_config.securitytrails_api_key
        self.base_url = self.settings.api_config.securitytrails_base_url
        self.has_api_access = bool(self.api_key)
        
        # Rate-Limiting
        self.rate_limit_delay = self.settings.scan_settings.api_rate_limit_delay
        
        # API-Endpunkte
        self.endpoints = {
            'domain_details': '/domain/{domain}',
            'historical_dns': '/history/{domain}/dns/{record_type}',
            'subdomain_discovery': '/domain/{domain}/subdomains',
            'associated_domains': '/domain/{domain}/associated',
            'domain_tags': '/domain/{domain}/tags'
        }
    
    def analyze_domain_intelligence(self, domain: str) -> Dict[str, Any]:
        """
        Hauptfunktion fuer SecurityTrails Domain-Intelligence
        
        Args:
            domain (str): Domain fuer erweiterte Analyse
            
        Returns:
            dict: SecurityTrails Intelligence-Daten
        """
        print(Colors.header("SECURITYTRAILS DOMAIN INTELLIGENCE"))
        print(Colors.investigation_separator(60))
        
        # Domain-Validierung
        if not DomainValidator.is_valid_domain(domain):
            error_msg = f"Ungueltige Domain: {domain}"
            print(Colors.error(error_msg))
            return {'error': error_msg, 'analysis_status': 'fehlgeschlagen'}
        
        # API-Key-Verfügbarkeit prüfen
        if not self.has_api_access:
            print(f"  {Colors.warning('SecurityTrails API:')} Kein API-Key konfiguriert")
            return self._provide_demo_data(domain)
        
        clean_domain = DomainValidator.clean_domain(domain)
        print(f"Analysiere Domain: {Colors.format_domain(clean_domain)}")
        print(f"API-Status: {Colors.success('AKTIV')} (SecurityTrails)")
        
        # Ergebnis-Dictionary initialisieren
        results = {
            'domain': clean_domain,
            'timestamp': datetime.now().isoformat(),
            'api_status': 'active',
            'domain_details': {},
            'historical_dns': {},
            'subdomain_intelligence': {},
            'associated_domains': {},
            'domain_tags': {},
            'analysis_status': 'gestartet'
        }
        
        # Domain-Details abrufen
        print(f"\n{Colors.section_header('DOMAIN DETAILS', 50)}")
        domain_details = self._get_domain_details(clean_domain)
        results['domain_details'] = domain_details
        
        # Historical DNS-Daten
        print(f"\n{Colors.section_header('HISTORICAL DNS INTELLIGENCE', 50)}")
        historical_dns = self._get_historical_dns(clean_domain)
        results['historical_dns'] = historical_dns
        
        # Subdomain-Discovery
        print(f"\n{Colors.section_header('SUBDOMAIN INTELLIGENCE', 50)}")
        subdomain_intel = self._get_subdomain_intelligence(clean_domain)
        results['subdomain_intelligence'] = subdomain_intel
        
        # Associated Domains
        print(f"\n{Colors.section_header('ASSOCIATED DOMAINS', 50)}")
        associated_domains = self._get_associated_domains(clean_domain)
        results['associated_domains'] = associated_domains
        
        # Domain-Tags und Kategorisierung
        print(f"\n{Colors.section_header('DOMAIN CATEGORIZATION', 50)}")
        domain_tags = self._get_domain_tags(clean_domain)
        results['domain_tags'] = domain_tags
        
        # Analyse abschließen
        results['analysis_status'] = 'abgeschlossen'
        self.results = results
        
        # Zusammenfassung anzeigen
        self._display_intelligence_summary(results)
        return results
    
    def _get_domain_details(self, domain: str) -> Dict[str, Any]:
        """
        Ruft Domain-Details von SecurityTrails ab
        
        Args:
            domain (str): Domain für Details-Abfrage
            
        Returns:
            dict: Domain-Details
        """
        print(f"  {Colors.info('Domain-Details:')} Abrufe Basis-Informationen...")
        
        endpoint = self.endpoints['domain_details'].format(domain=domain)
        response_data = self._make_api_request(endpoint)
        
        if response_data:
            domain_details = {
                'hostname': response_data.get('hostname'),
                'alexa_rank': response_data.get('alexa_rank'),
                'endpoint_count': response_data.get('endpoint_count', 0),
                'subdomain_count': response_data.get('subdomain_count', 0),
                'first_seen': response_data.get('first_seen'),
                'current_dns': response_data.get('current_dns', {}),
                'status': 'success'
            }
            
            print(f"    {Colors.success('Domain gefunden:')} {domain_details['hostname']}")
            if domain_details.get('alexa_rank'):
                print(f"    {Colors.info('Alexa Rank:')} {domain_details['alexa_rank']}")
            print(f"    {Colors.info('Subdomains bekannt:')} {domain_details['subdomain_count']}")
            print(f"    {Colors.info('Endpoints erfasst:')} {domain_details['endpoint_count']}")
            
            return domain_details
        else:
            print(f"    {Colors.warning('Domain-Details:')} Nicht verfügbar")
            return {'status': 'unavailable'}
    
    def _get_historical_dns(self, domain: str) -> Dict[str, Any]:
        """
        Ruft Historical DNS-Daten ab
        
        Args:
            domain (str): Domain für Historical DNS
            
        Returns:
            dict: Historical DNS-Daten
        """
        print(f"  {Colors.info('Historical DNS:')} Sammle DNS-Historie...")
        
        historical_data = {
            'a_records': [],
            'mx_records': [],
            'ns_records': [],
            'status': 'success'
        }
        
        # A-Records Historie
        a_records = self._get_historical_records(domain, 'a')
        if a_records:
            historical_data['a_records'] = a_records
            print(f"    {Colors.success('A-Records:')} {len(a_records)} historische Einträge")
        
        # MX-Records Historie
        mx_records = self._get_historical_records(domain, 'mx')
        if mx_records:
            historical_data['mx_records'] = mx_records
            print(f"    {Colors.success('MX-Records:')} {len(mx_records)} historische Einträge")
        
        # NS-Records Historie
        ns_records = self._get_historical_records(domain, 'ns')
        if ns_records:
            historical_data['ns_records'] = ns_records
            print(f"    {Colors.success('NS-Records:')} {len(ns_records)} historische Einträge")
        
        if not any([a_records, mx_records, ns_records]):
            print(f"    {Colors.warning('Historical DNS:')} Keine Daten verfügbar")
            historical_data['status'] = 'no_data'
        
        return historical_data
    
    def _get_historical_records(self, domain: str, record_type: str) -> Optional[List[Dict[str, Any]]]:
        """
        Ruft spezifische Historical DNS-Records ab
        
        Args:
            domain (str): Domain
            record_type (str): DNS-Record-Typ (a, mx, ns)
            
        Returns:
            list: Historical Records oder None
        """
        endpoint = self.endpoints['historical_dns'].format(domain=domain, record_type=record_type)
        response_data = self._make_api_request(endpoint)
        
        if response_data and 'records' in response_data:
            records = []
            for record in response_data['records'][:10]:  # Limit auf 10 neueste
                record_data = {
                    'first_seen': record.get('first_seen'),
                    'last_seen': record.get('last_seen'),
                    'values': record.get('values', []),
                    'organizations': record.get('organizations', [])
                }
                records.append(record_data)
            
            return records
        
        return None
    
    def _get_subdomain_intelligence(self, domain: str) -> Dict[str, Any]:
        """
        Erweiterte Subdomain-Intelligence
        
        Args:
            domain (str): Domain für Subdomain-Intel
            
        Returns:
            dict: Subdomain-Intelligence
        """
        print(f"  {Colors.info('Subdomain-Intelligence:')} Analysiere bekannte Subdomains...")
        
        endpoint = self.endpoints['subdomain_discovery'].format(domain=domain)
        response_data = self._make_api_request(endpoint)
        
        if response_data and 'subdomains' in response_data:
            subdomains = response_data['subdomains'][:20]  # Top 20
            
            # Kategorisierung der Subdomains
            categorized = self._categorize_subdomains(subdomains)
            
            subdomain_intel = {
                'total_found': len(response_data['subdomains']),
                'subdomains_sample': subdomains,
                'categorized_subdomains': categorized,
                'status': 'success'
            }
            
            print(f"    {Colors.success('Subdomains gefunden:')} {subdomain_intel['total_found']}")
            
            # Kategorien anzeigen
            for category, subs in categorized.items():
                if subs:
                    print(f"    {Colors.info(f'{category.title()}:')} {len(subs)} Subdomains")
            
            return subdomain_intel
        else:
            print(f"    {Colors.warning('Subdomain-Intel:')} Keine Daten verfügbar")
            return {'status': 'no_data'}
    
    def _categorize_subdomains(self, subdomains: List[str]) -> Dict[str, List[str]]:
        """
        Kategorisiert Subdomains nach Funktion
        
        Args:
            subdomains (list): Liste der Subdomains
            
        Returns:
            dict: Kategorisierte Subdomains
        """
        categories = {
            'admin': [],
            'api': [],
            'dev': [],
            'mail': [],
            'cdn': [],
            'other': []
        }
        
        for subdomain in subdomains:
            subdomain_lower = subdomain.lower()
            
            if any(pattern in subdomain_lower for pattern in ['admin', 'panel', 'manage']):
                categories['admin'].append(subdomain)
            elif any(pattern in subdomain_lower for pattern in ['api', 'rest', 'graphql']):
                categories['api'].append(subdomain)
            elif any(pattern in subdomain_lower for pattern in ['dev', 'test', 'stage']):
                categories['dev'].append(subdomain)
            elif any(pattern in subdomain_lower for pattern in ['mail', 'smtp', 'imap']):
                categories['mail'].append(subdomain)
            elif any(pattern in subdomain_lower for pattern in ['cdn', 'static', 'assets']):
                categories['cdn'].append(subdomain)
            else:
                categories['other'].append(subdomain)
        
        return categories
    
    def _get_associated_domains(self, domain: str) -> Dict[str, Any]:
        """
        Findet mit der Domain assoziierte Domains
        
        Args:
            domain (str): Basis-Domain
            
        Returns:
            dict: Assoziierte Domains
        """
        print(f"  {Colors.info('Associated Domains:')} Suche verwandte Domains...")
        
        endpoint = self.endpoints['associated_domains'].format(domain=domain)
        response_data = self._make_api_request(endpoint)
        
        if response_data and 'records' in response_data:
            associated = response_data['records'][:15]  # Top 15
            
            associated_data = {
                'total_found': len(response_data['records']),
                'associated_domains': associated,
                'status': 'success'
            }
            
            print(f"    {Colors.success('Assoziierte Domains:')} {associated_data['total_found']} gefunden")
            
            # Top 5 anzeigen
            for i, assoc_domain in enumerate(associated[:5], 1):
                domain_name = assoc_domain.get('hostname', 'unknown')
                print(f"    {i}. {Colors.format_domain(domain_name)}")
            
            return associated_data
        else:
            print(f"    {Colors.warning('Associated Domains:')} Keine gefunden")
            return {'status': 'no_data'}
    
    def _get_domain_tags(self, domain: str) -> Dict[str, Any]:
        """
        Ruft Domain-Tags und Kategorisierung ab
        
        Args:
            domain (str): Domain für Tags
            
        Returns:
            dict: Domain-Tags
        """
        print(f"  {Colors.info('Domain-Tags:')} Kategorisierung abrufen...")
        
        endpoint = self.endpoints['domain_tags'].format(domain=domain)
        response_data = self._make_api_request(endpoint)
        
        if response_data and 'tags' in response_data:
            tags_data = {
                'tags': response_data['tags'],
                'category': response_data.get('category'),
                'risk_score': response_data.get('risk_score'),
                'status': 'success'
            }
            
            if tags_data['tags']:
                tags_text = ', '.join(tags_data['tags'][:5])
                print(f"    {Colors.success('Tags:')} {tags_text}")
            
            if tags_data['category']:
                print(f"    {Colors.info('Kategorie:')} {tags_data['category']}")
            
            if tags_data['risk_score']:
                risk_score = tags_data['risk_score']
                risk_color = Colors.error if risk_score > 7 else Colors.warning if risk_score > 4 else Colors.success
                print(f"    {Colors.info('Risk Score:')} {risk_color(str(risk_score))}/10")
            
            return tags_data
        else:
            print(f"    {Colors.warning('Domain-Tags:')} Keine verfügbar")
            return {'status': 'no_data'}
    
    def _make_api_request(self, endpoint: str) -> Optional[Dict[str, Any]]:
        """
        Führt API-Request zu SecurityTrails durch
        
        Args:
            endpoint (str): API-Endpunkt
            
        Returns:
            dict: API-Response oder None
        """
        if not self.has_api_access:
            return None
        
        url = f"{self.base_url}{endpoint}"
        
        try:
            # Rate-Limiting beachten
            import time
            time.sleep(self.rate_limit_delay)
            
            req = urllib.request.Request(url)
            req.add_header('APIKEY', self.api_key)
            req.add_header('User-Agent', 'Domain-Forensic-Analyzer/3.4')
            
            with urllib.request.urlopen(req, timeout=self.api_timeout) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode())
                    return data
                else:
                    return None
                    
        except urllib.error.HTTPError as error:
            if error.code == 401:
                print(f"    {Colors.error('API-Fehler:')} Ungültiger API-Key")
            elif error.code == 429:
                print(f"    {Colors.warning('API-Limit:')} Rate-Limit erreicht")
            else:
                print(f"    {Colors.error('API-Fehler:')} HTTP {error.code}")
            return None
        except Exception:
            return None
    
    def _provide_demo_data(self, domain: str) -> Dict[str, Any]:
        """
        Stellt Demo-Daten bereit wenn kein API-Key verfügbar
        
        Args:
            domain (str): Domain für Demo-Daten
            
        Returns:
            dict: Demo-Intelligence-Daten
        """
        print(f"  {Colors.info('Demo-Modus:')} Simuliere SecurityTrails-Daten...")
        
        clean_domain = DomainValidator.clean_domain(domain)
        
        demo_results = {
            'domain': clean_domain,
            'timestamp': datetime.now().isoformat(),
            'api_status': 'demo_mode',
            'domain_details': {
                'hostname': clean_domain,
                'subdomain_count': 45,
                'endpoint_count': 12,
                'first_seen': '2020-01-15',
                'status': 'demo'
            },
            'historical_dns': {
                'a_records': [
                    {'first_seen': '2022-01-01', 'last_seen': '2023-01-01', 'values': ['192.168.1.100']},
                    {'first_seen': '2023-01-01', 'last_seen': '2024-01-01', 'values': ['192.168.1.101']}
                ],
                'status': 'demo'
            },
            'subdomain_intelligence': {
                'total_found': 45,
                'subdomains_sample': ['www', 'api', 'admin', 'dev', 'staging', 'mail'],
                'categorized_subdomains': {
                    'admin': ['admin'],
                    'api': ['api'],
                    'dev': ['dev', 'staging'],
                    'mail': ['mail'],
                    'other': ['www']
                },
                'status': 'demo'
            },
            'associated_domains': {
                'total_found': 8,
                'associated_domains': [
                    {'hostname': f'{clean_domain.split(".")[0]}-cdn.com'},
                    {'hostname': f'{clean_domain.split(".")[0]}-api.org'}
                ],
                'status': 'demo'
            },
            'domain_tags': {
                'tags': ['technology', 'web-service'],
                'category': 'Technology',
                'risk_score': 2,
                'status': 'demo'
            },
            'analysis_status': 'demo_abgeschlossen'
        }
        
        print(f"  {Colors.warning('Demo-Daten generiert für:')} {Colors.format_domain(clean_domain)}")
        print(f"  {Colors.info('Hinweis:')} Für echte Daten SecurityTrails API-Key konfigurieren")
        
        # Demo-Zusammenfassung anzeigen
        self._display_intelligence_summary(demo_results)
        
        return demo_results
    
    def _display_intelligence_summary(self, results: Dict[str, Any]) -> None:
        """
        Zeigt SecurityTrails Intelligence-Zusammenfassung
        
        Args:
            results (dict): Intelligence-Ergebnisse
        """
        print(f"\n{Colors.investigation_separator(60)}")
        print(Colors.header("SECURITYTRAILS INTELLIGENCE SUMMARY"))
        print(Colors.investigation_separator(60))
        
        # Domain und API-Status
        print(f"Domain: {Colors.format_domain(results['domain'])}")
        
        api_status = results.get('api_status', 'unknown')
        if api_status == 'active':
            print(f"API Status: {Colors.success('ACTIVE')} (SecurityTrails)")
        elif api_status == 'demo_mode':
            print(f"API Status: {Colors.warning('DEMO MODE')} (Kein API-Key)")
        
        # Domain-Details
        domain_details = results.get('domain_details', {})
        if domain_details.get('status') in ['success', 'demo']:
            subdomain_count = domain_details.get('subdomain_count', 0)
            endpoint_count = domain_details.get('endpoint_count', 0)
            print(f"Known Subdomains: {Colors.highlight(str(subdomain_count))}")
            print(f"Tracked Endpoints: {Colors.highlight(str(endpoint_count))}")
        
        # Historical DNS
        historical = results.get('historical_dns', {})
        if historical.get('status') in ['success', 'demo']:
            a_count = len(historical.get('a_records', []))
            mx_count = len(historical.get('mx_records', []))
            ns_count = len(historical.get('ns_records', []))
            
            if a_count > 0:
                print(f"Historical A-Records: {Colors.info(str(a_count))}")
            if mx_count > 0:
                print(f"Historical MX-Records: {Colors.info(str(mx_count))}")
            if ns_count > 0:
                print(f"Historical NS-Records: {Colors.info(str(ns_count))}")
        
        # Subdomain-Intelligence
        subdomain_intel = results.get('subdomain_intelligence', {})
        if subdomain_intel.get('status') in ['success', 'demo']:
            total_subdomains = subdomain_intel.get('total_found', 0)
            print(f"Subdomain Intelligence: {Colors.success(f'{total_subdomains} discovered')}")
            
            # Kategorien
            categorized = subdomain_intel.get('categorized_subdomains', {})
            sensitive_count = len(categorized.get('admin', [])) + len(categorized.get('api', []))
            if sensitive_count > 0:
                print(f"Sensitive Subdomains: {Colors.warning(str(sensitive_count))}")
        
        # Associated Domains
        associated = results.get('associated_domains', {})
        if associated.get('status') in ['success', 'demo']:
            assoc_count = associated.get('total_found', 0)
            if assoc_count > 0:
                print(f"Associated Domains: {Colors.info(str(assoc_count))}")
        
        # Domain-Tags
        tags = results.get('domain_tags', {})
        if tags.get('status') in ['success', 'demo']:
            if tags.get('category'):
                print(f"Category: {Colors.info(tags['category'])}")
            if tags.get('risk_score') is not None:
                risk_score = tags['risk_score']
                risk_color = Colors.error if risk_score > 7 else Colors.warning if risk_score > 4 else Colors.success
                print(f"Risk Score: {risk_color(f'{risk_score}/10')}")
        
        print(Colors.investigation_separator(60))
        print(f"Analysis Status: {Colors.success('COMPLETE')}")
        print(Colors.investigation_separator(60))
    
    def get_results(self) -> Dict[str, Any]:
        """
        Gibt SecurityTrails-Analyseergebnisse zurück
        
        Returns:
            dict: SecurityTrails Intelligence-Daten
        """
        return self.results
    
    def has_api_key(self) -> bool:
        """
        Prüft ob API-Key verfügbar ist
        
        Returns:
            bool: True wenn API-Key konfiguriert
        """
        return self.has_api_access

# Test-Funktion für SecurityTrails Client
def main():
    """
    Test-Funktion für SecurityTrails Client
    Testet mit einer Benchmark-Domain
    """
    print(Colors.header("SECURITYTRAILS CLIENT TEST - STEP 2.5"))
    print(Colors.investigation_separator(60))
    
    # Test-Domain
    test_domain = "github.com"
    
    client = SecurityTrailsClient()
    
    print(f"\n{Colors.section_header(f'TEST: {test_domain.upper()}', 60)}")
    
    results = client.analyze_domain_intelligence(test_domain)
    
    if results.get('error'):
        print(Colors.error(f"Test fehlgeschlagen: {results['error']}"))
    else:
        api_status = results.get('api_status', 'unknown')
        subdomain_count = results.get('domain_details', {}).get('subdomain_count', 0)
        
        print(f"\n{Colors.success('SECURITYTRAILS TEST ERFOLGREICH:')}")
        print(f"  API Status: {api_status}")
        print(f"  Subdomain Count: {subdomain_count}")
        print(f"  Intelligence Gathered: {'Ja' if results.get('analysis_status') else 'Nein'}")
    
    print(f"\n{Colors.investigation_separator(60)}")
    print(Colors.success("SECURITYTRAILS CLIENT STEP 2.5 - TESTING COMPLETE"))
    print(Colors.investigation_separator(60))

if __name__ == "__main__":
    main()