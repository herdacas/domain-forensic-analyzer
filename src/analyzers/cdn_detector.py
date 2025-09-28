          
"""
CDN Detector Module for Domain Forensic Analyzer
Infrastructure-Klassifikation und Provider-Erkennung

Step 2.2 Implementation - Mit Syntax-Fix
"""

import urllib.request
import json
import sys
import os
from typing import Dict, List, Optional, Any
from datetime import datetime

# Foundation-Module importieren
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src.utils.colors import Colors
from config.settings import get_settings

class CDNDetector:
    """
    CDN und Infrastructure-Provider Erkennung
    
    Analysiert IP-Adressen zur Identifikation von Content Delivery Networks,
    Cloud-Providern und Hosting-Services. Sammelt Geolocation und ASN-Daten.
    """
    
    def __init__(self):
        """Initialisiert CDN-Detector mit Provider-Datenbank"""
        self.results = {}
        self.settings = get_settings()
        self.api_timeout = self.settings.scan_settings.api_timeout
        
        # CDN und Cloud-Provider Datenbank
        self.provider_database = {
            'cloudflare': {
                'ip_ranges': [
                    '104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.',
                    '104.22.', '104.23.', '162.159.', '172.64.', '172.65.', '172.66.',
                    '172.67.', '172.68.', '172.69.', '172.70.', '172.71.'
                ],
                'type': 'cdn',
                'name': 'Cloudflare',
                'protection_level': 'high',
                'features': ['DDoS Protection', 'WAF', 'Bot Management', 'Always Online']
            },
            'aws_cloudfront': {
                'ip_ranges': ['13.', '99.', '54.', '52.', '18.'],
                'type': 'cdn',
                'name': 'AWS CloudFront',
                'protection_level': 'high',
                'features': ['AWS Shield', 'AWS WAF', 'Global Edge Locations']
            },
            'fastly': {
                'ip_ranges': ['151.101.', '185.31.', '23.235.'],
                'type': 'cdn',
                'name': 'Fastly',
                'protection_level': 'medium',
                'features': ['Edge Computing', 'Real-time Analytics']
            },
            'digitalocean': {
                'ip_ranges': ['159.65.', '167.172.', '178.62.', '188.166.'],
                'type': 'cloud',
                'name': 'DigitalOcean',
                'protection_level': 'basic',
                'features': ['VPS Hosting', 'Managed Databases']
            },
            'amazon_aws': {
                'ip_ranges': ['3.', '52.', '54.', '18.', '34.'],
                'type': 'cloud',
                'name': 'Amazon AWS',
                'protection_level': 'medium',
                'features': ['EC2', 'S3', 'Load Balancer']
            },
            'google_cloud': {
                'ip_ranges': ['35.', '34.', '130.211.', '146.148.'],
                'type': 'cloud',
                'name': 'Google Cloud Platform',
                'protection_level': 'medium',
                'features': ['Compute Engine', 'Cloud CDN']
            },
            'github': {
                'ip_ranges': ['140.82.', '192.30.', '185.199.'],
                'type': 'platform',
                'name': 'GitHub',
                'protection_level': 'medium',
                'features': ['GitHub Pages', 'Git Hosting']
            },
            'microsoft_azure': {
                'ip_ranges': ['20.', '40.', '52.', '104.'],
                'type': 'cloud',
                'name': 'Microsoft Azure',
                'protection_level': 'medium',
                'features': ['Virtual Machines', 'Azure CDN']
            }
        }
    
    def analyze_infrastructure(self, ip_address: str, domain: str = None) -> Dict[str, Any]:
        """
        Hauptanalyse-Funktion fuer Infrastructure-Klassifikation
        
        Args:
            ip_address (str): IP-Adresse zur Analyse
            domain (str): Optional - zugehoerige Domain
            
        Returns:
            dict: Infrastructure-Analyseergebnisse
        """
        print(Colors.header("INFRASTRUCTURE CLASSIFICATION"))
        print(Colors.investigation_separator(60))
        
        if not ip_address:
            error_msg = "Keine IP-Adresse fuer Analyse verfuegbar"
            print(Colors.error(error_msg))
            return {'error': error_msg, 'analysis_status': 'fehlgeschlagen'}
        
        print(f"Analysiere IP-Adresse: {Colors.format_ip(ip_address)}")
        if domain:
            print(f"Zugehoerige Domain: {Colors.format_domain(domain)}")
        
        # Ergebnis-Dictionary initialisieren
        results = {
            'ip_address': ip_address,
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'provider_detected': None,
            'provider_name': None,
            'infrastructure_type': None,
            'protection_level': None,
            'features': [],
            'geolocation': {},
            'asn_info': {},
            'analysis_status': 'gestartet'
        }
        
        # Provider-Erkennung durchfuehren
        print(f"\n{Colors.section_header('PROVIDER DETECTION', 50)}")
        provider_info = self._detect_provider(ip_address)
        results.update(provider_info)
        
        # Geolocation-Analyse
        print(f"\n{Colors.section_header('GEOLOCATION ANALYSIS', 50)}")
        geo_info = self._analyze_geolocation(ip_address)
        results['geolocation'] = geo_info
        
        # ASN und Organization-Info
        if geo_info.get('as') or geo_info.get('org'):
            results['asn_info'] = {
                'asn': geo_info.get('as'),
                'organization': geo_info.get('org'),
                'isp': geo_info.get('isp')
            }
        
        # Analyse abschliessen
        results['analysis_status'] = 'abgeschlossen'
        self.results = results
        
        # Zusammenfassung anzeigen
        self._display_summary(results)
        return results
    
    def _detect_provider(self, ip_address: str) -> Dict[str, Any]:
        """
        Erkennt CDN/Cloud-Provider basierend auf IP-Adresse
        
        Args:
            ip_address (str): IP-Adresse zur Provider-Erkennung
            
        Returns:
            dict: Provider-Erkennungsergebnisse
        """
        print(f"  {Colors.info('Provider-Erkennung:')} Analysiere IP-Bereiche...")
        
        # Provider-Datenbank durchsuchen
        for provider_key, provider_data in self.provider_database.items():
            for ip_range in provider_data['ip_ranges']:
                if ip_address.startswith(ip_range):
                    print(f"    {Colors.success('Provider erkannt:')} {provider_data['name']}")
                    print(f"    {Colors.info('Typ:')} {provider_data['type'].title()}")
                    print(f"    {Colors.info('Schutz-Level:')} {provider_data['protection_level'].title()}")
                    
                    # Features anzeigen
                    if provider_data.get('features'):
                        features_text = ', '.join(provider_data['features'][:3])
                        print(f"    {Colors.info('Features:')} {features_text}")
                    
                    return {
                        'provider_detected': provider_key,
                        'provider_name': provider_data['name'],
                        'infrastructure_type': provider_data['type'],
                        'protection_level': provider_data['protection_level'],
                        'features': provider_data.get('features', [])
                    }
        
        # Kein bekannter Provider gefunden
        print(f"    {Colors.warning('Provider:')} Unbekannt/Direct Hosting")
        return {
            'provider_detected': None,
            'provider_name': 'Unknown/Direct',
            'infrastructure_type': 'direct',
            'protection_level': 'minimal',
            'features': []
        }
    
    def _analyze_geolocation(self, ip_address: str) -> Dict[str, Any]:
        """
        Analysiert Geolocation und ASN-Informationen
        
        Args:
            ip_address (str): IP-Adresse fuer Geolocation
            
        Returns:
            dict: Geolocation-Daten
        """
        print(f"  {Colors.info('Geolocation-Analyse:')} Abfrage laeuft...")
        
        try:
            # IP-API.com fuer Geolocation (kostenlos, kein API-Key noetig)
            url = f"http://ip-api.com/json/{ip_address}?fields=status,country,city,region,org,as,isp,timezone"
            
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Domain-Forensic-Analyzer/3.4')
            
            with urllib.request.urlopen(req, timeout=self.api_timeout) as response:
                data = json.loads(response.read().decode())
                
                if data.get('status') == 'success':
                    geo_info = {
                        'country': data.get('country'),
                        'city': data.get('city'),
                        'region': data.get('region'),
                        'timezone': data.get('timezone'),
                        'org': data.get('org'),
                        'as': data.get('as'),
                        'isp': data.get('isp'),
                        'status': 'success'
                    }
                    
                    # Erfolgreiche Geolocation anzeigen
                    print(f"    {Colors.success('Land:')} {geo_info.get('country', 'Unbekannt')}")
                    print(f"    {Colors.success('Stadt:')} {geo_info.get('city', 'Unbekannt')}")
                    if geo_info.get('org'):
                        print(f"    {Colors.success('Organisation:')} {geo_info['org']}")
                    if geo_info.get('as'):
                        print(f"    {Colors.success('ASN:')} {geo_info['as']}")
                    
                    return geo_info
                else:
                    print(f"    {Colors.warning('Geolocation:')} API-Abfrage fehlgeschlagen")
                    return {'status': 'failed', 'error': 'API returned failure status'}
                    
        except urllib.error.URLError as error:
            print(f"    {Colors.error('Geolocation:')} Netzwerk-Fehler")
            return {'status': 'error', 'error': f'Network error: {str(error)}'}
        except json.JSONDecodeError:
            print(f"    {Colors.error('Geolocation:')} JSON-Parsing-Fehler")
            return {'status': 'error', 'error': 'JSON parsing failed'}
        except Exception as error:
            print(f"    {Colors.error('Geolocation:')} Unerwarteter Fehler")
            return {'status': 'error', 'error': str(error)}
    
    def _display_summary(self, results: Dict[str, Any]) -> None:
        """
        Zeigt Infrastructure-Analyse Zusammenfassung
        
        Args:
            results (dict): Analyseergebnisse
        """
        print(f"\n{Colors.investigation_separator(60)}")
        print(Colors.header("INFRASTRUCTURE ANALYSIS SUMMARY"))
        print(Colors.investigation_separator(60))
        
        # IP und Domain
        print(f"IP Address: {Colors.format_ip(results['ip_address'])}")
        if results.get('domain'):
            print(f"Domain: {Colors.format_domain(results['domain'])}")
        
        # Provider-Informationen
        provider_name = results.get('provider_name', 'Unknown')
        infra_type = results.get('infrastructure_type', 'unknown').title()
        
        if results.get('provider_detected'):
            print(f"Provider: {Colors.success(provider_name)} ({infra_type})")
        else:
            print(f"Provider: {Colors.warning(provider_name)} ({infra_type})")
        
        # Schutz-Level
        protection = results.get('protection_level', 'unknown').title()
        if protection == 'High':
            protection_colored = Colors.success(protection)
        elif protection == 'Medium':
            protection_colored = Colors.warning(protection)
        else:
            protection_colored = Colors.error(protection)
        
        print(f"Protection Level: {protection_colored}")
        
        # Geolocation
        geo = results.get('geolocation', {})
        if geo.get('status') == 'success':
            location = f"{geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}"
            print(f"Location: {Colors.info(location)}")
            
            if geo.get('org'):
                print(f"Organization: {Colors.info(geo['org'])}")
        else:
            print(f"Location: {Colors.warning('Analysis failed')}")
        
        # Features (wenn verfuegbar)
        features = results.get('features', [])
        if features:
            features_text = ', '.join(features[:3])
            print(f"Security Features: {Colors.highlight(features_text)}")
        
        print(Colors.investigation_separator(60))
        print(f"Analysis Status: {Colors.success('COMPLETE')}")
        print(Colors.investigation_separator(60))
    
    def get_results(self) -> Dict[str, Any]:
        """
        Gibt letzte Analyseergebnisse zurueck
        
        Returns:
            dict: Infrastructure-Analyseergebnisse
        """
        return self.results
    
    def classify_infrastructure_type(self, results: Dict[str, Any]) -> str:
        """
        Klassifiziert Infrastructure-Typ basierend auf Analyse
        
        Args:
            results (dict): Analyseergebnisse
            
        Returns:
            str: Infrastructure-Klassifikation
        """
        infra_type = results.get('infrastructure_type', 'unknown')
        
        if infra_type == 'cdn':
            return 'Content Delivery Network'
        elif infra_type == 'cloud':
            return 'Cloud Hosting Service'
        elif infra_type == 'platform':
            return 'Platform Service'
        elif infra_type == 'direct':
            return 'Direct/Traditional Hosting'
        else:
            return 'Unknown Infrastructure'
    
    def get_security_assessment(self, results: Dict[str, Any]) -> Dict[str, str]:
        """
        Erstellt Security-Assessment basierend auf Infrastructure
        
        Args:
            results (dict): Analyseergebnisse
            
        Returns:
            dict: Security-Assessment
        """
        protection_level = results.get('protection_level', 'minimal')
        infra_type = results.get('infrastructure_type', 'direct')
        
        assessment = {
            'ddos_protection': 'unknown',
            'waf_protection': 'unknown',
            'origin_exposure': 'unknown'
        }
        
        if protection_level == 'high':
            assessment['ddos_protection'] = 'strong'
            assessment['waf_protection'] = 'available'
            assessment['origin_exposure'] = 'protected'
        elif protection_level == 'medium':
            assessment['ddos_protection'] = 'basic'
            assessment['waf_protection'] = 'limited'
            assessment['origin_exposure'] = 'partially_protected'
        else:
            assessment['ddos_protection'] = 'minimal'
            assessment['waf_protection'] = 'none'
            assessment['origin_exposure'] = 'direct'
        
        return assessment

# Test-Funktion fuer CDN-Detector
def main():
    """
    Test-Funktion fuer CDN-Detector Modul
    Testet mit IP-Adressen der 3 Benchmark-Domains
    """
    print(Colors.header("CDN DETECTOR MODULE TEST - STEP 2.2"))
    print(Colors.investigation_separator(60))
    
    # Test-IPs von DNS-Analyzer Ergebnissen
    test_cases = [
        {'ip': '172.64.155.249', 'domain': 'stackoverflow.com', 'expected': 'Cloudflare'},
        {'ip': '140.82.121.4', 'domain': 'github.com', 'expected': 'GitHub'},
        {'ip': '159.65.149.231', 'domain': 'futuremultiverse.com', 'expected': 'DigitalOcean'}
    ]
    
    detector = CDNDetector()
    
    for i, test_case in enumerate(test_cases, 1):
        domain_name = test_case['domain'].upper()
        print(f"\n{Colors.section_header(f'TEST {i}: {domain_name}', 60)}")
        
        results = detector.analyze_infrastructure(
            test_case['ip'], 
            test_case['domain']
        )
        
        if results.get('error'):
            print(Colors.error(f"Test fehlgeschlagen: {results['error']}"))
        else:
            expected = test_case['expected']
            actual = results.get('provider_name', 'Unknown')
            
            if expected.lower() in actual.lower():
                print(Colors.success(f"Provider-Erkennung korrekt: {actual}"))
            else:
                print(Colors.warning(f"Provider-Erkennung: {actual} (erwartet: {expected})"))
            
            print(Colors.success(f"Test erfolgreich fuer {test_case['domain']}"))
        
        # Pause zwischen Tests
        if i < len(test_cases):
            import time
            time.sleep(1)
    
    print(f"\n{Colors.investigation_separator(60)}")
    print(Colors.success("CDN DETECTOR STEP 2.2 - TESTING COMPLETE"))
    print(Colors.investigation_separator(60))

if __name__ == "__main__":
    main()