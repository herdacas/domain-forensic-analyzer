          
"""
CDN Detector Module for Domain Forensic Analyzer
Infrastructure-Klassifikation und Provider-Erkennung

Step 2.2 Implementation - Mit Syntax-Fix
"""

import json
import os
import sys
import urllib.request
from datetime import datetime
from typing import Any, Dict

# Foundation-Module importieren
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from config.settings import get_settings
from src.utils.colors import Colors


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
                    '104.22.', '104.23.', '104.24.', '104.25.', '104.26.', '104.27.',
                    '162.159.', '172.64.', '172.65.', '172.66.',
                    '172.67.', '172.68.', '172.69.', '172.70.', '172.71.'
                ],
                'hostname_patterns': ['cloudflare.com', 'cloudflare.net', '.cf.'],
                'type': 'cdn',
                'name': 'Cloudflare',
                'protection_level': 'high',
                'features': ['DDoS Protection', 'WAF', 'Bot Management', 'Always Online']
            },
            'aws_cloudfront': {
                'ip_ranges': ['13.', '99.', '54.', '52.', '18.'],
                'hostname_patterns': ['cloudfront.net', 'amazonaws.com', 'awsdns'],
                'type': 'cdn',
                'name': 'AWS CloudFront',
                'protection_level': 'high',
                'features': ['AWS Shield', 'AWS WAF', 'Global Edge Locations']
            },
            'fastly': {
                'ip_ranges': ['151.101.', '185.31.', '23.235.'],
                'hostname_patterns': ['fastly.net', 'fastlylb.net'],
                'type': 'cdn',
                'name': 'Fastly',
                'protection_level': 'medium',
                'features': ['Edge Computing', 'Real-time Analytics']
            },
            'digitalocean': {
                'ip_ranges': ['159.65.', '167.172.', '178.62.', '188.166.'],
                'hostname_patterns': ['digitalocean.com', 'digitaloceanspaces.com'],
                'type': 'cloud',
                'name': 'DigitalOcean',
                'protection_level': 'basic',
                'features': ['VPS Hosting', 'Managed Databases']
            },
            'amazon_aws': {
                'ip_ranges': ['3.', '52.', '54.', '18.', '34.'],
                'hostname_patterns': ['amazonaws.com', 'aws.amazon.com', 'compute.internal'],
                'type': 'cloud',
                'name': 'Amazon AWS',
                'protection_level': 'medium',
                'features': ['EC2', 'S3', 'Load Balancer']
            },
            'google_cloud': {
                'ip_ranges': ['35.', '34.', '130.211.', '146.148.'],
                'hostname_patterns': ['googleusercontent.com', 'googleapis.com', '.google.com'],
                'type': 'cloud',
                'name': 'Google Cloud Platform',
                'protection_level': 'medium',
                'features': ['Compute Engine', 'Cloud CDN']
            },
            'github': {
                'ip_ranges': ['140.82.', '192.30.', '185.199.'],
                'hostname_patterns': ['github.com', 'github.io', 'githubusercontent.com'],
                'type': 'platform',
                'name': 'GitHub',
                'protection_level': 'medium',
                'features': ['GitHub Pages', 'Git Hosting']
            },
            'microsoft_azure': {
                'ip_ranges': ['20.', '40.', '52.', '104.'],
                'hostname_patterns': ['azure.com', 'azurewebsites.net', 'cloudapp.net', 'windows.net'],
                'type': 'cloud',
                'name': 'Microsoft Azure',
                'protection_level': 'medium',
                'features': ['Virtual Machines', 'Azure CDN']
            },
            'outscale': {
                'ip_ranges': ['80.247.', '213.32.', '46.231.128.'],
                'hostname_patterns': ['outscale.com', 'outscale.net', 'cloudgouv'],
                'type': 'gov-cloud',
                'name': 'Outscale (French Government Cloud)',
                'protection_level': 'basic',
                'features': ['SecNumCloud Certified', 'French Sovereign Cloud', 'EU Data Residency']
            },
            'ovhcloud': {
                'ip_ranges': [
                    '51.38.', '51.75.', '51.89.', '51.91.', '51.195.',
                    '87.98.', '91.121.', '145.239.', '5.135.', '149.202.', '5.196.', '54.36.'
                ],
                'hostname_patterns': ['ovh.net', 'ovhcloud.com', 'ovh.com', 'ovhcloud.net'],
                'type': 'cloud',
                'name': 'OVHcloud',
                'protection_level': 'basic',
                'features': ['Dedicated Servers', 'VPS', 'Managed Cloud', 'EU Data Centers']
            },
            'hetzner': {
                'ip_ranges': [
                    '78.46.', '88.198.', '95.216.', '116.203.', '136.243.',
                    '138.201.', '144.76.', '148.251.', '157.90.', '168.119.', '5.9.'
                ],
                'hostname_patterns': ['hetzner.com', 'your-server.de', 'hetzner.de', 'hetzner-cloud.net'],
                'type': 'hosting',
                'name': 'Hetzner',
                'protection_level': 'basic',
                'features': ['Dedicated Servers', 'VPS', 'Cloud Servers', 'Storage Boxes']
            },
            'ionos': {
                'ip_ranges': ['82.165.', '217.160.', '74.208.', '212.227.', '217.72.'],
                'hostname_patterns': ['ionos.com', '1und1.de', 'ionos.de', 'ui-r.com', '1and1.com'],
                'type': 'hosting',
                'name': 'IONOS / 1&1',
                'protection_level': 'basic',
                'features': ['Web Hosting', 'VPS', 'Dedicated Servers', 'Managed WordPress']
            },
            'telekom_dtag': {
                'ip_ranges': ['80.237.', '194.25.', '217.0.', '62.23.', '80.156.'],
                'hostname_patterns': ['t-online.de', 'telekom.de', 'dtag.de', 't-ipnet.de'],
                'type': 'transit',
                'name': 'Deutsche Telekom (DTAG)',
                'protection_level': 'minimal',
                'features': ['Residential / Business ISP', 'Transit Network', 'DE-CIX Peering']
            },
            'bundescloud': {
                'ip_ranges': [],
                'hostname_patterns': ['bund.de', 'bwi.de', 'bundescloud.de'],
                'type': 'gov-cloud',
                'name': 'Bundescloud / BWI',
                'protection_level': 'basic',
                'features': ['German Federal Government Cloud', 'BSI Classified Infrastructure']
            },
        }
    
    def analyze_infrastructure(self, ip_address: str, domain: str = None, rdns_hostname: str = None) -> Dict[str, Any]:
        """
        Hauptanalyse-Funktion fuer Infrastructure-Klassifikation.
        rdns_hostname: optional reverse-DNS hostname (enables hostname-pattern detection).
        """
        if not ip_address:
            error_msg = "Keine IP-Adresse fuer Analyse verfuegbar"
            return {'error': error_msg, 'analysis_status': 'fehlgeschlagen'}

        results = {
            'ip_address': ip_address,
            'domain': domain,
            'rdns_hostname': rdns_hostname,
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

        provider_info = self._detect_provider(ip_address, rdns_hostname)
        results.update(provider_info)

        geo_info = self._analyze_geolocation(ip_address)
        results['geolocation'] = geo_info

        if geo_info.get('as') or geo_info.get('org'):
            results['asn_info'] = {
                'asn': geo_info.get('as'),
                'organization': geo_info.get('org'),
                'isp': geo_info.get('isp')
            }

        results['analysis_status'] = 'abgeschlossen'
        self.results = results
        return results
    
    def _detect_provider(self, ip_address: str, rdns_hostname: str = None) -> Dict[str, Any]:
        """
        Erkennt CDN/Cloud-Provider basierend auf Hostname-Pattern (Pass 1) und IP-Prefix (Pass 2).
        Hostname-Patterns werden bevorzugt, da sie spezifischer sind (z.B. Outscale via rDNS).
        """
        def _make_match(provider_key, provider_data):
            return {
                'provider_detected': provider_key,
                'provider_name': provider_data['name'],
                'infrastructure_type': provider_data['type'],
                'protection_level': provider_data['protection_level'],
                'features': provider_data.get('features', [])
            }

        # Pass 1: hostname pattern matching (higher specificity)
        if rdns_hostname:
            rdns_lower = rdns_hostname.lower()
            for provider_key, provider_data in self.provider_database.items():
                for pattern in provider_data.get('hostname_patterns', []):
                    if pattern in rdns_lower:
                        return _make_match(provider_key, provider_data)

        # Pass 2: IP prefix matching
        for provider_key, provider_data in self.provider_database.items():
            for ip_range in provider_data['ip_ranges']:
                if ip_address.startswith(ip_range):
                    return _make_match(provider_key, provider_data)

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
        try:
            url = f"http://ip-api.com/json/{ip_address}?fields=status,country,countryCode,city,region,org,as,isp,timezone"

            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Domain-Forensic-Analyzer/3.4')

            with urllib.request.urlopen(req, timeout=self.api_timeout) as response:
                data = json.loads(response.read().decode())

                if data.get('status') == 'success':
                    return {
                        'country': data.get('country'),
                        'countryCode': data.get('countryCode'),
                        'city': data.get('city'),
                        'region': data.get('region'),
                        'timezone': data.get('timezone'),
                        'org': data.get('org'),
                        'as': data.get('as'),
                        'isp': data.get('isp'),
                        'status': 'success'
                    }
                else:
                    return {'status': 'failed', 'error': 'API returned failure status'}

        except urllib.error.URLError as error:
            return {'status': 'error', 'error': f'Network error: {str(error)}'}
        except json.JSONDecodeError:
            return {'status': 'error', 'error': 'JSON parsing failed'}
        except Exception as error:
            return {'status': 'error', 'error': str(error)}
    
    def get_results(self) -> Dict[str, Any]:
        """
        Gibt letzte Analyseergebnisse zurueck
        
        Returns:
            dict: Infrastructure-Analyseergebnisse
        """
        return self.results
    

# Test-Funktion fuer CDN-Detector
