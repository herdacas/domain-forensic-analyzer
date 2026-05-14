# FILE 3: analyzers/abuseipdb_client.py
"""
AbuseIPDB Client für IP Reputation Analysis
"""
from typing import Any, Dict

import requests

from ..config.api_config import SecureAPIManager


class AbuseIPDBClient:
    """
    Professional AbuseIPDB Integration für IP Reputation Analysis
    """
    
    def __init__(self):
        self.api_manager = SecureAPIManager()
        self.config = self.api_manager.get_api_config('abuseipdb')
        self.session = requests.Session()
        
        if self.config:
            self.session.headers.update({
                'Key': self.config.api_key,
                'Accept': 'application/json'
            })
    
    def analyze_ip_reputation(self, ip_address: str, domain: str) -> Dict[str, Any]:
        """
        Analyze IP reputation using AbuseIPDB
        
        Args:
            ip_address: IP to analyze
            domain: Associated domain for context
            
        Returns:
            Structured reputation analysis
        """
        if not self.config:
            return self._get_demo_result(ip_address, domain)
        
        try:
            # AbuseIPDB Check Endpoint
            endpoint = f"{self.config.base_url}/check"
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': True
            }
            
            response = self.session.get(endpoint, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()['data']
            
            return {
                'analysis_status': 'abgeschlossen',
                'ip_address': ip_address,
                'associated_domain': domain,
                'abuse_confidence': data.get('abuseConfidencePercentage', 0),
                'country_code': data.get('countryCode', 'Unknown'),
                'is_whitelisted': data.get('isWhitelisted', False),
                'usage_type': data.get('usageType', 'Unknown'),
                'recent_reports': len(data.get('reports', [])),
                'last_reported': data.get('reports', [{}])[0].get('reportedAt') if data.get('reports') else None,
                'threat_categories': self._extract_threat_categories(data.get('reports', [])),
                'reputation_intelligence': self._calculate_ip_intelligence(data),
                'api_status': 'live_data'
            }
            
        except Exception as error:
            return {
                'analysis_status': 'failed',
                'error': str(error),
                'ip_address': ip_address,
                'associated_domain': domain,
                'api_status': 'error'
            }
    
    def _extract_threat_categories(self, reports: list) -> Dict[str, int]:
        """Extract and categorize threat patterns"""
        categories = {}
        category_map = {
            3: 'Fraud Orders',
            4: 'DDoS Attack', 
            9: 'Hacking',
            10: 'IoT Targeted',
            11: 'Malware',
            14: 'Port Scan',
            18: 'Brute Force',
            19: 'Badware',
            20: 'Exploit',
            21: 'Web App Attack'
        }
        
        for report in reports[:10]:  # Analyze recent reports
            for cat_id in report.get('categories', []):
                cat_name = category_map.get(cat_id, f'Category_{cat_id}')
                categories[cat_name] = categories.get(cat_name, 0) + 1
        
        return categories
    
    def _calculate_ip_intelligence(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate IP intelligence metrics"""
        confidence = data.get('abuseConfidencePercentage', 0)
        
        # Risk Classification
        if confidence >= 75:
            risk_level = 'CRITICAL'
            risk_description = 'High abuse confidence - immediate investigation required'
        elif confidence >= 50:
            risk_level = 'HIGH' 
            risk_description = 'Moderate abuse confidence - monitoring recommended'
        elif confidence >= 25:
            risk_level = 'MEDIUM'
            risk_description = 'Low abuse confidence - informational'
        else:
            risk_level = 'LOW'
            risk_description = 'Clean IP - no significant abuse reports'
        
        return {
            'risk_level': risk_level,
            'risk_description': risk_description,
            'confidence_score': confidence,
            'geographic_risk': self._assess_geographic_risk(data.get('countryCode')),
            'usage_assessment': data.get('usageType', 'Unknown')
        }
    
    def _assess_geographic_risk(self, country_code: str) -> Dict[str, str]:
        """Assess geographic risk factors"""
        high_risk_countries = ['CN', 'RU', 'KP', 'IR']
        
        if country_code in high_risk_countries:
            return {
                'level': 'HIGH',
                'reason': f'IP from high-risk geographic region: {country_code}'
            }
        elif country_code == 'Unknown':
            return {
                'level': 'MEDIUM', 
                'reason': 'Geographic location unknown'
            }
        else:
            return {
                'level': 'LOW',
                'reason': f'IP from standard geographic region: {country_code}'
            }
    
    def _get_demo_result(self, ip_address: str, domain: str) -> Dict[str, Any]:
        """Demo result for testing without API key"""
        return {
            'analysis_status': 'demo_abgeschlossen',
            'ip_address': ip_address,
            'associated_domain': domain,
            'abuse_confidence': 25,
            'country_code': 'US',
            'is_whitelisted': False,
            'usage_type': 'Data Center',
            'recent_reports': 3,
            'last_reported': '2024-01-15T10:30:00Z',
            'threat_categories': {'Port Scan': 2, 'Brute Force': 1},
            'reputation_intelligence': {
                'risk_level': 'MEDIUM',
                'risk_description': 'Demo Mode - configure API key for live data',
                'confidence_score': 25,
                'geographic_risk': {'level': 'LOW', 'reason': 'Demo data'},
                'usage_assessment': 'Data Center'
            },
            'api_status': 'demo_mode'
        }