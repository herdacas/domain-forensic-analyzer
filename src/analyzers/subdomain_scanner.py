"""
Subdomain Scanner Module for Domain Forensic Analyzer.
"""

import os
import random
import socket
import string
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Optional

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from config.settings import get_settings
from src.utils.validators import DomainValidator


class SubdomainScanner:
    """DNS-based subdomain discovery with per-category asset classification."""

    def __init__(self):
        self.results = {}
        self.domain = None
        self.settings = get_settings()
        self.subdomain_timeout = self.settings.scan_settings.subdomain_timeout
        self.max_threads = self.settings.scan_settings.max_subdomain_threads

        self.basic_subdomains = [
            'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'imap',
            'ns1', 'ns2', 'ns3', 'mx', 'email',
        ]

        self.admin_subdomains = [
            'admin', 'administrator', 'panel', 'control', 'manage', 'manager',
            'cpanel', 'plesk', 'webmin', 'backend', 'dashboard', 'console',
        ]

        self.api_subdomains = [
            'api', 'rest', 'graphql', 'webhook', 'callback', 'gateway',
            'service', 'ws', 'rpc', 'soap', 'json', 'xml',
        ]

        self.dev_subdomains = [
            'dev', 'development', 'test', 'testing', 'staging', 'stage',
            'beta', 'alpha', 'demo', 'sandbox', 'lab', 'preview',
        ]

        self.service_subdomains = [
            'auth', 'login', 'sso', 'oauth', 'accounts', 'profile', 'user',
            'users', 'account', 'session', 'portal', 'access',
        ]

        self.commerce_subdomains = [
            'shop', 'store', 'cart', 'checkout', 'payment', 'billing',
            'order', 'orders', 'purchase', 'buy', 'sell', 'ecommerce',
        ]

        self.content_subdomains = [
            'blog', 'news', 'forum', 'wiki', 'docs', 'documentation',
            'support', 'help', 'faq', 'kb', 'knowledgebase', 'community',
        ]

        self.infrastructure_subdomains = [
            'cdn', 'cache', 'static', 'assets', 'media', 'images',
            'files', 'download', 'uploads', 'storage', 'backup',
        ]

        self.all_subdomains = (
            self.basic_subdomains + self.admin_subdomains + self.api_subdomains +
            self.dev_subdomains + self.service_subdomains + self.commerce_subdomains +
            self.content_subdomains + self.infrastructure_subdomains
        )

        self.sensitive_subdomains = self.admin_subdomains + self.api_subdomains + self.dev_subdomains

    def scan_subdomains(self, domain: str) -> Dict[str, Any]:
        """Run subdomain discovery and return structured result dict."""
        if not DomainValidator.is_valid_domain(domain):
            return {'error': f'Invalid domain: {domain}', 'analysis_status': 'fehlgeschlagen'}

        clean_domain = DomainValidator.clean_domain(domain)
        self.domain = clean_domain

        results = {
            'domain': clean_domain,
            'timestamp': datetime.now().isoformat(),
            'wildcard_detected': False,
            'total_subdomains_tested': 0,
            'discovered_assets': [],
            'categorized_assets': {
                'admin': [], 'api': [], 'dev': [], 'service': [],
                'commerce': [], 'content': [], 'infrastructure': [], 'basic': [],
            },
            'sensitive_assets': [],
            'analysis_status': 'gestartet',
        }

        wildcard_detected = self._detect_wildcard(clean_domain)
        results['wildcard_detected'] = wildcard_detected

        if wildcard_detected:
            subdomains_to_test = self.basic_subdomains + self.admin_subdomains + self.api_subdomains
        else:
            subdomains_to_test = self.all_subdomains

        discovered_assets = self._enumerate_subdomains(clean_domain, subdomains_to_test)
        results['discovered_assets'] = discovered_assets
        results['total_subdomains_tested'] = len(subdomains_to_test)

        results['categorized_assets'] = self._categorize_assets(discovered_assets)
        results['sensitive_assets'] = self._analyze_sensitive_assets(discovered_assets)

        results['analysis_status'] = 'abgeschlossen'
        self.results = results
        return results

    def _detect_wildcard(self, domain: str) -> bool:
        """Detect catch-all / wildcard DNS by resolving random subdomains.

        IP uniformity is NOT required — load-balanced pools return different IPs
        per query but still resolve every subdomain.
        """
        test_subdomains = [
            f"{''.join(random.choices(string.ascii_lowercase, k=8))}.{domain}"
            for _ in range(3)
        ]

        resolved_ips = []
        for test_subdomain in test_subdomains:
            old_timeout = socket.getdefaulttimeout()
            try:
                socket.setdefaulttimeout(3)
                ip = socket.gethostbyname(test_subdomain)
                resolved_ips.append(ip)
            except Exception:
                resolved_ips.append(None)
            finally:
                socket.setdefaulttimeout(old_timeout)

        valid_ips = [ip for ip in resolved_ips if ip is not None]
        return len(valid_ips) >= 2

    def _enumerate_subdomains(self, domain: str, subdomains_to_test: List[str]) -> List[Dict[str, Any]]:
        """Resolve subdomains in parallel threads, return active ones."""
        discovered_assets = []

        def check_subdomain(subdomain: str) -> Optional[Dict[str, Any]]:
            full_domain = f"{subdomain}.{domain}"
            old_timeout = socket.getdefaulttimeout()
            try:
                socket.setdefaulttimeout(self.subdomain_timeout)
                ip_address = socket.gethostbyname(full_domain)
                return {
                    'subdomain': subdomain,
                    'full_domain': full_domain,
                    'ip_address': ip_address,
                    'status': 'active',
                }
            except Exception:
                return None
            finally:
                socket.setdefaulttimeout(old_timeout)

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(check_subdomain, s): s for s in subdomains_to_test}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    discovered_assets.append(result)

        return discovered_assets

    def _categorize_assets(self, discovered_assets: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group discovered assets by functional category."""
        categorized: Dict[str, List] = {
            'admin': [], 'api': [], 'dev': [], 'service': [],
            'commerce': [], 'content': [], 'infrastructure': [], 'basic': [],
        }

        for asset in discovered_assets:
            subdomain = asset['subdomain'].lower()
            if subdomain in self.admin_subdomains:
                categorized['admin'].append(asset)
            elif subdomain in self.api_subdomains:
                categorized['api'].append(asset)
            elif subdomain in self.dev_subdomains:
                categorized['dev'].append(asset)
            elif subdomain in self.service_subdomains:
                categorized['service'].append(asset)
            elif subdomain in self.commerce_subdomains:
                categorized['commerce'].append(asset)
            elif subdomain in self.content_subdomains:
                categorized['content'].append(asset)
            elif subdomain in self.infrastructure_subdomains:
                categorized['infrastructure'].append(asset)
            else:
                categorized['basic'].append(asset)

        return categorized

    def _analyze_sensitive_assets(self, discovered_assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify and risk-classify sensitive (admin/API/dev/service) assets."""
        sensitive_assets = []

        for asset in discovered_assets:
            subdomain = asset['subdomain'].lower()
            if subdomain in self.admin_subdomains:
                risk_level, risk_reason = 'critical', 'Administrative Interface'
            elif subdomain in self.api_subdomains:
                risk_level, risk_reason = 'high', 'API Endpoint'
            elif subdomain in self.dev_subdomains:
                risk_level, risk_reason = 'high', 'Development Environment'
            elif subdomain in self.service_subdomains:
                risk_level, risk_reason = 'medium', 'Service Interface'
            else:
                continue

            sensitive_assets.append({
                'asset': asset,
                'risk_level': risk_level,
                'risk_reason': risk_reason,
                'recommendations': self._get_risk_recommendations(risk_level, subdomain),
            })

        risk_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        sensitive_assets.sort(key=lambda x: risk_order.get(x['risk_level'], 4))
        return sensitive_assets

    def _get_risk_recommendations(self, risk_level: str, _subdomain: str) -> List[str]:
        """Return security recommendations for a given risk level."""
        if risk_level == 'critical':
            return [
                'Implement strong authentication (MFA)',
                'Restrict access by IP whitelist',
                'Use VPN-only access',
                'Regular security audits',
            ]
        if risk_level == 'high':
            return [
                'API authentication required',
                'Rate limiting implementation',
                'Access logging enabled',
                'Regular vulnerability scans',
            ]
        if risk_level == 'medium':
            return [
                'Basic authentication required',
                'Monitor access patterns',
                'Regular updates',
            ]
        return []

    def get_results(self) -> Dict[str, Any]:
        """Return last scan results."""
        return self.results

    def get_sensitive_assets(self) -> List[Dict[str, Any]]:
        """Return only sensitive assets from last scan."""
        return self.results.get('sensitive_assets', [])
