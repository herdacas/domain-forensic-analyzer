"""
SecurityTrails Client for Domain Forensic Analyzer.
"""

import sys
import time
from pathlib import Path
from typing import Any, Dict

import requests

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent.parent))
from src.config.api_config import SecureAPIManager
from src.utils.api_helpers import api_error_response


class SecurityTrailsClient:
    """SecurityTrails API client for historical DNS intelligence."""

    def __init__(self):
        self.api_manager = SecureAPIManager()
        self.config = self.api_manager.get_api_config("securitytrails")
        self.session = requests.Session()

        if self.config:
            self.session.headers.update(
                {"APIKEY": self.config.api_key, "Accept": "application/json"}
            )

    def analyze_domain_intelligence(self, domain: str) -> Dict[str, Any]:
        """
        Main SecurityTrails domain intelligence analysis

        Args:
            domain: Domain to analyze

        Returns:
            Structured intelligence data
        """
        if not self.config:
            return self._get_demo_result(domain)

        try:
            domain_info = self._get_domain_info(domain)
            historical_dns = self._get_historical_dns_summary(domain)
            subdomains_data = self._get_subdomains(domain)

            any_succeeded = any(
                d.get("status") == "success"
                for d in (domain_info, historical_dns, subdomains_data)
            )
            quota_exceeded = any(
                d.get("status") == "quota_exceeded"
                for d in (domain_info, historical_dns, subdomains_data)
            )

            if quota_exceeded and not any_succeeded:
                return {
                    "analysis_status": "quota_exceeded",
                    "domain": domain,
                    "api_status": "quota_exceeded",
                    "error": "SecurityTrails API quota exceeded",
                    "domain_details": {"subdomain_count": 0},
                }

            api_status = "live_data" if any_succeeded else "api_error"

            return {
                "analysis_status": "abgeschlossen" if any_succeeded else "failed",
                "domain": domain,
                "api_status": api_status,
                "domain_details": domain_info,
                "historical_dns": historical_dns,
                "subdomain_intelligence": subdomains_data,
                "intelligence_summary": self._create_intelligence_summary(
                    domain_info, historical_dns, subdomains_data
                ),
            }

        except Exception as error:
            return api_error_response(error, {"domain": domain})

    def _get_domain_info(self, domain: str) -> Dict[str, Any]:
        """Get basic domain information"""
        try:
            endpoint = f"{self.config.base_url}/domain/{domain}"
            response = self.session.get(endpoint, timeout=30)
            if response.status_code in (402, 429):
                return {"status": "quota_exceeded"}
            response.raise_for_status()
            data = response.json()
            return {
                "hostname": data.get("hostname", domain),
                "subdomain_count": data.get("subdomain_count", 0),
                "endpoint_count": data.get("endpoint_count", 0),
                "first_seen": data.get("first_seen"),
                "current_dns": data.get("current_dns", {}),
                "status": "success",
            }
        except Exception:
            return {"status": "failed"}

    def _get_historical_dns_summary(self, domain: str) -> Dict[str, Any]:
        """Get historical DNS summary for key record types"""
        historical_data = {"a_records": [], "mx_records": [], "status": "success"}

        try:
            # Get A record history (most important)
            a_endpoint = f"{self.config.base_url}/history/{domain}/dns/a"
            a_response = self.session.get(a_endpoint, timeout=30)

            if a_response.status_code == 429:
                historical_data["status"] = "quota_exceeded"
                return historical_data
            if a_response.status_code == 200:
                a_data = a_response.json()
                records = a_data.get("records", [])[:5]
                for record in records:
                    historical_data["a_records"].append(
                        {
                            "first_seen": record.get("first_seen"),
                            "last_seen": record.get("last_seen"),
                            "ip_addresses": [
                                val.get("ip") for val in record.get("values", [])
                            ],
                            "organizations": record.get("organizations", []),
                        }
                    )

            time.sleep(0.5)

            mx_endpoint = f"{self.config.base_url}/history/{domain}/dns/mx"
            mx_response = self.session.get(mx_endpoint, timeout=30)

            if mx_response.status_code == 429:
                historical_data["status"] = "quota_exceeded"
                return historical_data
            if mx_response.status_code == 200:
                mx_data = mx_response.json()
                mx_records = mx_data.get("records", [])[:3]  # Last 3 changes

                for record in mx_records:
                    historical_data["mx_records"].append(
                        {
                            "first_seen": record.get("first_seen"),
                            "last_seen": record.get("last_seen"),
                            "mail_servers": [
                                val.get("hostname") for val in record.get("values", [])
                            ],
                        }
                    )

        except Exception:
            historical_data["status"] = "failed"

        return historical_data

    def _get_subdomains(self, domain: str) -> Dict[str, Any]:
        """Get subdomain intelligence"""
        try:
            endpoint = f"{self.config.base_url}/domain/{domain}/subdomains"
            response = self.session.get(endpoint, timeout=30)
            if response.status_code in (402, 429):
                return {"status": "quota_exceeded"}
            response.raise_for_status()

            data = response.json()
            subdomains = data.get("subdomains", [])[:50]  # Top 50

            # Categorize subdomains for threat analysis
            categorized = self._categorize_subdomains(subdomains)

            return {
                "total_found": len(data.get("subdomains", [])),
                "top_subdomains": subdomains,
                "categorized_assets": categorized,
                "sensitive_count": len(categorized.get("admin", []))
                + len(categorized.get("api", [])),
                "status": "success",
            }
        except Exception:
            return {"status": "failed"}

    def _categorize_subdomains(self, subdomains: list) -> Dict[str, list]:
        """Categorize subdomains for security analysis"""
        categories = {"admin": [], "api": [], "dev": [], "mail": [], "other": []}

        for subdomain in subdomains:
            sub_lower = subdomain.lower()

            if any(
                pattern in sub_lower
                for pattern in ["admin", "panel", "manage", "control"]
            ):
                categories["admin"].append(subdomain)
            elif any(
                pattern in sub_lower
                for pattern in ["api", "rest", "graphql", "webhook"]
            ):
                categories["api"].append(subdomain)
            elif any(
                pattern in sub_lower for pattern in ["dev", "test", "stage", "debug"]
            ):
                categories["dev"].append(subdomain)
            elif any(
                pattern in sub_lower for pattern in ["mail", "smtp", "imap", "pop"]
            ):
                categories["mail"].append(subdomain)
            else:
                categories["other"].append(subdomain)

        return categories

    def _create_intelligence_summary(
        self, domain_info: Dict, historical: Dict, subdomains: Dict
    ) -> Dict[str, Any]:
        """Create intelligence summary for risk assessment"""
        summary = {
            "total_subdomains": domain_info.get("subdomain_count", 0),
            "historical_changes": len(historical.get("a_records", [])),
            "sensitive_assets": subdomains.get("sensitive_count", 0),
            "risk_indicators": [],
        }

        # Risk indicators
        if summary["sensitive_assets"] > 5:
            summary["risk_indicators"].append("High number of sensitive subdomains")

        if summary["historical_changes"] > 10:
            summary["risk_indicators"].append("Frequent DNS infrastructure changes")

        if len(historical.get("a_records", [])) > 0:
            # Check for suspicious infrastructure patterns
            recent_ips = []
            for record in historical["a_records"][:3]:
                recent_ips.extend(record.get("ip_addresses", []))

            if len(set(recent_ips)) > 5:
                summary["risk_indicators"].append(
                    "Multiple IP address changes detected"
                )

        return summary

    def _get_demo_result(self, domain: str) -> Dict[str, Any]:
        """Demo result for testing without API key"""
        return {
            "analysis_status": "demo_abgeschlossen",
            "domain": domain,
            "api_status": "demo_mode",
            "domain_details": {
                "hostname": domain,
                "subdomain_count": 45,
                "endpoint_count": 12,
                "first_seen": "2020-01-15",
                "status": "demo",
            },
            "historical_dns": {
                "a_records": [
                    {
                        "first_seen": "2022-01-01",
                        "last_seen": "2023-01-01",
                        "ip_addresses": ["192.168.1.100"],
                        "organizations": ["Demo Hosting Inc"],
                    }
                ],
                "mx_records": [],
                "status": "demo",
            },
            "subdomain_intelligence": {
                "total_found": 45,
                "top_subdomains": ["www", "api", "admin", "dev", "mail", "cdn"],
                "categorized_assets": {
                    "admin": ["admin"],
                    "api": ["api"],
                    "dev": ["dev"],
                    "mail": ["mail"],
                    "other": ["www", "cdn"],
                },
                "sensitive_count": 2,
                "status": "demo",
            },
            "intelligence_summary": {
                "total_subdomains": 45,
                "historical_changes": 2,
                "sensitive_assets": 2,
                "risk_indicators": ["Demo Mode - configure API key for real analysis"],
            },
        }
