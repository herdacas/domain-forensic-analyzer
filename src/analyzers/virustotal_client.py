"""
VirusTotal Client for Domain/URL Reputation Analysis.
"""

from typing import Any, Dict

import requests

from ..config.api_config import SecureAPIManager
from ..utils.api_helpers import api_error_response


class VirusTotalClient:
    """VirusTotal API client for domain and IP threat intelligence."""

    def __init__(self):
        self.api_manager = SecureAPIManager()
        self.config = self.api_manager.get_api_config("virustotal")
        self.session = requests.Session()

        if self.config:
            self.session.headers.update({"x-apikey": self.config.api_key})

    def analyze_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """
        Analyze domain reputation using VirusTotal

        Args:
            domain: Domain to analyze

        Returns:
            Structured threat intelligence
        """
        if not self.config:
            return self._get_demo_result(domain)

        try:
            # Domain Analysis Endpoint
            endpoint = f"{self.config.base_url}/domains/{domain}"

            response = self.session.get(endpoint, timeout=30)
            response.raise_for_status()

            data = response.json()["data"]
            attributes = data.get("attributes", {})

            return {
                "analysis_status": "abgeschlossen",
                "domain": domain,
                "reputation": attributes.get("reputation", 0),
                "threat_analysis": self._analyze_threat_statistics(attributes),
                "categories": attributes.get("categories", {}),
                "last_analysis_stats": attributes.get("last_analysis_stats", {}),
                "threat_intelligence": self._calculate_threat_intelligence(attributes),
                "dns_records": self._extract_dns_records(attributes),
                "related_threats": self._extract_related_threats(attributes),
                "api_status": "live_data",
            }

        except Exception as error:
            return api_error_response(error, {"domain": domain})

    def _analyze_threat_statistics(self, attributes: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze threat detection statistics"""
        stats = attributes.get("last_analysis_stats", {})

        total_engines = sum(stats.values()) if stats else 0
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        return {
            "total_security_vendors": total_engines,
            "malicious_detections": malicious,
            "suspicious_detections": suspicious,
            "clean_detections": stats.get("clean", 0),
            "undetected": stats.get("undetected", 0),
            "detection_ratio": (
                f"{malicious + suspicious}/{total_engines}"
                if total_engines > 0
                else "0/0"
            ),
        }

    def _calculate_threat_intelligence(
        self, attributes: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Calculate comprehensive threat intelligence"""
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        reputation = attributes.get("reputation", 0)

        # Threat Classification
        if malicious >= 3:
            threat_level = "HIGH"
            threat_description = (
                f"Domain flagged as malicious by {malicious} security vendors"
            )
        elif malicious > 0:
            threat_level = "MEDIUM"
            threat_description = (
                f"Limited malicious detections ({malicious} vendors) - review required"
            )
        elif suspicious >= 3:
            threat_level = "MEDIUM"
            threat_description = (
                f"Domain flagged as suspicious by {suspicious} security vendors"
            )
        elif reputation < -10:
            threat_level = "MEDIUM"
            threat_description = f"Negative reputation score: {reputation}"
        else:
            threat_level = "CLEAN"
            threat_description = "No significant threats detected"

        return {
            "threat_level": threat_level,
            "threat_description": threat_description,
            "reputation_score": reputation,
            "vendor_consensus": self._calculate_vendor_consensus(stats),
            "threat_categories": list(attributes.get("categories", {}).keys()),
        }

    def _calculate_vendor_consensus(self, stats: Dict[str, int]) -> Dict[str, Any]:
        """Calculate security vendor consensus"""
        total = sum(stats.values()) if stats else 0
        if total == 0:
            return {"consensus": "NO_DATA", "confidence": 0}

        malicious_pct = (stats.get("malicious", 0) / total) * 100
        clean_pct = (stats.get("clean", 0) / total) * 100

        if malicious_pct > 10:
            consensus = "THREAT_DETECTED"
        elif clean_pct > 80:
            consensus = "CLEAN"
        else:
            consensus = "UNCERTAIN"

        return {
            "consensus": consensus,
            "confidence": max(malicious_pct, clean_pct),
            "malicious_percentage": malicious_pct,
            "clean_percentage": clean_pct,
        }

    def _extract_dns_records(self, attributes: Dict[str, Any]) -> Dict[str, Any]:
        """Extract DNS-related intelligence"""
        return {
            "dns_records": attributes.get("dns_records", []),
            "whois_data": attributes.get("whois"),
            "creation_date": attributes.get("creation_date"),
            "last_modification_date": attributes.get("last_modification_date"),
        }

    def _extract_related_threats(self, attributes: Dict[str, Any]) -> Dict[str, Any]:
        """Extract related threat intelligence"""
        return {
            "similar_domains": attributes.get("similar_domains", []),
            "communicating_files": attributes.get("communicating_files", []),
            "referrer_files": attributes.get("referrer_files", []),
        }

    def _get_demo_result(self, domain: str) -> Dict[str, Any]:
        """Demo result for testing without API key"""
        return {
            "analysis_status": "demo_abgeschlossen",
            "domain": domain,
            "reputation": 0,
            "threat_analysis": {
                "total_security_vendors": 89,
                "malicious_detections": 0,
                "suspicious_detections": 0,
                "clean_detections": 85,
                "undetected": 4,
                "detection_ratio": "0/89",
            },
            "categories": {"software development": "good"},
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "clean": 85,
                "undetected": 4,
            },
            "threat_intelligence": {
                "threat_level": "CLEAN",
                "threat_description": "Demo Mode - configure API key for live threat data",
                "reputation_score": 0,
                "vendor_consensus": {"consensus": "CLEAN", "confidence": 95.5},
                "threat_categories": [],
            },
            "dns_records": {},
            "related_threats": {},
            "api_status": "demo_mode",
        }
