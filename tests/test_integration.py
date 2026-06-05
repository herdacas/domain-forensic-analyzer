"""Integration tests for DomainAnalyzer with mocked network calls."""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime


MOCK_DNS_RESULT = {
    "analysis_status": "abgeschlossen",
    "ipv4": "93.184.216.34",
    "ipv6": None,
    "nameservers": ["a.iana-servers.net", "b.iana-servers.net"],
    "mail_servers": [],
    "txt_records": ["v=spf1 -all"],
    "spf_record": "v=spf1 -all",
    "dmarc_record": "v=DMARC1; p=reject;",
    "dnssec_enabled": True,
    "reverse_dns": None,
}

MOCK_WHOIS_RESULT = {
    "analysis_status": "abgeschlossen",
    "domain": "example.com",
    "registrar": "IANA",
    "creation_date": "1995-08-14",
    "expiration_date": "2026-08-13",
    "updated_date": "2023-08-14",
    "registrant_country": "US",
    "source": "python-whois (lokal)",
    "privacy_proxy": None,
}

MOCK_CDN_RESULT = {
    "analysis_status": "abgeschlossen",
    "provider_detected": None,
    "provider_name": "Unknown/Direct",
    "infrastructure_type": "direct",
    "protection_level": "minimal",
    "geolocation": {"countryCode": "US", "country": "United States", "city": "Norristown", "regionName": "PA"},
    "asn_info": {"asn": "AS15133", "organization": "Edgecast Inc.", "isp": "Edgecast Inc."},
}

MOCK_SSL_RESULT = {
    "analysis_status": "abgeschlossen",
    "domain": "example.com",
    "available": True,
    "verified": True,
    "self_signed": False,
    "issuer_org": "DigiCert Inc",
    "issuer_cn": "DigiCert TLS RSA SHA256 2020 CA1",
    "valid_from": "2023-01-15",
    "valid_until": "2024-02-15",
    "days_to_expiry": 300,
    "sans": ["example.com", "www.example.com"],
    "has_wildcard": False,
    "cert_type": "Multi-SAN",
    "tls_version": "TLSv1.3",
    "assessment": "Valid - modern TLS",
}

MOCK_NETWORK_RESULT = {
    "analysis_status": "abgeschlossen",
    "connectivity_test": {"status": "reachable", "latency_ms": 20},
    "traceroute_data": {"status": "success", "total_hops": 8, "hops": []},
    "http_behavior": {
        "http_status": "301",
        "https_status": "200 OK",
        "redirect_chain": ["http://example.com -> https://example.com"],
        "hsts": "max-age=31536000",
        "server": "nginx",
        "csp": None,
        "x_frame_options": "DENY",
        "assessment": "Strong",
    },
}

MOCK_SUBDOMAIN_RESULT = {
    "analysis_status": "abgeschlossen",
    "discovered_assets": [
        {"subdomain": "www.example.com", "ip": "93.184.216.34", "risk_level": "low"}
    ],
    "total_found": 1,
    "wildcard_detected": False,
}

MOCK_VT_RESULT = {
    "analysis_status": "abgeschlossen",
    "api_status": "success",
    "domain": "example.com",
    "threat_analysis": {"malicious_detections": 0, "total_security_vendors": 91},
    "threat_intelligence": {"threat_level": "LOW"},
    "reputation_score": 5,
}

MOCK_ABUSE_RESULT = {
    "analysis_status": "abgeschlossen",
    "ip_address": "93.184.216.34",
    "abuse_confidence": 0,
    "reputation_intelligence": {"risk_level": "LOW"},
}

MOCK_ST_RESULT = {
    "analysis_status": "abgeschlossen",
    "domain_details": {"subdomain_count": 5},
}

MOCK_DNS_HISTORY_RESULT = {
    "analysis_status": "abgeschlossen",
    "data_sources": ["RobTex"],
    "timeline": [],
    "a_history": [],
    "ns_history": [],
    "mx_history": [],
    "ct_history": [],
    "major_changes": 0,
    "timeline_span": {"start_date": "2020-01-01", "end_date": "2024-01-01", "days": 1461},
    "pattern_analysis": {"risk_level": "LOW", "suspicious_patterns": ["none detected"],
                         "change_frequency": "low", "infrastructure_stability": "stable"},
    "first_seen": "1995-08-14",
    "ct_metadata": None,
    "historical_risk_events": [],
}

MOCK_IP_HISTORY_RESULT = {
    "analysis_status": "abgeschlossen",
    "ip_address": "93.184.216.34",
    "domain": "example.com",
    "top_co_hosted": [],
    "total_co_hosted": 0,
}


def _make_module_mock_map():
    return {
        "dns": MOCK_DNS_RESULT,
        "whois": MOCK_WHOIS_RESULT,
        "cdn": MOCK_CDN_RESULT,
        "ssl": MOCK_SSL_RESULT,
        "network": MOCK_NETWORK_RESULT,
        "subdomain": MOCK_SUBDOMAIN_RESULT,
        "virustotal": MOCK_VT_RESULT,
        "abuseipdb": MOCK_ABUSE_RESULT,
        "securitytrails": MOCK_ST_RESULT,
        "dns_history": MOCK_DNS_HISTORY_RESULT,
        "ip_history": MOCK_IP_HISTORY_RESULT,
    }


# ---------------------------------------------------------------------------
# DomainAnalyzer integration with mocked modules
# ---------------------------------------------------------------------------

class TestDomainAnalyzerIntegration:

    @pytest.fixture
    def analyzer(self):
        from src.core.domain_analyzer import DomainAnalyzer
        return DomainAnalyzer()

    def _patch_all_modules(self, analyzer, mock_map):
        """Replace all module call results with pre-defined mocks."""
        original = analyzer._call_module_function

        def patched(module_name, module, domain):
            if module_name in mock_map:
                return mock_map[module_name]
            return original(module_name, module, domain)

        return patch.object(analyzer, "_call_module_function", side_effect=patched)

    def test_analyze_domain_returns_unified_result(self, analyzer):
        from src.core.result_aggregator import UnifiedResult
        mock_map = _make_module_mock_map()

        with self._patch_all_modules(analyzer, mock_map):
            result = analyzer.analyze_domain("example.com")

        assert isinstance(result, UnifiedResult)
        assert result.domain == "example.com"

    def test_analyze_domain_populates_results(self, analyzer):
        mock_map = _make_module_mock_map()

        with self._patch_all_modules(analyzer, mock_map):
            result = analyzer.analyze_domain("example.com")

        assert "dns" in result.results
        assert "whois" in result.results

    def test_invalid_domain_raises_value_error(self, analyzer):
        with pytest.raises(ValueError):
            analyzer.analyze_domain("not_a_domain")

    def test_module_failure_does_not_crash_analysis(self, analyzer):
        mock_map = _make_module_mock_map()
        mock_map["ssl"] = None  # will cause module to fail

        def patched(module_name, module, domain):
            if module_name in mock_map:
                if mock_map[module_name] is None:
                    raise Exception("Simulated SSL failure")
                return mock_map[module_name]
            raise Exception(f"Unexpected module: {module_name}")

        with patch.object(analyzer, "_call_module_function", side_effect=patched):
            result = analyzer.analyze_domain("example.com")

        assert result is not None

    def test_github_domain_analysis(self, analyzer):
        mock_map = _make_module_mock_map()
        mock_map["dns"] = {**MOCK_DNS_RESULT, "ipv4": "140.82.121.4"}
        mock_map["cdn"] = {**MOCK_CDN_RESULT, "provider_detected": "github",
                          "provider_name": "GitHub", "infrastructure_type": "hosting"}

        with self._patch_all_modules(analyzer, mock_map):
            result = analyzer.analyze_domain("github.com")

        assert result.domain == "github.com"

    def test_historical_domain_no_ip(self, analyzer):
        mock_map = _make_module_mock_map()
        mock_map["dns"] = {**MOCK_DNS_RESULT, "ipv4": None}

        with self._patch_all_modules(analyzer, mock_map):
            result = analyzer.analyze_domain("securecloud4you.com")

        assert result is not None

    def test_module_returns_non_dict_handled(self, analyzer):
        def patched(module_name, module, domain):
            if module_name == "ssl":
                return "not a dict"
            return _make_module_mock_map().get(module_name, {})

        with patch.object(analyzer, "_call_module_function", side_effect=patched):
            result = analyzer.analyze_domain("example.com")

        assert result is not None

    def test_get_fallback_result_for_all_modules(self, analyzer):
        for module in ["dns", "whois", "cdn", "network", "subdomain",
                       "securitytrails", "abuseipdb", "virustotal", "ip_history", "ssl", "dns_history"]:
            result = analyzer._get_fallback_result(module, "error", "test error")
            assert isinstance(result, dict)
            assert result["analysis_status"] == "failed"


# ---------------------------------------------------------------------------
# DomainValidator edge cases via integration
# ---------------------------------------------------------------------------

class TestValidatorIntegration:

    def test_preprocess_strips_to_apex_before_analyze(self):
        from src.utils.validators import DomainValidator
        domain, msg = DomainValidator.preprocess_domain("mail.google.com")
        assert domain == "google.com"

    def test_batch_list_format_rejected(self):
        from src.utils.validators import DomainValidator
        domain, msg = DomainValidator.preprocess_domain("list.txt")
        assert domain is None
        assert "--list" in msg
