"""Unit tests for SubdomainScanner pure logic methods."""

import pytest
from unittest.mock import patch, MagicMock
from src.analyzers.subdomain_scanner import SubdomainScanner


@pytest.fixture
def scanner():
    return SubdomainScanner()


# ---------------------------------------------------------------------------
# _categorize_assets
# ---------------------------------------------------------------------------

class TestCategorizeAssets:

    def test_admin_subdomain_categorized(self, scanner):
        assets = [{"subdomain": "admin", "ip": "1.2.3.4", "risk_level": "critical"}]
        result = scanner._categorize_assets(assets)
        assert len(result["admin"]) == 1

    def test_api_subdomain_categorized(self, scanner):
        assets = [{"subdomain": "api", "ip": "1.2.3.4", "risk_level": "high"}]
        result = scanner._categorize_assets(assets)
        assert len(result["api"]) == 1

    def test_unknown_subdomain_goes_to_basic(self, scanner):
        assets = [{"subdomain": "randomxyz", "ip": "1.2.3.4", "risk_level": "low"}]
        result = scanner._categorize_assets(assets)
        assert len(result["basic"]) == 1

    def test_empty_assets_returns_empty_categories(self, scanner):
        result = scanner._categorize_assets([])
        for cat in ("admin", "api", "dev", "service", "basic"):
            assert result[cat] == []

    def test_www_subdomain_goes_to_basic_or_content(self, scanner):
        assets = [{"subdomain": "www", "ip": "1.2.3.4", "risk_level": "low"}]
        result = scanner._categorize_assets(assets)
        total = sum(len(v) for v in result.values())
        assert total == 1


# ---------------------------------------------------------------------------
# _analyze_sensitive_assets
# ---------------------------------------------------------------------------

class TestAnalyzeSensitiveAssets:

    def test_admin_is_critical(self, scanner):
        assets = [{"subdomain": "admin", "ip": "1.2.3.4"}]
        result = scanner._analyze_sensitive_assets(assets)
        assert len(result) == 1
        assert result[0]["risk_level"] == "critical"

    def test_api_is_high(self, scanner):
        assets = [{"subdomain": "api", "ip": "1.2.3.4"}]
        result = scanner._analyze_sensitive_assets(assets)
        assert len(result) == 1
        assert result[0]["risk_level"] == "high"

    def test_dev_is_high(self, scanner):
        assets = [{"subdomain": "dev", "ip": "1.2.3.4"}]
        result = scanner._analyze_sensitive_assets(assets)
        assert len(result) >= 1
        assert result[0]["risk_level"] == "high"

    def test_www_not_sensitive(self, scanner):
        assets = [{"subdomain": "www", "ip": "1.2.3.4"}]
        result = scanner._analyze_sensitive_assets(assets)
        assert result == []

    def test_sorted_critical_before_high(self, scanner):
        assets = [
            {"subdomain": "api", "ip": "1.2.3.4"},
            {"subdomain": "admin", "ip": "1.2.3.4"},
        ]
        result = scanner._analyze_sensitive_assets(assets)
        if len(result) >= 2:
            assert result[0]["risk_level"] == "critical"


# ---------------------------------------------------------------------------
# _get_risk_recommendations
# ---------------------------------------------------------------------------

class TestGetRiskRecommendations:

    def test_critical_returns_list(self, scanner):
        result = scanner._get_risk_recommendations("critical", "admin")
        assert isinstance(result, list)
        assert len(result) > 0

    def test_high_returns_list(self, scanner):
        result = scanner._get_risk_recommendations("high", "api")
        assert isinstance(result, list)

    def test_medium_returns_list(self, scanner):
        result = scanner._get_risk_recommendations("medium", "staging")
        assert isinstance(result, list)

    def test_unknown_risk_returns_list(self, scanner):
        result = scanner._get_risk_recommendations("low", "www")
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# scan_subdomains — mocked DNS
# ---------------------------------------------------------------------------

class TestScanSubdomainsMocked:

    def test_scan_returns_dict(self, scanner):
        with patch.object(scanner, "_detect_wildcard", return_value=False), \
             patch.object(scanner, "_enumerate_subdomains", return_value=[
                 {"subdomain": "www", "full_domain": "www.example.com", "ip": "1.2.3.4", "risk_level": "low"}
             ]):
            result = scanner.scan_subdomains("example.com")

        assert isinstance(result, dict)
        assert "discovered_assets" in result

    def test_wildcard_domain_handled(self, scanner):
        with patch.object(scanner, "_detect_wildcard", return_value=True), \
             patch.object(scanner, "_enumerate_subdomains", return_value=[]):
            result = scanner.scan_subdomains("example.com")

        assert isinstance(result, dict)
        assert result.get("wildcard_detected") is True

    def test_empty_results_on_all_failures(self, scanner):
        with patch.object(scanner, "_detect_wildcard", return_value=False), \
             patch.object(scanner, "_enumerate_subdomains", return_value=[]):
            result = scanner.scan_subdomains("example.com")

        assert len(result.get("discovered_assets", [])) == 0
