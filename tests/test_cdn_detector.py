"""Unit tests for CDNDetector._detect_provider and provider database."""

import pytest
from unittest.mock import patch, MagicMock
from src.analyzers.cdn_detector import CDNDetector


@pytest.fixture
def detector():
    return CDNDetector()


# ---------------------------------------------------------------------------
# _detect_provider — IP prefix matching
# ---------------------------------------------------------------------------

class TestDetectProviderByIP:

    def test_cloudflare_ip_detected(self, detector):
        result = detector._detect_provider("104.16.0.1")
        assert result["provider_detected"] == "cloudflare"
        assert result["infrastructure_type"] == "cdn"

    def test_cloudflare_second_range_detected(self, detector):
        result = detector._detect_provider("104.24.0.1")
        assert result["provider_detected"] == "cloudflare"

    def test_github_ip_detected(self, detector):
        result = detector._detect_provider("140.82.0.1")
        assert result["provider_detected"] == "github"

    def test_unknown_ip_returns_direct(self, detector):
        result = detector._detect_provider("1.2.3.4")
        assert result["provider_detected"] is None
        assert result["infrastructure_type"] == "direct"

    def test_aws_ip_detected(self, detector):
        result = detector._detect_provider("52.0.0.1")
        assert result["provider_detected"] is not None


# ---------------------------------------------------------------------------
# _detect_provider — hostname pattern matching (Pass 1)
# ---------------------------------------------------------------------------

class TestDetectProviderByHostname:

    def test_cloudflare_rdns_takes_priority_over_ip(self, detector):
        result = detector._detect_provider("1.2.3.4", rdns_hostname="host.cloudflare.net")
        assert result["provider_detected"] == "cloudflare"

    def test_hetzner_rdns_detected(self, detector):
        result = detector._detect_provider("1.2.3.4", rdns_hostname="static.123.your-server.de")
        assert result["provider_detected"] == "hetzner"

    def test_ovh_rdns_detected(self, detector):
        result = detector._detect_provider("1.2.3.4", rdns_hostname="ip1.ovh.net")
        assert result["provider_detected"] == "ovhcloud"

    def test_unknown_rdns_falls_back_to_ip(self, detector):
        result = detector._detect_provider("104.16.0.1", rdns_hostname="unknown.example.com")
        assert result["provider_detected"] == "cloudflare"


# ---------------------------------------------------------------------------
# analyze_infrastructure
# ---------------------------------------------------------------------------

class TestAnalyzeInfrastructure:

    def test_missing_ip_returns_error(self, detector):
        result = detector.analyze_infrastructure(None)
        assert result["analysis_status"] in ("fehlgeschlagen", "failed", "error")

    def test_empty_ip_returns_error(self, detector):
        result = detector.analyze_infrastructure("")
        assert result["analysis_status"] in ("fehlgeschlagen", "failed", "error")

    def test_valid_ip_returns_abgeschlossen(self, detector):
        with patch.object(detector, "_analyze_geolocation", return_value={"status": "success", "countryCode": "US"}):
            result = detector.analyze_infrastructure("104.16.0.1", "example.com")
        assert result["analysis_status"] == "abgeschlossen"
        assert result["provider_detected"] == "cloudflare"

    def test_result_contains_required_keys(self, detector):
        with patch.object(detector, "_analyze_geolocation", return_value={}):
            result = detector.analyze_infrastructure("104.16.0.1")
        for key in ("ip_address", "provider_name", "infrastructure_type", "protection_level"):
            assert key in result


# ---------------------------------------------------------------------------
# Provider database integrity
# ---------------------------------------------------------------------------

class TestProviderDatabase:

    def test_all_providers_have_required_fields(self, detector):
        required = {"name", "type", "protection_level", "ip_ranges"}
        for key, data in detector.provider_database.items():
            missing = required - set(data.keys())
            assert not missing, f"Provider '{key}' missing fields: {missing}"

    def test_cloudflare_has_multiple_ip_ranges(self, detector):
        cf = detector.provider_database.get("cloudflare", {})
        assert len(cf.get("ip_ranges", [])) >= 3

    def test_protection_level_values_valid(self, detector):
        valid = {"high", "medium", "low", "minimal", "basic", "unknown"}
        for key, data in detector.provider_database.items():
            level = data.get("protection_level", "").lower()
            assert level in valid, f"Provider '{key}' has unexpected protection_level '{level}'"
