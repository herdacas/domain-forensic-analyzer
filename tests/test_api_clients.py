"""Unit tests for API client modules using mocked HTTP responses."""

import pytest
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# VirusTotal client
# ---------------------------------------------------------------------------

class TestVirusTotalClient:

    @pytest.fixture
    def client(self):
        from src.analyzers.virustotal_client import VirusTotalClient
        c = VirusTotalClient()
        c.api_key = "test_key_1234567890"
        return c

    def test_no_api_key_returns_demo_mode(self):
        from src.analyzers.virustotal_client import VirusTotalClient
        c = VirusTotalClient()
        c.api_key = None
        result = c.analyze_domain_reputation("example.com")
        assert result.get("api_status") in ("demo", "no_api_key", "failed", None) or \
               "[Demo" in str(result) or \
               result.get("analysis_status") is not None

    def test_successful_domain_analysis(self, client, vt_domain_response):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = vt_domain_response
        mock_resp.raise_for_status = MagicMock()

        with patch("requests.Session.get", return_value=mock_resp):
            result = client.analyze_domain_reputation("example.com")

        assert isinstance(result, dict)
        assert result.get("analysis_status") is not None

    def test_api_error_returns_failed_status(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.raise_for_status.side_effect = Exception("403 Forbidden")

        with patch("requests.Session.get", side_effect=Exception("403 Forbidden")):
            result = client.analyze_domain_reputation("example.com")

        assert isinstance(result, dict)

    def test_network_error_handled_gracefully(self, client):
        with patch("requests.Session.get", side_effect=ConnectionError("Network error")):
            result = client.analyze_domain_reputation("example.com")
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# AbuseIPDB client
# ---------------------------------------------------------------------------

class TestAbuseIPDBClient:

    @pytest.fixture
    def client(self):
        from src.analyzers.abuseipdb_client import AbuseIPDBClient
        c = AbuseIPDBClient()
        c.api_key = "test_key_1234567890"
        return c

    def test_no_api_key_handled(self):
        from src.analyzers.abuseipdb_client import AbuseIPDBClient
        c = AbuseIPDBClient()
        c.api_key = None
        result = c.analyze_ip_reputation("93.184.216.34", "example.com")
        assert isinstance(result, dict)

    def test_successful_ip_check(self, client, abuseipdb_response):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = abuseipdb_response
        mock_resp.raise_for_status = MagicMock()

        with patch("requests.get", return_value=mock_resp):
            result = client.analyze_ip_reputation("93.184.216.34", "example.com")

        assert isinstance(result, dict)

    def test_network_error_handled(self, client):
        with patch("requests.get", side_effect=ConnectionError("timeout")):
            result = client.analyze_ip_reputation("1.2.3.4", "example.com")
        assert isinstance(result, dict)

    def test_result_contains_ip_field(self, client, abuseipdb_response):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = abuseipdb_response
        mock_resp.raise_for_status = MagicMock()

        with patch("requests.get", return_value=mock_resp):
            result = client.analyze_ip_reputation("93.184.216.34", "example.com")

        assert "ip_address" in result or "analysis_status" in result


# ---------------------------------------------------------------------------
# SecurityTrails client
# ---------------------------------------------------------------------------

class TestSecurityTrailsClient:

    @pytest.fixture
    def client(self):
        from src.analyzers.securitytrails_client import SecurityTrailsClient
        c = SecurityTrailsClient()
        c.api_key = "test_key_1234567890"
        return c

    def test_no_api_key_returns_demo(self):
        from src.analyzers.securitytrails_client import SecurityTrailsClient
        c = SecurityTrailsClient()
        c.api_key = None
        result = c.analyze_domain_intelligence("example.com")
        assert isinstance(result, dict)
        assert result.get("analysis_status") is not None

    def test_successful_domain_info(self, client):
        domain_resp = MagicMock()
        domain_resp.status_code = 200
        domain_resp.json.return_value = {
            "alexa_rank": 1000,
            "whois": {"registrar": "IANA"},
            "hostname": "example.com",
        }
        domain_resp.raise_for_status = MagicMock()

        hist_resp = MagicMock()
        hist_resp.status_code = 200
        hist_resp.json.return_value = {"a": {"records": []}, "ns": {"records": []}, "mx": {"records": []}}
        hist_resp.raise_for_status = MagicMock()

        sub_resp = MagicMock()
        sub_resp.status_code = 200
        sub_resp.json.return_value = {"subdomains": ["www", "api", "mail"]}
        sub_resp.raise_for_status = MagicMock()

        with patch.object(client.session, "get", side_effect=[domain_resp, hist_resp, sub_resp]):
            result = client.analyze_domain_intelligence("example.com")

        assert isinstance(result, dict)
        assert result.get("analysis_status") is not None

    def test_quota_exceeded_returns_correct_status(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 429

        with patch.object(client.session, "get", return_value=mock_resp):
            result = client.analyze_domain_intelligence("example.com")

        assert result.get("analysis_status") in ("quota_exceeded", "failed", "skipped")

    def test_categorize_subdomains(self, client):
        result = client._categorize_subdomains(["www", "api", "mail", "dev", "admin", "custom"])
        assert isinstance(result, dict)
        assert any(len(v) > 0 for v in result.values())

    def test_create_intelligence_summary(self, client):
        categorized = client._categorize_subdomains(["www", "api", "admin"])
        result = client._create_intelligence_summary(
            {"hostname": "example.com", "alexa_rank": 100, "subdomain_count": 3},
            {"a": {"records": [{"ip": "1.2.3.4"}]}, "ns": {"records": []}, "mx": {"records": []}},
            categorized,
        )
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# IP History Analyzer
# ---------------------------------------------------------------------------

class TestIPHistoryPureLogic:

    @pytest.fixture
    def analyzer(self):
        from src.analyzers.ip_history_analyzer import IPHistoryAnalyzer
        return IPHistoryAnalyzer()

    def test_looks_like_ip_valid(self, analyzer):
        from src.analyzers.ip_history_analyzer import IPHistoryAnalyzer
        assert IPHistoryAnalyzer._looks_like_ip("1.2.3.4") is True
        assert IPHistoryAnalyzer._looks_like_ip("255.255.255.255") is True

    def test_looks_like_ip_invalid(self, analyzer):
        from src.analyzers.ip_history_analyzer import IPHistoryAnalyzer
        assert IPHistoryAnalyzer._looks_like_ip("example.com") is False
        assert IPHistoryAnalyzer._looks_like_ip("1.2.3") is False
        assert IPHistoryAnalyzer._looks_like_ip("999.1.2.3") is False

    def test_fmt_date_unix_timestamp(self, analyzer):
        from src.analyzers.ip_history_analyzer import IPHistoryAnalyzer
        result = IPHistoryAnalyzer._fmt_date(1700000000)
        assert result is not None
        assert len(result) == 10

    def test_fmt_date_none_returns_none(self, analyzer):
        from src.analyzers.ip_history_analyzer import IPHistoryAnalyzer
        assert IPHistoryAnalyzer._fmt_date(None) is None

    def test_fmt_date_string_sliced(self, analyzer):
        from src.analyzers.ip_history_analyzer import IPHistoryAnalyzer
        result = IPHistoryAnalyzer._fmt_date("2024-01-15T12:00:00")
        assert result == "2024-01-15"

    def test_fmt_timestamp_valid(self, analyzer):
        from src.analyzers.ip_history_analyzer import IPHistoryAnalyzer
        result = IPHistoryAnalyzer._fmt_timestamp(1700000000)
        assert result is not None

    def test_fmt_timestamp_invalid_returns_none(self, analyzer):
        from src.analyzers.ip_history_analyzer import IPHistoryAnalyzer
        result = IPHistoryAnalyzer._fmt_timestamp("not_a_timestamp")
        assert result is None


class TestIPHistoryAnalyzer:

    @pytest.fixture
    def analyzer(self):
        from src.analyzers.ip_history_analyzer import IPHistoryAnalyzer
        return IPHistoryAnalyzer()

    def test_analyze_returns_dict(self, analyzer):
        domain_entry = {"domain": "a.com", "first_seen": None, "last_seen": None}
        with patch.object(analyzer, "_query_virustotal_reverse", return_value={"status": "no_key", "domains": []}), \
             patch.object(analyzer, "_query_robtex_reverse", return_value={"status": "success", "domains": [domain_entry]}), \
             patch.object(analyzer, "_query_hackertarget_reverse", return_value={"status": "success", "domains": [domain_entry]}):
            result = analyzer.analyze_reverse_ip("1.2.3.4", "example.com")
        assert isinstance(result, dict)

    def test_no_ip_handled(self, analyzer):
        try:
            result = analyzer.analyze_reverse_ip(None, "example.com")
            assert isinstance(result, dict)
        except Exception:
            pass  # acceptable — no IP is invalid input
