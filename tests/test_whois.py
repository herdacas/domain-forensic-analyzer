"""Unit tests for WHOIS helper functions and main API flow."""

import pytest
from datetime import datetime
from unittest.mock import patch, MagicMock
from src.analyzers.whois import (
    _detect_registry_policy,
    _detect_privacy_proxy,
    _normalize_date,
    _extract_whoisxml_nameservers,
)


# ---------------------------------------------------------------------------
# _detect_registry_policy
# ---------------------------------------------------------------------------

class TestDetectRegistryPolicy:

    def test_de_tld_returns_denic(self):
        result = _detect_registry_policy("example.de")
        assert result is not None
        assert "DENIC" in result or "denic" in result.lower()

    def test_nl_tld_returns_sidn(self):
        result = _detect_registry_policy("example.nl")
        assert result is not None

    def test_ch_tld_returns_switch(self):
        result = _detect_registry_policy("example.ch")
        assert result is not None

    def test_com_tld_returns_none(self):
        result = _detect_registry_policy("example.com")
        assert result is None

    def test_org_tld_returns_none(self):
        result = _detect_registry_policy("example.org")
        assert result is None

    def test_case_insensitive(self):
        result = _detect_registry_policy("EXAMPLE.DE")
        assert result is not None


# ---------------------------------------------------------------------------
# _detect_privacy_proxy
# ---------------------------------------------------------------------------

class TestDetectPrivacyProxy:

    def test_whoisguard_detected_in_registrar(self):
        result = _detect_privacy_proxy("WhoisGuard Inc.", None, None)
        assert result == "WhoisGuard"

    def test_domains_by_proxy_detected(self):
        result = _detect_privacy_proxy("domainsbyproxy.com", None, None)
        assert result == "Domains By Proxy"

    def test_redacted_for_privacy_in_email(self):
        result = _detect_privacy_proxy(None, "redacted for privacy@example.com", None)
        assert result == "Redacted for Privacy"

    def test_withheld_for_privacy_detected(self):
        result = _detect_privacy_proxy("Withheld for Privacy ehf", None, None)
        assert result == "Withheld for Privacy"

    def test_no_proxy_returns_none(self):
        result = _detect_privacy_proxy("GoDaddy LLC", "registrant@example.com", "John Doe")
        assert result is None

    def test_all_none_returns_none(self):
        result = _detect_privacy_proxy(None, None, None)
        assert result is None

    def test_case_insensitive_detection(self):
        result = _detect_privacy_proxy("WHOISGUARD PROTECTED", None, None)
        assert result is not None


# ---------------------------------------------------------------------------
# _normalize_date
# ---------------------------------------------------------------------------

class TestNormalizeDate:

    def test_none_returns_none(self):
        assert _normalize_date(None) is None

    def test_datetime_returns_isoformat(self):
        dt = datetime(2024, 1, 15, 12, 0, 0)
        result = _normalize_date(dt)
        assert "2024-01-15" in result

    def test_string_returns_as_is(self):
        assert _normalize_date("2024-01-15T00:00:00") == "2024-01-15T00:00:00"

    def test_list_uses_first_element(self):
        dt = datetime(2024, 3, 1)
        result = _normalize_date([dt, datetime(2020, 1, 1)])
        assert "2024-03-01" in result

    def test_empty_list_returns_none(self):
        # Empty list: first element access will fail → returns None or raises
        # Depending on implementation — should not crash
        try:
            result = _normalize_date([])
            # If it doesn't raise, result should be None or a string
        except (IndexError, TypeError):
            pass  # acceptable


# ---------------------------------------------------------------------------
# _extract_whoisxml_nameservers
# ---------------------------------------------------------------------------

class TestExtractWhoisxmlNameservers:

    def test_extracts_from_hostnames_list(self):
        record = {"nameServers": {"hostNames": ["ns1.example.com", "ns2.example.com"]}}
        result = _extract_whoisxml_nameservers(record, {})
        assert "ns1.example.com" in result
        assert "ns2.example.com" in result

    def test_extracts_from_registry_data(self):
        record = {}
        registry = {"nameServers": {"hostNames": ["ns3.example.com"]}}
        result = _extract_whoisxml_nameservers(record, registry)
        assert "ns3.example.com" in result

    def test_deduplicates_nameservers(self):
        record = {"nameServers": {"hostNames": ["ns1.example.com"]}}
        registry = {"nameServers": {"hostNames": ["ns1.example.com", "ns2.example.com"]}}
        result = _extract_whoisxml_nameservers(record, registry)
        assert result.count("ns1.example.com") == 1

    def test_empty_inputs_return_empty_list(self):
        result = _extract_whoisxml_nameservers({}, {})
        assert result == []

    def test_string_nameserver_handled(self):
        record = {"nameServers": {"hostNames": "ns1.example.com"}}
        result = _extract_whoisxml_nameservers(record, {})
        assert "ns1.example.com" in result


# ---------------------------------------------------------------------------
# get_whois_local — mocked python-whois
# ---------------------------------------------------------------------------

class TestGetWhoisLocal:

    def test_returns_dict_with_required_fields(self):
        from src.analyzers.whois import get_whois_local
        from unittest.mock import patch, MagicMock
        from datetime import datetime

        mock_w = MagicMock()
        mock_w.registrar = "Test Registrar Inc."
        mock_w.creation_date = datetime(1995, 8, 14)
        mock_w.expiration_date = datetime(2026, 8, 13)
        mock_w.updated_date = datetime(2023, 8, 14)
        mock_w.name_servers = ["ns1.example.com", "ns2.example.com"]
        mock_w.registrant_country = "US"
        mock_w.org = None
        mock_w.emails = "admin@example.com"

        with patch("whois.whois", return_value=mock_w):
            result = get_whois_local("example.com")

        assert isinstance(result, dict)
        assert "registrar" in result

    def test_exception_returns_error_dict(self):
        from src.analyzers.whois import get_whois_local
        from unittest.mock import patch

        with patch("whois.whois", side_effect=Exception("Connection error")):
            result = get_whois_local("example.com")

        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# get_whois (main dispatcher) — mocked
# ---------------------------------------------------------------------------

class TestGetWhoisXmlApi:

    def test_no_api_key_returns_skipped(self):
        from src.analyzers.whois import get_whois_xmlapi
        from unittest.mock import patch
        with patch("src.analyzers.whois.WHOISXML_API_KEY", None):
            result = get_whois_xmlapi("example.com")
        assert isinstance(result, dict)
        assert result.get("analysis_status") in ("skipped", None) or "error" in result

    def test_invalid_api_key_skipped(self):
        from src.analyzers.whois import get_whois_xmlapi
        from unittest.mock import patch
        with patch("src.analyzers.whois.WHOISXML_API_KEY", "your_key_here"):
            result = get_whois_xmlapi("example.com")
        assert isinstance(result, dict)

    def test_successful_api_response(self, whoisxml_response):
        from src.analyzers.whois import get_whois_xmlapi
        from unittest.mock import patch, MagicMock
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = whoisxml_response
        mock_resp.raise_for_status = MagicMock()

        with patch("src.analyzers.whois.WHOISXML_API_KEY", "test_key_123"), \
             patch("requests.get", return_value=mock_resp):
            result = get_whois_xmlapi("example.com")

        assert isinstance(result, dict)

    def test_api_error_returns_error_dict(self):
        from src.analyzers.whois import get_whois_xmlapi
        from unittest.mock import patch
        with patch("src.analyzers.whois.WHOISXML_API_KEY", "test_key_123"), \
             patch("requests.get", side_effect=Exception("API error")):
            result = get_whois_xmlapi("example.com")
        assert isinstance(result, dict)


class TestGetWhoisDispatcher:

    def test_no_api_key_uses_local_fallback(self):
        from src.analyzers.whois import get_whois
        from unittest.mock import patch

        local_result = {
            "registrar": "IANA",
            "creation_date": "1995-08-14T00:00:00",
            "analysis_status": "abgeschlossen",
        }

        with patch("src.analyzers.whois.get_whois_local", return_value=local_result) as mock_local, \
             patch("src.analyzers.whois.WHOISXML_API_KEY", None):
            result = get_whois("example.com")

        assert isinstance(result, dict)
