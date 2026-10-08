"""Unit tests for the AlienVault OTX client and its DNS history source (mocked HTTP only)."""

import inspect
from unittest.mock import MagicMock, patch

import pytest

from src.config.api_config import APIConfig

OTX_KEY = "a" * 64

GENERAL = {
    "pulse_info": {
        "count": 2,
        "pulses": [{"name": "Phishing kit hosts"}, {"name": "Botnet C2 list"}],
    },
    "validation": [{"source": "whitelist", "message": "known"}],
}

PASSIVE_DNS = {
    "count": 7,
    "passive_dns": [
        {"hostname": "example.com", "address": "93.184.216.34", "record_type": "A",
         "first": "2019-01-01T00:00:00", "last": "2024-05-01T10:00:00", "asn": "AS15133 edgecast"},
        {"hostname": "example.com", "address": "104.20.23.154", "record_type": "A",
         "first": "2025-01-01T00:00:00", "last": "2026-10-07T19:09:57", "asn": "AS13335 cloudflare"},
        {"hostname": "example.com", "address": "2606:4700:10::6814:179a", "record_type": "AAAA",
         "first": "2026-04-10T20:08:00", "last": "2026-10-07T19:09:57", "asn": "AS13335 cloudflare"},
        {"hostname": "example.com", "address": "mail.example.com.", "record_type": "MX",
         "first": "2020-01-01T00:00:00", "last": "2026-01-01T00:00:00"},
        {"hostname": "www.example.com", "address": "104.20.23.154", "record_type": "A",
         "first": "2025-02-01T00:00:00", "last": "2026-10-01T00:00:00"},
        {"hostname": "admin.example.com", "address": "10.0.0.1", "record_type": "A",
         "first": "2021-02-01T00:00:00", "last": "2022-10-01T00:00:00"},
        {"hostname": "*.api.example.com", "address": "1.2.3.4", "record_type": "A",
         "first": "2023-02-01T00:00:00", "last": "2023-10-01T00:00:00"},
        {"hostname": "notexample.com", "address": "5.6.7.8", "record_type": "A",
         "first": "2023-02-01T00:00:00", "last": "2023-10-01T00:00:00"},
    ],
}


def _resp(status, payload=None):
    response = MagicMock()
    response.status_code = status
    response.json.return_value = payload if payload is not None else {}
    return response


def _router(general=(200, GENERAL), pdns=(200, PASSIVE_DNS), calls=None):
    def fake_get(self, url, *args, **kwargs):
        if calls is not None:
            calls.append((url, dict(self.headers), kwargs.get("headers") or {}))
        if url.endswith("/general"):
            return _resp(*general)
        if url.endswith("/passive_dns"):
            return _resp(*pdns)
        raise AssertionError(f"unexpected URL {url}")
    return fake_get


@pytest.fixture(autouse=True)
def clear_cache():
    from src.analyzers import otx_client
    otx_client._PASSIVE_DNS_CACHE.clear()
    yield
    otx_client._PASSIVE_DNS_CACHE.clear()


@pytest.fixture
def client():
    from src.analyzers.otx_client import OTXClient
    c = OTXClient()
    c.config = APIConfig(api_key=OTX_KEY, base_url="https://otx.alienvault.com/api/v1", rate_limit=1000)
    c.session.headers.update({"X-OTX-API-KEY": OTX_KEY})
    return c


class TestOTXClient:

    def test_no_api_key_returns_demo_mode(self):
        from src.analyzers.otx_client import OTXClient
        c = OTXClient()
        c.config = None
        result = c.analyze_domain_intelligence("example.com")
        assert result["analysis_status"] == "demo_abgeschlossen"
        assert result["api_status"] == "demo_mode"
        assert result["source"] == "AlienVault OTX"

    def test_env_key_is_picked_up(self, monkeypatch):
        monkeypatch.setenv("OTX_API_KEY", OTX_KEY)
        from src.analyzers.otx_client import OTXClient
        c = OTXClient()
        assert c.config is not None and c.config.api_key == OTX_KEY
        assert c.session.headers["X-OTX-API-KEY"] == OTX_KEY

    def test_successful_analysis(self, client):
        calls = []
        with patch("requests.Session.get", _router(calls=calls)):
            result = client.analyze_domain_intelligence("Example.com")

        assert result["analysis_status"] == "abgeschlossen"
        assert result["api_status"] == "live_data"
        assert result["partial"] is False
        # every request carries the key in a header (counted by the DFA runner budget)
        assert all(OTX_KEY in {**session_h, **call_h}.values() for _, session_h, call_h in calls)

        sub = result["subdomain_intelligence"]
        assert sub["total_found"] == 3
        assert sub["top_subdomains"][0] == "www"          # most recently seen first
        assert set(sub["top_subdomains"]) == {"www", "admin", "api"}
        assert "notexample" not in " ".join(sub["top_subdomains"])
        assert sub["categorized_assets"]["admin"] == ["admin"]
        assert sub["categorized_assets"]["api"] == ["api"]
        assert sub["sensitive_count"] == 2
        assert result["domain_details"]["subdomain_count"] == 3
        assert result["domain_details"]["pulse_count"] == 2

        hist = result["historical_dns"]
        assert hist["status"] == "success"
        assert hist["unique_ips"] == 3                     # apex A/AAAA only
        assert hist["a_records"][0]["ip_addresses"] in (["104.20.23.154"], ["2606:4700:10::6814:179a"])
        assert hist["mx_records"][0]["mail_servers"] == ["mail.example.com"]
        assert hist["record_type_counts"] == {"A": 2, "AAAA": 1, "MX": 1}
        assert hist["first_seen"] == "2019-01-01T00:00:00"

        threat = result["threat_intelligence"]
        assert threat["pulse_count"] == 2
        assert threat["pulse_names"] == ["Phishing kit hosts", "Botnet C2 list"]
        assert threat["validation"] == ["whitelist"]
        assert any("threat pulse" in r for r in result["intelligence_summary"]["risk_indicators"])

    def test_quota_exceeded(self, client):
        with patch("requests.Session.get", _router(general=(429, {}), pdns=(429, {}))):
            result = client.analyze_domain_intelligence("example.com")
        assert result["analysis_status"] == "quota_exceeded"
        assert result["api_status"] == "quota_exceeded"
        assert result["domain_details"] == {"subdomain_count": 0}

    def test_rejected_key_is_failed(self, client):
        with patch("requests.Session.get", _router(general=(403, {}), pdns=(403, {}))):
            result = client.analyze_domain_intelligence("example.com")
        assert result["analysis_status"] == "failed"
        assert result["api_status"] == "api_error"
        assert "rejected the API key" in result["error"]
        assert OTX_KEY not in str(result)

    def test_partial_result_when_one_part_fails(self, client):
        with patch("requests.Session.get", _router(general=(429, {}))):
            result = client.analyze_domain_intelligence("example.com")
        assert result["analysis_status"] == "abgeschlossen"
        assert result["partial"] is True
        assert result["subdomain_intelligence"]["total_found"] == 3

    def test_unknown_domain_404_is_empty_success(self, client):
        with patch("requests.Session.get", _router(general=(404, {}), pdns=(404, {}))):
            result = client.analyze_domain_intelligence("unknown-domain.example")
        assert result["analysis_status"] == "abgeschlossen"
        assert result["subdomain_intelligence"]["total_found"] == 0
        assert result["threat_intelligence"]["pulse_count"] == 0

    def test_network_error_handled(self, client):
        import requests
        with patch("requests.Session.get", side_effect=requests.ConnectionError("down")):
            result = client.analyze_domain_intelligence("example.com")
        assert result["analysis_status"] == "failed"


class TestPassiveDNSFetch:

    def test_success_is_cached_once_per_domain(self):
        from src.analyzers.otx_client import fetch_passive_dns
        calls = []
        with patch("requests.Session.get", _router(calls=calls)):
            first = fetch_passive_dns("example.com", OTX_KEY)
            second = fetch_passive_dns("EXAMPLE.com.", OTX_KEY)
        assert first is second
        assert len(calls) == 1

    def test_failure_is_not_cached(self):
        from src.analyzers.otx_client import fetch_passive_dns
        calls = []
        with patch("requests.Session.get", _router(pdns=(429, {}), calls=calls)):
            assert fetch_passive_dns("example.com", OTX_KEY)["status"] == "quota_exceeded"
            fetch_passive_dns("example.com", OTX_KEY)
        assert len(calls) == 2

    def test_record_cap(self, monkeypatch):
        from src.analyzers import otx_client
        monkeypatch.setattr(otx_client, "MAX_RECORDS", 3)
        with patch("requests.Session.get", _router()):
            result = otx_client.fetch_passive_dns("example.com", OTX_KEY)
        assert len(result["records"]) == 3
        assert result["total"] == 7

    def test_invalid_json(self):
        from src.analyzers.otx_client import fetch_passive_dns
        bad = MagicMock(status_code=200)
        bad.json.side_effect = ValueError("no json")
        with patch("requests.Session.get", return_value=bad):
            assert fetch_passive_dns("example.com", OTX_KEY)["status"] == "failed"


class TestDNSHistoryOTXSource:

    def _analyzer(self, key):
        from src.analyzers.dns_history_analyzer import DNSHistoryAnalyzer
        analyzer = DNSHistoryAnalyzer()
        analyzer.otx_api_key = key
        return analyzer

    def test_skipped_without_key(self):
        result = self._analyzer(None)._collect_otx_history("example.com")
        assert result["status"] == "skipped"

    def test_events_for_the_domain_itself(self):
        with patch("requests.Session.get", _router()):
            result = self._analyzer(OTX_KEY)._collect_otx_history("example.com")
        assert result["status"] == "success"
        assert result["label"] == "AlienVault OTX"
        assert len(result["events"]) == 4                  # apex records only
        assert {e["source"] for e in result["events"]} == {"AlienVault OTX"}
        assert {e["record_type"] for e in result["events"]} == {"A", "AAAA", "MX"}

    def test_quota(self):
        with patch("requests.Session.get", _router(pdns=(429, {}))):
            result = self._analyzer(OTX_KEY)._collect_otx_history("example.com")
        assert result["status"] == "quota_exceeded"

    def test_source_is_part_of_the_timeline(self):
        analyzer = self._analyzer(OTX_KEY)
        empty = {"status": "skipped", "events": []}
        with patch.object(analyzer, "_collect_robtex_history", return_value=empty), \
             patch.object(analyzer, "_collect_mnemonic_history", return_value=empty), \
             patch.object(analyzer, "_collect_virustotal_history", return_value=empty), \
             patch.object(analyzer, "_collect_securitytrails_history", return_value=empty), \
             patch.object(analyzer, "_collect_certificate_transparency", return_value=empty), \
             patch("requests.Session.get", _router()):
            result = analyzer.analyze_dns_history("example.com")
        assert "AlienVault OTX" in result.get("data_sources", [])


class TestIntegrationPoints:

    def test_otx_replaces_securitytrails_in_default_order(self):
        from src.core.domain_analyzer import DomainAnalyzer
        analyzer = DomainAnalyzer()
        assert "otx" in analyzer.module_execution_order
        assert "securitytrails" not in analyzer.module_execution_order
        assert "otx" in analyzer.modules
        assert "securitytrails" in analyzer.modules        # still available on request

    def test_live_api_statuses_signature_and_label(self):
        from src.core import result_formatter
        params = list(inspect.signature(result_formatter._collect_live_api_statuses).parameters)
        assert params == ["vt_result", "whois_result", "dns_history_result", "st_result",
                          "abuse_result", "ip_history_result", "otx_result"]
        labels = result_formatter._collect_live_api_statuses(
            {}, {}, {}, None, None, None, {"api_status": "live_data"})
        assert "AlienVault OTX" in labels

    def test_env_var_map(self):
        from src.config import api_config
        assert api_config._ENV_VAR_MAP["otx"] == "OTX_API_KEY"
        assert api_config._DEFAULTS["otx"][0] == "https://otx.alienvault.com/api/v1"
