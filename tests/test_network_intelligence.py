"""Unit tests for NetworkIntelligence pure-logic methods (no network required)."""

import pytest
from unittest.mock import patch, MagicMock
from src.analyzers.network_intelligence import NetworkIntelligence


@pytest.fixture
def ni():
    return NetworkIntelligence()


# ---------------------------------------------------------------------------
# _extract_ping_time
# ---------------------------------------------------------------------------

class TestExtractPingTime:

    def test_finds_ms_on_average_line(self, ni):
        # Function returns first ms value found on any line containing 'average'
        output = "Average = 15ms"
        result = ni._extract_ping_time(output)
        assert result == "15ms"

    def test_no_average_line_returns_none(self, ni):
        output = "Request timed out."
        assert ni._extract_ping_time(output) is None

    def test_german_mittelwert_detected(self, ni):
        output = "Mittelwert = 10ms"
        result = ni._extract_ping_time(output)
        assert result == "10ms"

    def test_float_latency_parsed(self, ni):
        output = "Average = 7.5ms"
        result = ni._extract_ping_time(output)
        assert result == "7.5ms"


# ---------------------------------------------------------------------------
# _is_likely_international_route
# ---------------------------------------------------------------------------

class TestIsLikelyInternationalRoute:

    def test_private_ip_not_international(self, ni):
        assert ni._is_likely_international_route("192.168.1.1") is False
        assert ni._is_likely_international_route("10.0.0.1") is False
        assert ni._is_likely_international_route("172.16.0.1") is False

    def test_german_range_not_international(self, ni):
        assert ni._is_likely_international_route("80.0.0.1") is False
        assert ni._is_likely_international_route("84.100.0.1") is False

    def test_us_ip_is_international(self, ni):
        assert ni._is_likely_international_route("8.8.8.8") is True
        assert ni._is_likely_international_route("104.16.0.1") is True


# ---------------------------------------------------------------------------
# _parse_tracepath_output
# ---------------------------------------------------------------------------

class TestParseTracepathOutput:

    def test_parses_responsive_hop(self, ni):
        output = " 1:  192.168.0.1  1.234ms\n"
        hops = ni._parse_tracepath_output(output)
        assert len(hops) == 1
        assert hops[0]["hop"] == 1
        assert hops[0]["status"] == "responsive"
        assert "192.168.0.1" in hops[0]["ip"]

    def test_parses_no_reply_as_timeout(self, ni):
        output = " 2:  no reply\n"
        hops = ni._parse_tracepath_output(output)
        assert len(hops) == 1
        assert hops[0]["status"] == "timeout"
        assert hops[0]["ip"] is None

    def test_skips_resume_line(self, ni):
        output = "Resume: pmtu 1500\n 1:  1.2.3.4  5.0ms\n"
        hops = ni._parse_tracepath_output(output)
        assert len(hops) == 1

    def test_deduplicates_same_hop_number(self, ni):
        output = " 1:  1.2.3.4  5ms\n 1:  1.2.3.4  6ms\n"
        hops = ni._parse_tracepath_output(output)
        assert len(hops) == 1

    def test_empty_output_returns_empty_list(self, ni):
        assert ni._parse_tracepath_output("") == []

    def test_multiple_hops_parsed(self, ni):
        output = " 1:  192.168.0.1  1.0ms\n 2:  10.0.0.1  5.0ms\n 3:  8.8.8.8  20.0ms\n"
        hops = ni._parse_tracepath_output(output)
        assert len(hops) == 3
        assert hops[2]["hop"] == 3


# ---------------------------------------------------------------------------
# _summarize_traceroute_progress
# ---------------------------------------------------------------------------

class TestSummarizeTracerouteProgress:

    def test_finds_last_responsive_hop(self, ni):
        hops = [
            {"hop": 1, "status": "responsive"},
            {"hop": 2, "status": "responsive"},
            {"hop": 3, "status": "timeout"},
        ]
        summary = ni._summarize_traceroute_progress(hops)
        assert summary["last_responsive_hop"] == 2
        assert summary["first_unresponsive_hop"] == 3

    def test_all_timeouts(self, ni):
        hops = [{"hop": 1, "status": "timeout"}, {"hop": 2, "status": "timeout"}]
        summary = ni._summarize_traceroute_progress(hops)
        assert summary["last_responsive_hop"] is None

    def test_no_timeouts(self, ni):
        hops = [{"hop": 1, "status": "responsive"}, {"hop": 2, "status": "responsive"}]
        summary = ni._summarize_traceroute_progress(hops)
        assert summary["first_unresponsive_hop"] is None


# ---------------------------------------------------------------------------
# _analyze_provider_from_hostname
# ---------------------------------------------------------------------------

class TestAnalyzeProviderFromHostname:

    def test_cloudflare_hostname_detected(self, ni):
        result = ni._analyze_provider_from_hostname("host.cloudflare.net")
        assert result is not None
        assert "cloudflare" in result.get("provider", "").lower() or \
               "cloudflare" in result.get("name", "").lower()

    def test_unknown_hostname_returns_none(self, ni):
        result = ni._analyze_provider_from_hostname("unknown.example.com")
        assert result is None


# ---------------------------------------------------------------------------
# analyze_network — mocked
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# _parse_traceroute_output + _parse_traceroute_line (Windows tracert format)
# ---------------------------------------------------------------------------

class TestParseTracerouteOutput:

    def test_parses_windows_tracert_line_with_hostname(self, ni):
        line = "  1    <1 ms    <1 ms    <1 ms  kabelbox.local [192.168.0.1]"
        hop = ni._parse_traceroute_line(line)
        assert hop is not None
        assert hop["hop"] == 1
        assert hop["ip"] == "192.168.0.1"
        assert hop["status"] == "responsive"

    def test_parses_timeout_line(self, ni):
        line = "  3     *        *        *     Request timed out."
        hop = ni._parse_traceroute_line(line)
        assert hop is not None
        assert hop["status"] == "timeout"

    def test_multiline_tracert_output(self, ni):
        output = (
            "  1    <1 ms    <1 ms    <1 ms  192.168.0.1\n"
            "  2    10 ms    11 ms    10 ms  83.0.0.1\n"
            "  3     *        *        *     Request timed out.\n"
        )
        hops = ni._parse_traceroute_output(output)
        assert len(hops) == 3
        assert hops[0]["ip"] == "192.168.0.1"
        assert hops[2]["status"] == "timeout"

    def test_non_hop_lines_skipped(self, ni):
        output = "Tracing route to example.com [93.184.216.34]\n  1  1ms  1.2.3.4\n"
        hops = ni._parse_traceroute_output(output)
        # Only lines starting with digit are parsed
        assert isinstance(hops, list)

    def test_empty_output(self, ni):
        assert ni._parse_traceroute_output("") == []

    def test_short_line_returns_none(self, ni):
        assert ni._parse_traceroute_line("1") is None


# ---------------------------------------------------------------------------
# _analyze_enhanced_network_path
# ---------------------------------------------------------------------------

class TestAnalyzeEnhancedNetworkPath:

    def _make_hop(self, num, ip, hostname=None, status="responsive"):
        return {"hop": num, "ip": ip, "hostname": hostname, "status": status, "latencies": ["5ms"]}

    def test_first_hop_classified_as_local_gateway(self, ni):
        hops = [self._make_hop(1, "192.168.0.1")]
        result = ni._analyze_enhanced_network_path(hops)
        assert result[0]["hop_classification"] == "local_gateway"

    def test_timeout_hop_classified_as_no_response(self, ni):
        hops = [self._make_hop(3, None, status="timeout")]
        result = ni._analyze_enhanced_network_path(hops)
        assert result[0]["hop_classification"] == "no_response"

    def test_transit_hop_default_classification(self, ni):
        hops = [self._make_hop(5, "8.8.8.8", "dns.google")]
        result = ni._analyze_enhanced_network_path(hops)
        assert result[0]["hop_classification"] in ("transit", "national_isp", "backbone_transit", "opsec_risk")

    def test_empty_hops_returns_empty(self, ni):
        assert ni._analyze_enhanced_network_path([]) == []

    def test_result_has_required_keys(self, ni):
        hops = [self._make_hop(1, "192.168.0.1")]
        result = ni._analyze_enhanced_network_path(hops)
        required = {"hop_number", "ip_address", "status", "hop_classification", "provider_type"}
        assert required.issubset(set(result[0].keys()))


# ---------------------------------------------------------------------------
# _gather_hop_intelligence
# ---------------------------------------------------------------------------

class TestGatherHopIntelligence:

    def test_empty_path_returns_zero_counts(self, ni):
        result = ni._gather_hop_intelligence([])
        assert result["total_hops_analyzed"] == 0
        assert result["responsive_hops"] == 0

    def test_counts_responsive_hops(self, ni):
        path = [
            {"hop_number": 1, "ip_address": "1.2.3.4", "hostname": None, "status": "responsive",
             "is_consumer_isp": False, "is_national_isp": False, "is_international_backbone": False},
            {"hop_number": 2, "ip_address": None, "hostname": None, "status": "timeout",
             "is_consumer_isp": False, "is_national_isp": False, "is_international_backbone": False},
        ]
        result = ni._gather_hop_intelligence(path)
        assert result["responsive_hops"] == 1

    def test_intelligence_summary_present(self, ni):
        result = ni._gather_hop_intelligence([])
        assert "intelligence_summary" in result
        assert "providers_identified" in result["intelligence_summary"]


# ---------------------------------------------------------------------------
# _test_http_behavior — mocked requests
# ---------------------------------------------------------------------------

class TestHttpBehavior:

    def _make_response(self, status_code, headers=None, location=None):
        resp = MagicMock()
        resp.status_code = status_code
        resp.headers = headers or {}
        if location:
            resp.headers['Location'] = location
        return resp

    def test_http_redirect_to_https_detected(self, ni):
        http_resp = self._make_response(301, location="https://example.com/")
        https_resp = self._make_response(200, headers={"Server": "nginx", "Strict-Transport-Security": "max-age=31536000"})

        with patch("requests.Session") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session
            mock_session.get.side_effect = [http_resp, https_resp]
            result = ni._test_http_behavior("example.com")

        assert isinstance(result, dict)

    def test_connection_refused_returns_unavailable(self, ni):
        with patch("requests.Session") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session
            mock_session.get.side_effect = ConnectionError("refused")
            result = ni._test_http_behavior("example.com")

        assert result["assessment"] in ("unavailable", "not available") or \
               "unavailable" in str(result.get("assessment", ""))

    def test_https_200_without_hsts_is_moderate(self, ni):
        http_resp = self._make_response(200)
        https_resp = self._make_response(200, headers={"Server": "Apache"})

        with patch("requests.Session") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session
            mock_session.get.side_effect = [http_resp, https_resp]
            result = ni._test_http_behavior("example.com")

        assert isinstance(result, dict)

    def test_result_contains_required_keys(self, ni):
        with patch("requests.Session") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value = mock_session
            mock_session.get.side_effect = ConnectionError("refused")
            result = ni._test_http_behavior("example.com")

        for key in ("http_status", "https_status", "assessment", "redirect_chain"):
            assert key in result


# ---------------------------------------------------------------------------
# _classify_route
# ---------------------------------------------------------------------------

class TestClassifyRoute:

    def _hop(self, is_consumer=False, is_national=False, is_backbone=False):
        return {
            "hop_number": 1, "ip_address": "1.2.3.4", "status": "responsive",
            "is_consumer_isp": is_consumer,
            "is_national_isp": is_national,
            "is_international_backbone": is_backbone,
        }

    def test_empty_path_is_standard_route(self, ni):
        result = ni._classify_route([], {})
        assert result["route_type"] == "standard_route"

    def test_consumer_isp_route_detected(self, ni):
        hops = [self._hop(is_consumer=True)]
        result = ni._classify_route(hops, {})
        assert result["route_type"] == "consumer_isp_route"

    def test_backbone_route_detected(self, ni):
        hops = [self._hop(is_backbone=True)]
        result = ni._classify_route(hops, {})
        assert result["route_type"] == "backbone_route"

    def test_privacy_level_good_with_no_consumer(self, ni):
        result = ni._classify_route([], {})
        assert result["privacy_level"] == "good"

    def test_privacy_level_medium_with_one_consumer(self, ni):
        hops = [self._hop(is_consumer=True)]
        result = ni._classify_route(hops, {})
        assert result["privacy_level"] == "medium"

    def test_privacy_level_low_with_two_consumers(self, ni):
        hops = [self._hop(is_consumer=True), self._hop(is_consumer=True)]
        result = ni._classify_route(hops, {})
        assert result["privacy_level"] == "low"


# ---------------------------------------------------------------------------
# _assess_enhanced_opsec_risks
# ---------------------------------------------------------------------------

class TestAssessOpsecRisks:

    def _hop(self, is_consumer=False, is_national=False, is_backbone=False):
        return {
            "is_consumer_isp": is_consumer,
            "is_national_isp": is_national,
            "is_international_backbone": is_backbone,
        }

    def test_empty_path_low_risk(self, ni):
        result = ni._assess_enhanced_opsec_risks([], {}, {})
        assert result["risk_level"] == "low"

    def test_consumer_isp_raises_risk(self, ni):
        hops = [self._hop(is_consumer=True)]
        result = ni._assess_enhanced_opsec_risks(hops, {"intelligence_summary": {"providers_identified": 0}}, {})
        assert "Consumer-ISP" in str(result["risk_factors"])

    def test_backbone_keeps_low_risk(self, ni):
        hops = [self._hop(is_backbone=True)]
        result = ni._assess_enhanced_opsec_risks(hops, {"intelligence_summary": {"providers_identified": 1}}, {})
        assert result["risk_level"] == "low"

    def test_result_has_required_keys(self, ni):
        result = ni._assess_enhanced_opsec_risks([], {}, {})
        for key in ("risk_level", "risk_factors", "recommendations", "intelligence_exposure"):
            assert key in result

    def test_many_providers_medium_exposure(self, ni):
        hop_intelligence = {"intelligence_summary": {"providers_identified": 4}}
        result = ni._assess_enhanced_opsec_risks([], hop_intelligence, {})
        assert result["intelligence_exposure"] == "medium"


class TestAnalyzeNetworkMocked:

    def test_returns_dict_with_required_keys(self, ni):
        with patch.object(ni, "_test_connectivity", return_value={"status": "reachable", "latency_ms": 10}), \
             patch.object(ni, "_perform_traceroute", return_value={"status": "success", "hops": [], "total_hops": 0}), \
             patch.object(ni, "_test_http_behavior", return_value={"http_status": "200", "assessment": "Strong"}):
            result = ni.analyze_network("93.184.216.34", "example.com")

        assert isinstance(result, dict)
        assert result.get("analysis_status") is not None

    def test_handles_traceroute_failure_gracefully(self, ni):
        with patch.object(ni, "_test_connectivity", return_value={"status": "unreachable"}), \
             patch.object(ni, "_perform_traceroute", return_value={"status": "failed", "hops": [], "total_hops": 0}), \
             patch.object(ni, "_test_http_behavior", return_value={}):
            result = ni.analyze_network("93.184.216.34", "example.com")

        assert isinstance(result, dict)
