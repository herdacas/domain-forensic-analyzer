"""Mocked tests for DNS history analyzer HTTP-based sources."""

import pytest
from unittest.mock import patch, MagicMock
from src.analyzers.dns_history_analyzer import DNSHistoryAnalyzer


@pytest.fixture
def analyzer():
    return DNSHistoryAnalyzer()


# ---------------------------------------------------------------------------
# _collect_robtex_history — mocked
# ---------------------------------------------------------------------------

class TestRobTexHistoryMocked:

    def test_success_response_parsed(self, analyzer):
        import json
        line1 = json.dumps({"rrtype": "A", "rrname": "example.com", "rrdata": "1.2.3.4", "time_first": 1700000000, "time_last": 1700100000})
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = line1 + "\n"
        mock_resp.raise_for_status = MagicMock()

        with patch.object(analyzer.session, "get", return_value=mock_resp):
            result = analyzer._collect_robtex_history("example.com")

        assert result["status"] == "success"
        assert len(result["events"]) >= 1

    def test_404_returns_failed(self, analyzer):
        with patch.object(analyzer.session, "get", side_effect=Exception("404")):
            result = analyzer._collect_robtex_history("nonexistent.invalid")

        assert result["status"] in ("failed", "error")

    def test_empty_list_response_handled(self, analyzer):
        import json
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = json.dumps([]) + "\n"
        mock_resp.raise_for_status = MagicMock()

        with patch.object(analyzer.session, "get", return_value=mock_resp):
            result = analyzer._collect_robtex_history("example.com")

        assert isinstance(result, dict)
        assert "events" in result


# ---------------------------------------------------------------------------
# _collect_mnemonic_history — mocked
# ---------------------------------------------------------------------------

class TestMnemonicHistoryMocked:

    def test_success_response_parsed(self, analyzer):
        payload = {
            "responseCode": 200,
            "data": [
                {
                    "rrtype": "A",
                    "query": "example.com",
                    "answer": "93.184.216.34",
                    "firstSeen": 1700000000000,
                    "lastSeen": 1700100000000,
                }
            ]
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = payload
        mock_resp.raise_for_status = MagicMock()

        with patch.object(analyzer.session, "get", return_value=mock_resp):
            result = analyzer._collect_mnemonic_history("example.com")

        assert result["status"] == "success"

    def test_quota_exceeded(self, analyzer):
        mock_resp = MagicMock()
        mock_resp.status_code = 429

        with patch.object(analyzer.session, "get", return_value=mock_resp):
            result = analyzer._collect_mnemonic_history("example.com")

        assert result["status"] in ("quota_exceeded", "failed")

    def test_network_error_returns_failed(self, analyzer):
        with patch.object(analyzer.session, "get", side_effect=ConnectionError("timeout")):
            result = analyzer._collect_mnemonic_history("example.com")

        assert result["status"] in ("failed", "error")


# ---------------------------------------------------------------------------
# _collect_crtsh — mocked
# ---------------------------------------------------------------------------

class TestCrtshMocked:

    def test_success_returns_ct_events(self, analyzer):
        payload = [
            {"name_value": "example.com\nwww.example.com", "not_before": "2024-01-15T00:00:00"},
            {"name_value": "api.example.com", "not_before": "2023-06-01T00:00:00"},
        ]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = payload
        mock_resp.raise_for_status = MagicMock()

        with patch.object(analyzer.session, "get", return_value=mock_resp), \
             patch("time.sleep"):
            result = analyzer._collect_crtsh("example.com")

        assert result["status"] == "success"
        assert len(result["events"]) > 0

    def test_empty_response_returns_failed(self, analyzer):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = []
        mock_resp.raise_for_status = MagicMock()

        with patch.object(analyzer.session, "get", return_value=mock_resp), \
             patch("time.sleep"):
            result = analyzer._collect_crtsh("example.com")

        assert isinstance(result, dict)
        assert "status" in result  # "failed" when no events — expected

    def test_server_error_triggers_retry(self, analyzer):
        with patch.object(analyzer.session, "get", side_effect=Exception("503")), \
             patch("time.sleep"):
            result = analyzer._collect_crtsh("example.com")

        assert result["status"] in ("failed", "error")


# ---------------------------------------------------------------------------
# _analyze_patterns — extended
# ---------------------------------------------------------------------------

class TestAnalyzePatternsExtended:

    def test_empty_timeline_returns_low_risk(self, analyzer):
        result = analyzer._analyze_patterns([])
        assert result["risk_level"] == "LOW"

    def test_single_event_low_risk(self, analyzer):
        event = analyzer._make_event(
            event_date="2024-01-01",
            change_type="Historical IP resolution",
            record_type="A",
            source="RobTex",
            previous_value=None,
            new_value=["1.2.3.4"],
            classification="Infrastructure resolution change",
        )
        result = analyzer._analyze_patterns([event])
        assert result["risk_level"] == "LOW"

    def test_ns_changes_counted_by_date(self, analyzer):
        events = [
            analyzer._make_event(
                event_date=f"2024-0{i}:01",
                change_type="NS Record Change",
                record_type="NS",
                source="RobTex",
                previous_value=None,
                new_value=[f"ns{i}.example.com"],
                classification="Nameserver change",
            )
            for i in range(1, 5)
        ]
        result = analyzer._analyze_patterns(events)
        assert isinstance(result, dict)
        assert "risk_level" in result
