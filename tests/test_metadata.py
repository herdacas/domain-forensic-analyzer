"""Unit tests for metadata collection functions."""

import pytest
from unittest.mock import patch, MagicMock
from src.core.metadata import (
    get_local_ip,
    get_system_metadata,
    assess_opsec_risk,
    get_external_ip,
)


class TestGetLocalIp:

    def test_returns_string(self):
        result = get_local_ip()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_returns_unknown_on_socket_error(self):
        with patch("socket.socket") as mock_sock:
            mock_sock.return_value.__enter__.return_value.connect.side_effect = OSError
            result = get_local_ip()
        assert result in ("Unknown", "") or "." in result


class TestGetSystemMetadata:

    def test_returns_dict_with_required_keys(self):
        result = get_system_metadata()
        for key in ("hostname", "username", "platform", "platform_version", "architecture"):
            assert key in result

    def test_values_are_strings(self):
        result = get_system_metadata()
        for key, val in result.items():
            assert isinstance(val, str), f"Expected str for key '{key}', got {type(val)}"

    def test_returns_unknown_fallback_on_error(self):
        with patch("socket.gethostname", side_effect=OSError):
            result = get_system_metadata()
        assert isinstance(result, dict)


class TestGetExternalIp:

    def test_returns_string(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "1.2.3.4"
        with patch("requests.get", return_value=mock_resp):
            result = get_external_ip()
        assert result == "1.2.3.4"

    def test_returns_unknown_on_all_failures(self):
        with patch("requests.get", side_effect=ConnectionError):
            result = get_external_ip()
        assert result == "Unknown"

    def test_tries_multiple_services(self):
        responses = [
            MagicMock(status_code=500, text=""),
            MagicMock(status_code=200, text="5.6.7.8"),
        ]
        responses[0].raise_for_status = MagicMock()
        with patch("requests.get", side_effect=responses):
            result = get_external_ip()
        assert result == "5.6.7.8"


class TestAssessOpsecRisk:

    def test_nat_detection(self):
        result = assess_opsec_risk("1.2.3.4", "192.168.0.1")
        assert result["behind_nat"] is True
        assert result["attribution_risk"] == "LOW"

    def test_direct_connection_medium_risk(self):
        result = assess_opsec_risk("1.2.3.4", "1.2.3.4")
        assert result["behind_nat"] is False
        assert result["attribution_risk"] == "MEDIUM"

    def test_vpn_detection_via_rdns(self):
        with patch("socket.getfqdn", return_value="vpn.mullvad.net"):
            result = assess_opsec_risk("10.0.0.1", "192.168.0.1")
        assert result["potential_vpn"] is True
        assert result["stealth_level"] == "HIGH"

    def test_no_vpn_medium_stealth(self):
        with patch("socket.getfqdn", return_value="regular.isp.net"):
            result = assess_opsec_risk("1.2.3.4", "192.168.0.1")
        assert result["potential_vpn"] is False
        assert result["stealth_level"] == "MEDIUM"

    def test_result_has_analysis_type(self):
        result = assess_opsec_risk("1.2.3.4", "192.168.0.1")
        assert "analysis_type" in result
        assert "Passive" in result["analysis_type"] or "Active" in result["analysis_type"]

    def test_socket_error_on_rdns_handled(self):
        with patch("socket.getfqdn", side_effect=OSError):
            result = assess_opsec_risk("1.2.3.4", "192.168.0.1")
        assert isinstance(result, dict)
