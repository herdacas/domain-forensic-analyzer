"""Unit tests for metadata collection functions."""

import pytest
from unittest.mock import patch, MagicMock
from src.core.metadata import (
    get_local_ip,
    get_system_metadata,
    assess_opsec_risk,
    detect_tunnel_interface,
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


@pytest.fixture
def no_tunnel():
    with patch("src.core.metadata.detect_tunnel_interface", return_value=None):
        yield


@pytest.mark.usefixtures("no_tunnel")
class TestAssessOpsecRisk:

    def test_nat_detection(self):
        result = assess_opsec_risk("1.2.3.4", "192.168.0.1")
        assert result["behind_nat"] is True

    def test_nat_alone_does_not_lower_attribution_risk(self):
        # A home router hides nothing: the target still sees its public IP.
        with patch("socket.getfqdn", return_value="dsl.example-isp.net"):
            result = assess_opsec_risk("1.2.3.4", "192.168.0.1")
        assert result["behind_nat"] is True
        assert result["attribution_risk"] == "MEDIUM"
        assert result["vpn_signal"] is None

    def test_direct_connection_medium_risk(self):
        result = assess_opsec_risk("1.2.3.4", "1.2.3.4")
        assert result["behind_nat"] is False
        assert result["attribution_risk"] == "MEDIUM"

    def test_public_172_address_is_not_nat(self):
        # Only 172.16.0.0/12 is private; 172.217.x.x is public.
        result = assess_opsec_risk("1.2.3.4", "172.217.1.1")
        assert result["behind_nat"] is False

    def test_private_172_range_is_nat(self):
        result = assess_opsec_risk("1.2.3.4", "172.20.0.5")
        assert result["behind_nat"] is True

    def test_unknown_local_ip_is_not_nat(self):
        result = assess_opsec_risk("Unknown", "Unknown")
        assert result["behind_nat"] is False

    def test_vpn_detection_via_rdns(self):
        with patch("socket.getfqdn", return_value="vpn.mullvad.net"):
            result = assess_opsec_risk("10.0.0.1", "192.168.0.1")
        assert result["potential_vpn"] is True
        assert result["vpn_signal"] == "rdns"
        assert result["stealth_level"] == "HIGH"
        assert result["attribution_risk"] == "LOW"

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


class TestTunnelSignal:

    def test_tunnel_interface_marks_vpn(self):
        with patch("src.core.metadata.detect_tunnel_interface", return_value="wg0"), \
                patch("socket.getfqdn", return_value="89-38-97-215.example-dc.net"):
            result = assess_opsec_risk("89.38.97.215", "10.2.0.2")
        assert result["potential_vpn"] is True
        assert result["vpn_signal"] == "tunnel_interface"
        assert result["tunnel_interface"] == "wg0"
        assert result["attribution_risk"] == "LOW"
        assert result["stealth_level"] == "HIGH"


def _route_get(stdout):
    return MagicMock(stdout=stdout)


class TestDetectTunnelInterface:

    def test_not_linux_returns_none(self):
        with patch("platform.system", return_value="Windows"), \
                patch("subprocess.run") as run:
            assert detect_tunnel_interface() is None
        run.assert_not_called()

    def test_wireguard_by_link_type(self):
        out = "8.8.8.8 dev dfa0 table 51820 src 10.2.0.2 uid 1004 \\    cache"
        with patch("platform.system", return_value="Linux"), \
                patch("subprocess.run", return_value=_route_get(out)), \
                patch("pathlib.Path.read_text", return_value="65534\n"):
            assert detect_tunnel_interface() == "dfa0"

    def test_tunnel_by_name_when_sysfs_unreadable(self):
        out = "8.8.8.8 dev wg-proton src 10.2.0.2 uid 1004"
        with patch("platform.system", return_value="Linux"), \
                patch("subprocess.run", return_value=_route_get(out)), \
                patch("pathlib.Path.read_text", side_effect=OSError):
            assert detect_tunnel_interface() == "wg-proton"

    def test_ethernet_default_route_is_not_tunnel(self):
        out = "8.8.8.8 via 81.169.192.1 dev eno1 src 81.169.211.133 uid 1004"
        with patch("platform.system", return_value="Linux"), \
                patch("subprocess.run", return_value=_route_get(out)), \
                patch("pathlib.Path.read_text", return_value="1\n"):
            assert detect_tunnel_interface() is None

    def test_ip_command_missing(self):
        with patch("platform.system", return_value="Linux"), \
                patch("subprocess.run", side_effect=FileNotFoundError):
            assert detect_tunnel_interface() is None

    def test_unparseable_output(self):
        with patch("platform.system", return_value="Linux"), \
                patch("subprocess.run", return_value=_route_get("RTNETLINK answers: Network is unreachable")):
            assert detect_tunnel_interface() is None
