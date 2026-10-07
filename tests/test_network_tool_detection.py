"""Path tool detection must be deterministic and degrade gracefully."""

import platform
from unittest.mock import patch

import pytest

from src.analyzers.network_intelligence import NetworkIntelligence

WHICH = "src.analyzers.network_intelligence.shutil.which"


def test_traceroute_tool_detection():
    ni = NetworkIntelligence()
    tool = ni._detect_traceroute_tool()

    if platform.system().lower() == "windows":
        assert tool in (None, "tracert")
    else:
        assert tool in (None, "tracepath", "traceroute")


def test_traceroute_unavailable_gracefully():
    ni = NetworkIntelligence()
    ni._detect_traceroute_tool = lambda: None

    result = ni._perform_traceroute("8.8.8.8")

    assert result["status"] == "unavailable"
    assert result["hops"] == []
    assert "install" in result.get("error", "").lower()


@pytest.mark.parametrize("installed,expected", [
    ({"tracepath", "traceroute"}, "tracepath"),
    ({"traceroute"}, "traceroute"),
    ({"tracepath"}, "tracepath"),
    (set(), None),
])
def test_linux_prefers_tracepath_then_traceroute(installed, expected):
    ni = NetworkIntelligence()
    ni.is_windows = False
    with patch(WHICH, side_effect=lambda name: f"/usr/bin/{name}" if name in installed else None):
        assert ni._detect_traceroute_tool() == expected


@pytest.mark.parametrize("installed,expected", [({"tracert"}, "tracert"), (set(), None)])
def test_windows_uses_tracert_only(installed, expected):
    ni = NetworkIntelligence()
    ni.is_windows = True
    with patch(WHICH, side_effect=lambda name: name if name in installed else None):
        assert ni._detect_traceroute_tool() == expected


def test_unavailable_tool_never_spawns_process():
    ni = NetworkIntelligence()
    ni.is_windows = False
    with patch(WHICH, return_value=None), \
         patch("src.analyzers.network_intelligence.subprocess.Popen") as popen:
        result = ni._perform_traceroute("192.0.2.1")
    popen.assert_not_called()
    assert result["status"] == "unavailable"
    assert result["total_hops"] == 0


def test_unavailable_tool_is_rendered_as_unavailable_not_failed(capsys):
    from src.core.result_formatter import _display_traceroute_details
    _display_traceroute_details(
        {"status": "unavailable", "error": "Neither tracepath nor traceroute is installed. "
                                           "Install with: sudo apt install iputils-tracepath traceroute",
         "hops": [], "total_hops": 0}, [])
    out = capsys.readouterr().out
    assert "UNAVAILABLE" in out and "FAILED" not in out
    assert "apt install" in out
