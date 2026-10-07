"""Aggregator must read the connectivity/traceroute fields the network module emits."""

from src.analyzers.network_intelligence import NetworkIntelligence
from src.core.result_aggregator import ResultAggregator


def test_network_connectivity_fields_match():
    module_results = {
        "network": {
            "analysis_status": "abgeschlossen",
            "connectivity_test": {
                "ping_reachable": True,
                "http_accessible": False,
                "https_accessible": True,
                "response_times": {"https": "25ms"},
            },
            "traceroute_data": {
                "total_hops": 10,
                "responsive_hops": 8,
            },
            "opsec_assessment": {"risk_level": "low"},
        }
    }
    agg = ResultAggregator()
    result = agg._aggregate_network_intelligence(module_results)

    assert result is not None
    assert result.connectivity_status != "unknown"
    assert result.connectivity_status == "reachable"
    assert result.total_hops == 10
    assert result.responsive_hops == 8
    assert result.opsec_risk_level == "low"


def test_network_missing_fields_handled_gracefully():
    module_results = {
        "network": {
            "analysis_status": "abgeschlossen",
            "connectivity_test": {},
            "traceroute_data": {},
            "opsec_assessment": {},
        }
    }
    agg = ResultAggregator()
    result = agg._aggregate_network_intelligence(module_results)

    assert result is not None
    assert result.connectivity_status in ["unreachable", "unknown"]
    assert result.total_hops == 0
    assert result.responsive_hops == 0


def test_all_probes_failed_is_unreachable():
    module_results = {"network": {
        "analysis_status": "abgeschlossen",
        "connectivity_test": {"ping_reachable": False, "http_accessible": False,
                              "https_accessible": False},
    }}
    result = ResultAggregator()._aggregate_network_intelligence(module_results)
    assert result.connectivity_status == "unreachable"


def test_http_only_is_http_accessible():
    module_results = {"network": {
        "analysis_status": "abgeschlossen",
        "connectivity_test": {"ping_reachable": False, "http_accessible": False,
                              "https_accessible": True},
    }}
    result = ResultAggregator()._aggregate_network_intelligence(module_results)
    assert result.connectivity_status == "http_accessible"


def test_emitted_connectivity_keys_are_the_ones_aggregator_reads(monkeypatch):
    """Contract test: real _test_connectivity output feeds the aggregator."""
    ni = NetworkIntelligence()
    monkeypatch.setattr(ni, "_test_ping", lambda ip: {"reachable": False, "avg_time": None})
    monkeypatch.setattr(ni, "_test_http_connectivity",
                        lambda domain: {"http_accessible": False, "https_accessible": True})
    connectivity = ni._test_connectivity("192.0.2.1", "example.com")
    assert {"ping_reachable", "http_accessible", "https_accessible"} <= set(connectivity)
    result = ResultAggregator()._aggregate_network_intelligence({"network": {
        "analysis_status": "abgeschlossen", "connectivity_test": connectivity}})
    assert result.connectivity_status == "http_accessible"


def test_traceroute_summary_emits_responsive_hop_count():
    ni = NetworkIntelligence()
    summary = ni._summarize_traceroute_progress([
        {"hop": 1, "status": "responsive"},
        {"hop": 2, "status": "timeout"},
        {"hop": 3, "status": "responsive"},
    ])
    assert summary["responsive_hops"] == 2
