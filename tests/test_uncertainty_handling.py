"""Uncertain observations must surface as explicit states, never as false confidence."""

from unittest.mock import MagicMock

import dns.exception

from src.analyzers.dns_analyzer import DNSAnalyzer
from src.core.result_aggregator import ResultAggregator


def test_null_asn_marked_unavailable():
    module_results = {
        "cdn": {
            "analysis_status": "abgeschlossen",
            "asn_info": {"asn": None, "organization": None},
        }
    }
    agg = ResultAggregator()
    result = agg._aggregate_infrastructure(module_results)

    assert result is not None
    assert result.asn_info.get("asn") in ("unavailable", None)
    assert result.asn_info == {"asn": "unavailable", "organization": "unavailable"}
    assert result.confidence.value == "unknown"


def test_present_asn_is_kept():
    result = ResultAggregator()._aggregate_infrastructure({"cdn": {
        "analysis_status": "abgeschlossen",
        "asn_info": {"asn": "AS15133", "organization": "Edgecast"},
    }})
    assert result.asn_info == {"asn": "AS15133", "organization": "Edgecast"}
    assert result.confidence.value == "medium"


def _analyzer_with_dnssec_answers(monkeypatch, ds, dnskey):
    analyzer = DNSAnalyzer.__new__(DNSAnalyzer)
    answers = {"DS": ds, "DNSKEY": dnskey}
    monkeypatch.setattr(analyzer, "_query_dnssec_type",
                        lambda domain, rtype: answers[rtype], raising=False)
    return analyzer


def test_dnssec_query_failure_is_inconclusive_with_note(monkeypatch):
    analyzer = _analyzer_with_dnssec_answers(monkeypatch, ([], True), ([], False))
    dnssec = analyzer._analyze_dnssec("example.com")["dnssec"]
    assert dnssec["status"] == "inconclusive"
    assert dnssec["note"] == "Status may vary across DNS servers"


def test_dnssec_clean_absence_is_not_detected_without_note(monkeypatch):
    analyzer = _analyzer_with_dnssec_answers(monkeypatch, ([], False), ([], False))
    dnssec = analyzer._analyze_dnssec("example.com")["dnssec"]
    assert dnssec["status"] == "not_detected"
    assert dnssec["note"] == ""


def test_dnssec_records_win_over_partial_failure(monkeypatch):
    analyzer = _analyzer_with_dnssec_answers(monkeypatch, ([MagicMock()], False), ([], True))
    assert analyzer._analyze_dnssec("example.com")["dnssec"]["status"] == "enabled"


def test_inconclusive_dnssec_lowers_confidence_and_warns():
    module_results = {"dns": {"analysis_status": "abgeschlossen",
                              "dnssec": {"status": "inconclusive"}}}
    result = ResultAggregator().aggregate_results("example.com", module_results, 0)
    assert result.confidence_metrics["dns"].value == "low"
    assert any("DNSSEC check inconclusive" in w for w in result.warnings)


def test_timeout_exception_maps_to_query_failed(monkeypatch):
    analyzer = DNSAnalyzer.__new__(DNSAnalyzer)
    resolver = MagicMock()
    resolver.resolve.side_effect = dns.exception.Timeout()
    monkeypatch.setattr(analyzer, "_create_resolver", lambda: resolver, raising=False)
    assert analyzer._query_dnssec_type("example.com", "DS") == ([], True)
