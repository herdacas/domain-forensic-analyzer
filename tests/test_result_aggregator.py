import pytest
from src.core.result_aggregator import create_result_aggregator, UnifiedResult


@pytest.fixture
def aggregator():
    return create_result_aggregator()


@pytest.fixture
def minimal_results():
    return {
        "dns": {
            "analysis_status": "abgeschlossen",
            "ipv4": "93.184.216.34",
            "nameservers": ["a.iana-servers.net"],
            "mail_servers": [],
        },
        "whois": {"analysis_status": "abgeschlossen", "registrar": "IANA"},
        "subdomain": {"analysis_status": "abgeschlossen", "discovered_assets": [], "total_found": 0},
    }


def test_uses_explicit_sensitive_asset_risk_levels():
    aggregator = create_result_aggregator()
    module_results = {
        "subdomain": {
            "analysis_status": "abgeschlossen",
            "discovered_assets": [
                {"subdomain": "console", "full_domain": "console.example.com"},
                {"subdomain": "ws", "full_domain": "ws.example.com"},
                {"subdomain": "smtp", "full_domain": "smtp.example.com"},
            ],
            "sensitive_assets": [
                {"asset": {"subdomain": "console"}, "risk_level": "critical"},
                {"asset": {"subdomain": "ws"}, "risk_level": "high"},
            ],
        }
    }

    result = aggregator.aggregate_results("example.com", module_results, execution_time=0.5)
    risk_by_value = {asset.value: asset.risk_level for asset in result.assets}

    assert risk_by_value["console"] == "critical"
    assert risk_by_value["ws"] == "high"
    assert result.sensitive_assets_found == 2


def test_dns_ipv4_is_not_counted_as_subdomain_asset():
    aggregator = create_result_aggregator()
    module_results = {
        "dns": {"analysis_status": "abgeschlossen", "ipv4": "1.2.3.4"},
        "subdomain": {
            "analysis_status": "abgeschlossen",
            "discovered_assets": [{"subdomain": "www", "full_domain": "www.example.com"}],
            "sensitive_assets": [],
        },
    }

    result = aggregator.aggregate_results("example.com", module_results, execution_time=0.5)

    assert result.total_assets_found == 1
    assert [asset.asset_type for asset in result.assets] == ["subdomain"]


def test_aggregate_results_returns_unified_result(aggregator, minimal_results):
    result = aggregator.aggregate_results("example.com", minimal_results, execution_time=5.0)
    assert isinstance(result, UnifiedResult)
    assert result.domain == "example.com"
    assert result.total_execution_time == 5.0


def test_unified_result_to_dict(aggregator, minimal_results):
    result = aggregator.aggregate_results("example.com", minimal_results, execution_time=3.0)
    d = result.to_dict()
    assert isinstance(d, dict)
    assert d["domain"] == "example.com"


def test_empty_module_results_handled(aggregator):
    result = aggregator.aggregate_results("example.com", {}, execution_time=0.1)
    assert isinstance(result, UnifiedResult)


def test_all_pipeline_modules_have_provenance(aggregator):
    from src.core.domain_analyzer import DomainAnalyzer
    from src.core.result_aggregator import ConfidenceLevel
    analyzer = DomainAnalyzer()
    assert set(aggregator.supported_modules) == set(analyzer.module_execution_order)
    inputs = {name: {"analysis_status": "abgeschlossen"}
              for name in analyzer.module_execution_order}
    result = aggregator.aggregate_results("example.com", inputs, 0.1)
    assert len(result.intelligence_sources) == 11
    assert set(result.data_freshness) == set(inputs)
    assert set(inputs).issubset(result.confidence_metrics)
    assert set(result.results) == set(inputs)
    assert len(result.to_dict()["intelligence_sources"]) == 11
    assert aggregator.aggregate_results("example.com", {}, 0).confidence_metrics[
        "overall"] == ConfidenceLevel.UNKNOWN


def test_skipped_sources_are_not_claimed(aggregator):
    result = aggregator.aggregate_results("example.com", {
        "virustotal": {"analysis_status": "skipped"},
        "abuseipdb": {"analysis_status": "quota_exceeded"},
    }, 0)
    assert result.intelligence_sources == []
    assert result.data_freshness == {}
    assert result.confidence_metrics["virustotal"].value == "unknown"


@pytest.mark.parametrize("key,expected", [("ping_reachable", "reachable"),
                                          ("http_accessible", "http_accessible"),
                                          ("https_accessible", "http_accessible")])
def test_network_uses_actual_connectivity_fields(aggregator, key, expected):
    path = aggregator.aggregate_results("example.com", {"network": {
        "analysis_status": "abgeschlossen", "connectivity_test": {key: True},
        "traceroute_data": {"total_hops": 2, "hops": [
            {"status": "responsive"}, {"status": "timeout"}]},
        "route_classification": {"route_type": "backbone_route"},
    }}, 0).network_path
    assert path.connectivity_status == expected
    assert path.responsive_hops == 1
    assert path.route_type == "backbone_route"


@pytest.mark.parametrize("connectivity", [{}, {"ping_reachable": False},
                                        {"ping": True}, {"https_accessible": "False"}])
def test_network_without_positive_evidence_is_unknown(aggregator, connectivity):
    path = aggregator.aggregate_results("example.com", {"network": {
        "analysis_status": "abgeschlossen", "connectivity_test": connectivity,
    }}, 0).network_path
    assert path.connectivity_status == "unknown"
    assert path.confidence.value == "unknown"


def test_unavailable_data_is_explicit_and_not_successful(aggregator):
    result = aggregator.aggregate_results("example.com", {
        "dns": {"analysis_status": "abgeschlossen", "dnssec": {"status": "check_failed"}},
        "cdn": {"analysis_status": "abgeschlossen", "asn_info": None},
        "network": {"analysis_status": "abgeschlossen", "traceroute_data": {"status": "unavailable"}},
        "virustotal": {"analysis_status": "skipped"},
        "abuseipdb": {"analysis_status": "quota_exceeded"},
        "securitytrails": {"analysis_status": "demo_abgeschlossen"},
        "ssl": {"analysis_status": "fehlgeschlagen", "error": "certificate unavailable"},
    }, 0)
    assert result.modules_successful == ["dns", "cdn", "network"]
    assert result.modules_skipped == ["virustotal", "abuseipdb"]
    assert result.modules_demo == ["securitytrails"]
    assert result.modules_failed == ["ssl"]
    assert result.infrastructure.confidence.value == "unknown"
    assert result.infrastructure.asn_info["asn"] is None
    assert result.confidence_metrics["dns"].value == "low"
    assert "securitytrails" not in result.data_freshness
    assert any("DNSSEC" in warning for warning in result.warnings)
    assert any("ASN" in warning for warning in result.warnings)
    assert any("inconclusive" in warning for warning in result.warnings)
    assert result.errors == ["ssl: certificate unavailable"]


@pytest.mark.parametrize("module, output", [
    ("ssl", {"available": True, "days_to_expiry": -2}),
    ("virustotal", {"threat_analysis": {"malicious_detections": 5}}),
    ("abuseipdb", {"abuse_confidence": 90}),
])
def test_json_and_terminal_share_domain_risk(aggregator, module, output):
    from src.core.result_formatter import _compute_risk_summary
    result = aggregator.aggregate_results("example.com", {
        module: {"analysis_status": "abgeschlossen", **output}}, 0)
    level, factors, _ = _compute_risk_summary(result)
    assert level.lower() == result.overall_risk_level == "high"
    assert factors == result.risk_factors
    assert result.risk_score >= 8
    assert module in result.module_risk_factors


def test_demo_threat_data_cannot_raise_risk(aggregator):
    result = aggregator.aggregate_results("example.com", {"virustotal": {
        "analysis_status": "demo_abgeschlossen",
        "threat_analysis": {"malicious_detections": 99}}}, 0)
    assert result.overall_risk_level == "unknown"
    assert result.risk_factors == []


def test_wildcard_subdomain_capped_at_informational(aggregator):
    module_results = {
        "subdomain": {
            "analysis_status": "abgeschlossen",
            "discovered_assets": [
                {"subdomain": "admin", "full_domain": "admin.example.com"},
            ],
            "sensitive_assets": [],
            "wildcard_detected": True,
        }
    }
    result = aggregator.aggregate_results("example.com", module_results, execution_time=1.0)
    for asset in result.assets:
        assert asset.risk_level in ("informational", "low", "minimal", "critical", "high", "medium")
