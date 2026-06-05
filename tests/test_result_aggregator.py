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
