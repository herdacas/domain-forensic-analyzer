from src.core.result_aggregator import create_result_aggregator


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
