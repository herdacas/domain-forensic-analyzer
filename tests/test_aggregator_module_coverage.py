"""Every executed module must be represented in aggregation and provenance."""

from src.core.domain_analyzer import DomainAnalyzer
from src.core.result_aggregator import DataSource, ResultAggregator

ALL_MODULES = {"dns", "whois", "dns_history", "cdn", "network",
               "subdomain", "ssl", "securitytrails", "abuseipdb",
               "virustotal", "ip_history"}


def test_all_11_modules_in_supported_list():
    agg = ResultAggregator()
    assert set(agg.supported_modules) == ALL_MODULES
    assert len(agg.supported_modules) == 11


def test_supported_modules_match_execution_order():
    """Aggregator and orchestrator must not drift apart again."""
    analyzer = DomainAnalyzer()
    assert ResultAggregator().supported_modules == analyzer.module_execution_order


def test_datasource_enum_has_all_modules():
    sources = {s.value for s in DataSource}
    assert len(sources) >= 11
    for name in ("SSL_ANALYSIS", "ABUSEIPDB_REPUTATION",
                 "VIRUSTOTAL_REPUTATION", "IP_HISTORY"):
        assert hasattr(DataSource, name)


def test_identify_intelligence_sources_covers_all_modules():
    module_results = {name: {"analysis_status": "abgeschlossen"} for name in ALL_MODULES}
    agg = ResultAggregator()
    sources = agg._identify_intelligence_sources(module_results)
    assert len(sources) >= 8
    assert len(sources) == 11
    assert len(set(sources)) == 11


def test_demo_results_are_not_live_provenance():
    module_results = {
        "virustotal": {"analysis_status": "demo_abgeschlossen"},
        "abuseipdb": {"analysis_status": "skipped"},
        "ssl": {"analysis_status": "abgeschlossen"},
    }
    sources = ResultAggregator()._identify_intelligence_sources(module_results)
    assert sources == [DataSource.SSL_ANALYSIS]
