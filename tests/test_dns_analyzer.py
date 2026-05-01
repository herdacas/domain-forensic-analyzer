import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.analyzers.dns_analyzer import DNSAnalyzer


class FakeTXTRecord:
    def __init__(self, parts):
        self.strings = parts


class FakeSOARecord:
    def __init__(self):
        self.mname = "ns1.example.net."
        self.rname = "hostmaster.example.net."
        self.serial = 2026042201
        self.refresh = 3600
        self.retry = 900
        self.expire = 1209600
        self.minimum = 300


class FakeCAARecord:
    def __init__(self, flags, tag, value):
        self.flags = flags
        self.tag = tag
        self.value = value


def test_normalize_txt_record_joins_chunks():
    analyzer = DNSAnalyzer()
    record = FakeTXTRecord([b"v=spf1 ", b"include:_spf.example.net", b" -all"])

    assert analyzer._normalize_txt_record(record) == "v=spf1 include:_spf.example.net -all"


def test_spf_detection_uses_existing_txt_records():
    analyzer = DNSAnalyzer()

    result = analyzer._analyze_spf_record(
        ["google-site-verification=abc", "v=spf1 include:_spf.example.net -all"]
    )

    assert result["spf_record"] == "v=spf1 include:_spf.example.net -all"


def test_caa_field_normalization_decodes_bytes():
    analyzer = DNSAnalyzer()

    assert analyzer._normalize_caa_field(b"issue") == "issue"
    assert analyzer._normalize_caa_field(b"letsencrypt.org") == "letsencrypt.org"


def test_spf_policy_analysis_detects_hard_fail_and_includes():
    analyzer = DNSAnalyzer()

    result = analyzer._analyze_spf_policy(
        "v=spf1 include:_spf.example.net include:mail.example.net ip4:192.0.2.0/24 -all"
    )

    assert result["spf_analysis"]["status"] == "configured"
    assert result["spf_analysis"]["all_mechanism"] == "hard_fail"
    assert result["spf_analysis"]["includes_count"] == 2


def test_dmarc_analysis_extracts_policy_and_reporting():
    analyzer = DNSAnalyzer()

    result = analyzer._analyze_dmarc_configuration(
        "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; adkim=s; aspf=s"
    )

    assert result["dmarc_analysis"]["status"] == "configured"
    assert result["dmarc_analysis"]["policy"] == "quarantine"
    assert result["dmarc_analysis"]["reporting_enabled"] is True
    assert result["dmarc_analysis"]["alignment"]["adkim"] == "s"


def test_dkim_selector_discovery_uses_common_selector_list(monkeypatch):
    analyzer = DNSAnalyzer()

    def fake_resolve(name, record_type, nameservers=None):
        if name == "selector1._domainkey.example.com" and record_type == "TXT":
            return [FakeTXTRecord([b"v=DKIM1; k=rsa; p=ABC123"])]
        return []

    monkeypatch.setattr(analyzer, "_resolve_dns_records", fake_resolve)

    result = analyzer._analyze_dkim_selectors("example.com")

    assert result["dkim"]["status"] == "selectors_found"
    assert result["dkim"]["selectors"][0]["selector"] == "selector1"


def test_dns_configuration_assessment_reports_baseline_gaps():
    analyzer = DNSAnalyzer()

    result = analyzer._assess_dns_configuration(
        {
            "status": "configured",
            "all_mechanism": "soft_fail",
        },
        {
            "status": "configured",
            "policy": "none",
            "reporting_enabled": False,
        },
        {"status": "not_detected"},
        {"status": "not_detected"},
        {"status": "not_allowed"},
        [],
    )

    assert result["dns_configuration_assessment"]["status"] == "baseline_gaps"
    assert "DMARC is monitor-only" in result["dns_configuration_assessment"]["findings"]


def test_dns_configuration_assessment_can_be_partially_hardened():
    analyzer = DNSAnalyzer()

    result = analyzer._assess_dns_configuration(
        {
            "status": "configured",
            "all_mechanism": "hard_fail",
        },
        {
            "status": "configured",
            "policy": "quarantine",
            "reporting_enabled": True,
        },
        {"status": "not_detected"},
        {"status": "not_detected"},
        {"status": "not_allowed"},
        [{"tag": "issue", "value": "letsencrypt.org"}],
    )

    assert result["dns_configuration_assessment"]["status"] == "partially_hardened"


def test_dns_forensics_bundle_builds_expected_records(monkeypatch):
    analyzer = DNSAnalyzer()

    fake_answers = {
        ("example.com", "SOA"): [FakeSOARecord()],
        ("example.com", "TXT"): [FakeTXTRecord([b"v=spf1 include:_spf.example.net -all"])],
        ("_dmarc.example.com", "TXT"): [FakeTXTRecord([b"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"])],
        ("selector1._domainkey.example.com", "TXT"): [FakeTXTRecord([b"v=DKIM1; p=ABC123"])],
        ("example.com", "CAA"): [FakeCAARecord(0, "issue", "letsencrypt.org")],
        ("example.com", "DS"): ["ds-present"],
        ("example.com", "DNSKEY"): [],
        ("ns1.example.net", "A"): [],
    }

    def fake_resolve(name, record_type, nameservers=None):
        return fake_answers.get((name, record_type), [])

    monkeypatch.setattr(analyzer, "_resolve_dns_records", fake_resolve)

    soa = analyzer._analyze_soa_record("example.com")
    txt = analyzer._analyze_txt_records("example.com")
    spf = analyzer._analyze_spf_record(txt["txt_records"])
    spf_analysis = analyzer._analyze_spf_policy(spf["spf_record"])
    dmarc = analyzer._analyze_dmarc_record("example.com")
    dmarc_analysis = analyzer._analyze_dmarc_configuration(dmarc["dmarc_record"])
    dkim = analyzer._analyze_dkim_selectors("example.com")
    caa = analyzer._analyze_caa_records("example.com")
    dnssec = analyzer._analyze_dnssec("example.com")
    axfr = analyzer._analyze_zone_transfer("example.com", ["ns1.example.net"])
    dns_assessment = analyzer._assess_dns_configuration(
        spf_analysis["spf_analysis"],
        dmarc_analysis["dmarc_analysis"],
        dkim["dkim"],
        dnssec["dnssec"],
        axfr["zone_transfer"],
        caa["caa_records"],
    )

    assert soa["soa_record"]["primary_nameserver"] == "ns1.example.net"
    assert txt["txt_records"] == ["v=spf1 include:_spf.example.net -all"]
    assert spf["spf_record"].startswith("v=spf1")
    assert spf_analysis["spf_analysis"]["all_mechanism"] == "hard_fail"
    assert dmarc["dmarc_record"].startswith("v=DMARC1")
    assert dmarc_analysis["dmarc_analysis"]["policy"] == "reject"
    assert dkim["dkim"]["status"] == "selectors_found"
    assert caa["caa_records"][0]["value"] == "letsencrypt.org"
    assert dnssec["dnssec"]["status"] == "enabled"
    assert axfr["zone_transfer"]["status"] == "not_allowed"
    assert dns_assessment["dns_configuration_assessment"]["status"] == "well_hardened"
