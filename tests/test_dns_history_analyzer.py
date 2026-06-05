from src.analyzers.dns_history_analyzer import DNSHistoryAnalyzer


def test_make_event_produces_required_keys():
    analyzer = DNSHistoryAnalyzer()
    event = analyzer._make_event(
        event_date="2024-06-01T00:00:00+00:00",
        change_type="Historical IP resolution",
        record_type="A",
        source="VirusTotal",
        previous_value=None,
        new_value=["192.0.2.10"],
        classification="Infrastructure resolution change",
    )
    for key in ("date", "change_type", "record_type", "source", "new", "classification"):
        assert key in event, f"Expected key '{key}' missing from event"
    assert event["record_type"] == "A"
    assert event["source"] == "VirusTotal"
    assert event["new"] == ["192.0.2.10"]


def test_dns_history_timeline_span_counts_days():
    analyzer = DNSHistoryAnalyzer()
    timeline = [
        {"date": "2024-01-01T00:00:00+00:00"},
        {"date": "2024-01-31T00:00:00+00:00"},
    ]

    span = analyzer._calculate_timeline_span(timeline)

    assert span["start_date"] == "2024-01-01"
    assert span["end_date"] == "2024-01-31"
    assert span["days"] == 30


def test_dns_history_pattern_analysis_flags_rapid_changes():
    analyzer = DNSHistoryAnalyzer()
    timeline = [
        analyzer._make_event(
            event_date=f"2024-01-{day:02d}T00:00:00+00:00",
            change_type="Historical IP resolution",
            record_type="A",
            source="SecurityTrails",
            previous_value=None,
            new_value=[f"192.0.2.{day}"],
            classification="Infrastructure resolution change",
        )
        for day in range(1, 16)
    ]

    analysis = analyzer._analyze_patterns(timeline)

    assert analysis["risk_level"] in {"MEDIUM", "HIGH"}
    assert "rapid DNS change pattern" in analysis["suspicious_patterns"]


def test_virustotal_history_groups_same_day_resolutions():
    analyzer = DNSHistoryAnalyzer()
    payload = {
        "data": [
            {"attributes": {"ip_address": "142.250.158.100", "date": 1777593600}},
            {"attributes": {"ip_address": "142.250.158.102", "date": 1777593600}},
            {"attributes": {"ip_address": "142.250.158.113", "date": 1777593600}},
            {"attributes": {"ip_address": "142.250.158.138", "date": 1777593600}},
            {"attributes": {"ip_address": "142.250.158.139", "date": 1777593600}},
        ]
    }

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return payload

    class FakeSession:
        def get(self, *args, **kwargs):
            return FakeResponse()

    analyzer.virustotal_api_key = "valid_key_123456789"
    analyzer.session = FakeSession()

    result = analyzer._collect_virustotal_history("google.com")

    assert result["status"] == "success"
    assert len(result["events"]) == 1
    assert result["events"][0]["classification"] == "Load-balanced resolution set"
    assert len(result["events"][0]["new"]) == 5


def test_pattern_analysis_does_not_flag_load_balanced_sets_as_rapid_change():
    analyzer = DNSHistoryAnalyzer()
    timeline = [
        analyzer._make_event(
            event_date="2026-05-01",
            change_type="Historical IP resolution",
            record_type="A",
            source="VirusTotal",
            previous_value=None,
            new_value=[
                "142.250.158.100",
                "142.250.158.102",
                "142.250.158.113",
                "142.250.158.138",
                "142.250.158.139",
            ],
            classification="Load-balanced resolution set",
            severity="low",
        )
    ]

    analysis = analyzer._analyze_patterns(timeline)

    assert analysis["risk_level"] == "LOW"
    assert analysis["infrastructure_stability"] == "load-balanced / distributed"
    assert analysis["suspicious_patterns"] == ["none detected"]
