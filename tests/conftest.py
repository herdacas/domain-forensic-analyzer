"""Shared fixtures for Domain Forensic Analyzer test suite."""

import pytest


@pytest.fixture(autouse=True)
def isolated_network_and_action_runtime(monkeypatch):
    """Tests use mocked transports; no customer target is contacted by the suite."""
    import socket
    from src.core import action_tracer, scope_guard, scan_runtime

    def offline(*args, **kwargs):
        raise OSError("Live network disabled during tests")

    monkeypatch.setattr(socket.socket, "connect", offline)
    monkeypatch.setattr(socket.socket, "sendto", offline)
    # libc resolver calls bypass Python socket.connect, so block these too.
    monkeypatch.setattr(socket, "gethostbyname", offline)
    monkeypatch.setattr(socket, "getaddrinfo", offline)
    monkeypatch.setattr(socket, "gethostbyaddr", offline)
    monkeypatch.setattr(socket, "getfqdn", offline)
    # Each test starts without state left behind by another scan/test.
    monkeypatch.setattr(action_tracer, "TRACE_FILE", None)
    monkeypatch.setattr(scope_guard, "_scope", None)
    monkeypatch.setattr(scope_guard, "_source_ip", "")
    monkeypatch.setattr(scope_guard, "_next_action", 0.0)
    trace_token = action_tracer._trace_context.set(None)
    policy_token = scope_guard._policy_context.set(None)
    source_token = scope_guard._source_context.set(None)
    target_token = scan_runtime._target_context.set(None)
    yield
    action_tracer._trace_context.reset(trace_token)
    scope_guard._policy_context.reset(policy_token)
    scope_guard._source_context.reset(source_token)
    scan_runtime._target_context.reset(target_token)


# ---------------------------------------------------------------------------
# Mock API responses
# ---------------------------------------------------------------------------

@pytest.fixture
def vt_domain_response():
    """Minimal VirusTotal /domains/{domain} response."""
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 80,
                    "undetected": 11,
                },
                "reputation": 5,
                "categories": {"Forcepoint ThreatSeeker": "Information Technology"},
                "last_dns_records": [],
            }
        }
    }


@pytest.fixture
def vt_ip_resolution_response():
    """Minimal VirusTotal /ip_addresses/{ip}/resolutions response."""
    return {
        "data": [
            {"attributes": {"host_name": "example.com", "date": 1700000000}},
            {"attributes": {"host_name": "sub.example.com", "date": 1699000000}},
        ],
        "meta": {"count": 2},
    }


@pytest.fixture
def abuseipdb_response():
    """Minimal AbuseIPDB /check response."""
    return {
        "data": {
            "ipAddress": "93.184.216.34",
            "abuseConfidenceScore": 0,
            "countryCode": "US",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Edgecast Inc.",
            "domain": "verizondigitalmedia.com",
            "totalReports": 0,
            "lastReportedAt": None,
        }
    }


@pytest.fixture
def whoisxml_response():
    """Minimal WhoisXML API response for example.com."""
    return {
        "WhoisRecord": {
            "domainName": "example.com",
            "registrarName": "IANA",
            "createdDate": "1995-08-14T04:00:00Z",
            "expiresDate": "2026-08-13T04:00:00Z",
            "updatedDate": "2023-08-14T07:01:38Z",
            "registrant": {
                "name": "Not disclosed",
                "email": "noc@iana.org",
                "country": "US",
            },
            "nameServers": {"hostNames": ["a.iana-servers.net", "b.iana-servers.net"]},
            "registryData": {"nameServers": None},
        }
    }


@pytest.fixture
def ip_api_response():
    """Minimal ip-api.com response."""
    return {
        "status": "success",
        "country": "United States",
        "countryCode": "US",
        "regionName": "California",
        "city": "San Jose",
        "as": "AS15169 Google LLC",
        "org": "Google LLC",
        "isp": "Google LLC",
        "query": "8.8.8.8",
    }


# ---------------------------------------------------------------------------
# DNS record fakes (reusable across dns_analyzer tests)
# ---------------------------------------------------------------------------

class FakeRRset:
    """Fake dns.resolver RRset with iterable records."""
    def __init__(self, records, rdtype_name="A"):
        self._records = records
        self.rdtype = type("RdType", (), {"name": rdtype_name})()
        self.ttl = 300

    def __iter__(self):
        return iter(self._records)


class FakeARecord:
    def __init__(self, address):
        self.address = address

    def __str__(self):
        return self.address


class FakeNSRecord:
    def __init__(self, target):
        self._target = target

    def to_text(self):
        return self._target

    def __str__(self):
        return self._target


class FakeMXRecord:
    def __init__(self, exchange, preference=10):
        self.exchange = type("Name", (), {
            "__str__": lambda s: exchange,
            "rstrip": lambda s, c: exchange.rstrip(c),
        })()
        self.preference = preference


@pytest.fixture
def fake_rrset_factory():
    return FakeRRset


@pytest.fixture
def fake_a_record():
    return FakeARecord


@pytest.fixture
def fake_ns_record():
    return FakeNSRecord
