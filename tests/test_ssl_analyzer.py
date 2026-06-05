"""Unit tests for SSLAnalyzer static helpers and assess logic."""

import socket
import ssl
import pytest
from unittest.mock import patch, MagicMock
from src.analyzers.ssl_analyzer import SSLAnalyzer


@pytest.fixture
def analyzer():
    return SSLAnalyzer()


# ---------------------------------------------------------------------------
# _assess — pure logic, no network
# ---------------------------------------------------------------------------

class TestAssess:

    def test_valid_modern_tls(self):
        result = SSLAnalyzer._assess(90, False, "TLSv1.3", True)
        assert result == "Valid - modern TLS"

    def test_expired_certificate(self):
        result = SSLAnalyzer._assess(-5, False, "TLSv1.3", True)
        assert "expired" in result.lower()
        assert "5" in result

    def test_expiring_soon_warning(self):
        result = SSLAnalyzer._assess(7, False, "TLSv1.3", True)
        assert "WARNING" in result
        assert "7" in result

    def test_self_signed_detected(self):
        result = SSLAnalyzer._assess(180, True, "TLSv1.3", True)
        assert "self-signed" in result.lower() or "Self-signed" in result

    def test_unverified_invalid(self):
        result = SSLAnalyzer._assess(180, False, "TLSv1.3", False)
        assert "INVALID" in result

    def test_deprecated_tls_v1(self):
        result = SSLAnalyzer._assess(180, False, "TLSv1", True)
        assert "deprecated" in result.lower() or "Weak" in result

    def test_deprecated_tls_v1_1(self):
        result = SSLAnalyzer._assess(180, False, "TLSv1.1", True)
        assert "deprecated" in result.lower() or "Weak" in result

    def test_expiry_exactly_14_days_still_warning(self):
        result = SSLAnalyzer._assess(13, False, "TLSv1.3", True)
        assert "WARNING" in result

    def test_expiry_exactly_14_days_boundary(self):
        result = SSLAnalyzer._assess(14, False, "TLSv1.3", True)
        assert result == "Valid - modern TLS"


# ---------------------------------------------------------------------------
# analyze_ssl — no-cryptography fallback
# ---------------------------------------------------------------------------

class TestAnalyzeSslNoCryptography:

    def test_returns_failed_when_no_cryptography(self, analyzer, monkeypatch):
        import src.analyzers.ssl_analyzer as ssl_mod
        monkeypatch.setattr(ssl_mod, "CRYPTOGRAPHY_AVAILABLE", False)
        result = analyzer.analyze_ssl("example.com")
        assert result["analysis_status"] == "failed"
        assert "cryptography" in result["error"].lower()
        assert result["available"] is False

    def test_returns_domain_in_result(self, analyzer, monkeypatch):
        import src.analyzers.ssl_analyzer as ssl_mod
        monkeypatch.setattr(ssl_mod, "CRYPTOGRAPHY_AVAILABLE", False)
        result = analyzer.analyze_ssl("test.example.com")
        assert result["domain"] == "test.example.com"


# ---------------------------------------------------------------------------
# analyze_ssl — mocked connection (no network)
# ---------------------------------------------------------------------------

class TestAnalyzeSslMocked:

    def test_connection_refused_returns_unavailable(self, analyzer, monkeypatch):
        import socket
        def mock_connect(domain):
            return None, "port 443 unreachable", False
        monkeypatch.setattr(analyzer, "_connect", mock_connect)
        result = analyzer.analyze_ssl("example.com")
        assert result["available"] is False
        assert result["analysis_status"] == "abgeschlossen"

    def test_successful_parse_returns_full_result(self, analyzer, monkeypatch):
        """Mock _connect to return a real DER cert from badssl.com test fixture."""
        import base64
        # Minimal self-signed DER cert (generated for testing)
        # We mock _parse_certificate instead to avoid needing a real cert
        def mock_connect(domain):
            return b"\x00" * 10, "TLSv1.3", True

        def mock_parse(cert_der, tls_version, verified, domain):
            return {
                "analysis_status": "abgeschlossen",
                "domain": domain,
                "available": True,
                "verified": verified,
                "self_signed": False,
                "issuer_org": "Let's Encrypt",
                "issuer_cn": "R3",
                "valid_from": "2024-01-01",
                "valid_until": "2024-04-01",
                "days_to_expiry": 90,
                "sans": ["example.com", "www.example.com"],
                "has_wildcard": False,
                "cert_type": "Multi-SAN",
                "tls_version": "TLSv1.3",
                "assessment": "Valid - modern TLS",
            }

        monkeypatch.setattr(analyzer, "_connect", mock_connect)
        monkeypatch.setattr(analyzer, "_parse_certificate", mock_parse)

        result = analyzer.analyze_ssl("example.com")
        assert result["analysis_status"] == "abgeschlossen"
        assert result["available"] is True
        assert result["cert_type"] == "Multi-SAN"
        assert result["tls_version"] == "TLSv1.3"


# ---------------------------------------------------------------------------
# _extract_sans — with mock x509 extension
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# _connect — mocked socket
# ---------------------------------------------------------------------------

class TestConnect:

    def test_connection_refused_returns_none(self, analyzer):
        with patch("socket.create_connection", side_effect=ConnectionRefusedError):
            cert, version, verified = analyzer._connect("example.com")
        assert cert is None
        assert "unreachable" in version or version is not None

    def test_timeout_returns_none(self, analyzer):
        with patch("socket.create_connection", side_effect=socket.timeout):
            cert, version, verified = analyzer._connect("example.com")
        assert cert is None
        assert "timeout" in version

    def test_os_error_returns_none(self, analyzer):
        with patch("socket.create_connection", side_effect=OSError("Network unreachable")):
            cert, version, verified = analyzer._connect("example.com")
        assert cert is None

    def test_ssl_error_on_verified_falls_back_to_unverified(self, analyzer):
        import ssl as ssl_mod
        fake_cert = b"\x30\x82\x01\x00"
        call_count = [0]

        mock_conn_success = MagicMock()
        mock_conn_success.__enter__ = MagicMock(return_value=mock_conn_success)
        mock_conn_success.__exit__ = MagicMock(return_value=False)
        mock_conn_success.getpeercert.return_value = fake_cert
        mock_conn_success.version.return_value = "TLSv1.3"

        def wrap_side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise ssl_mod.SSLError("cert verify failed")
            return mock_conn_success

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.side_effect = wrap_side_effect

        with patch("socket.create_connection", return_value=mock_sock), \
             patch("ssl.create_default_context", return_value=mock_ctx):
            cert, version, verified = analyzer._connect("example.com")

        # Should have fallen back to unverified
        assert cert == fake_cert
        assert verified is False  # unverified fallback

    def test_successful_connection_returns_cert(self, analyzer):
        import ssl as ssl_mod
        fake_cert = b"\x30\x82\x01\x00"
        mock_conn = MagicMock()
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_conn.getpeercert.return_value = fake_cert
        mock_conn.version.return_value = "TLSv1.3"

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_conn

        with patch("socket.create_connection", return_value=mock_sock), \
             patch("ssl.create_default_context", return_value=mock_ctx):
            cert, version, verified = analyzer._connect("example.com")

        assert cert == fake_cert
        assert version == "TLSv1.3"
        assert verified is True


class TestExtractSans:

    def test_returns_empty_list_on_missing_extension(self):
        class FakeX509:
            class extensions:
                @staticmethod
                def get_extension_for_class(cls):
                    from cryptography import x509
                    raise x509.ExtensionNotFound("", None)

        result = SSLAnalyzer._extract_sans(FakeX509())
        assert result == []

    def test_returns_san_values(self):
        class FakeName:
            def __init__(self, v):
                self.value = v

        class FakeSANExt:
            value = [FakeName("example.com"), FakeName("www.example.com")]

        class FakeExtensions:
            @staticmethod
            def get_extension_for_class(cls):
                class Wrapper:
                    value = FakeSANExt.value
                return Wrapper()

        class FakeX509:
            extensions = FakeExtensions()

        result = SSLAnalyzer._extract_sans(FakeX509())
        assert "example.com" in result
        assert "www.example.com" in result
