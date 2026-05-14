"""
SSL/TLS Analyzer for Domain Forensic Analyzer.

Establishes a TLS connection to port 443 and extracts certificate
and protocol metadata without relying on external APIs.

Two-pass connection:
  Pass 1 - with hostname verification (normal case)
  Pass 2 - without verification (expired / self-signed fallback)
"""

import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("ssl_analyzer")
logger.addHandler(logging.NullHandler())
logger.propagate = False

try:
    from cryptography import x509 as cx509

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


class SSLAnalyzer:
    """Analyse TLS certificate and protocol details for a domain."""

    TIMEOUT = 10

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_ssl(self, domain: str) -> Dict[str, Any]:
        """
        Connect to domain:443, extract certificate and TLS metadata.
        Returns a structured dict with analysis_status='abgeschlossen'.
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            return {
                "analysis_status": "failed",
                "error": "cryptography library not installed",
                "domain": domain,
                "available": False,
            }

        cert_der, tls_version, verified = self._connect(domain)

        if cert_der is None:
            return {
                "analysis_status": "abgeschlossen",
                "domain": domain,
                "available": False,
                "error": tls_version,
            }

        return self._parse_certificate(cert_der, tls_version, verified, domain)

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def _connect(self, domain: str):
        """
        Try TLS connection twice: verified first, then unverified fallback.
        Returns (cert_der_bytes, tls_version_str, verified_bool)
        or (None, error_str, False) on complete failure.
        """
        last_error = "connection failed"

        for verify in (True, False):
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            try:
                with socket.create_connection(
                    (domain, 443), timeout=self.TIMEOUT
                ) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as conn:
                        cert_der = conn.getpeercert(binary_form=True)
                        tls_version = conn.version() or "Unknown"
                        return cert_der, tls_version, verify
            except ssl.SSLError as exc:
                last_error = str(exc)[:120]
                if verify:
                    continue
            except (socket.timeout, TimeoutError):
                return None, "connection timeout", False
            except ConnectionRefusedError:
                return None, "port 443 unreachable", False
            except OSError as exc:
                return None, str(exc)[:120], False
            except Exception as exc:
                last_error = str(exc)[:120]
                if verify:
                    continue

        return None, last_error, False

    # ------------------------------------------------------------------
    # Certificate parsing
    # ------------------------------------------------------------------

    def _parse_certificate(
        self,
        cert_der: bytes,
        tls_version: str,
        verified: bool,
        domain: str,
    ) -> Dict[str, Any]:
        try:
            x509 = cx509.load_der_x509_certificate(cert_der)
        except Exception as exc:
            return {
                "analysis_status": "abgeschlossen",
                "domain": domain,
                "available": True,
                "parse_error": str(exc)[:120],
                "tls_version": tls_version,
                "verified": verified,
            }

        now = datetime.now(timezone.utc)

        valid_from = x509.not_valid_before_utc
        valid_until = x509.not_valid_after_utc
        days_to_expiry = (valid_until - now).days

        issuer_org = self._name_attr(x509.issuer, cx509.NameOID.ORGANIZATION_NAME)
        issuer_cn = self._name_attr(x509.issuer, cx509.NameOID.COMMON_NAME)

        sans: List[str] = self._extract_sans(x509)
        has_wildcard = any(s.startswith("*.") for s in sans)

        if has_wildcard:
            cert_type = "Wildcard"
        elif len(sans) > 1:
            cert_type = "Multi-SAN"
        else:
            cert_type = "Single"

        self_signed = x509.issuer == x509.subject
        assessment = self._assess(days_to_expiry, self_signed, tls_version, verified)

        return {
            "analysis_status": "abgeschlossen",
            "domain": domain,
            "available": True,
            "verified": verified,
            "self_signed": self_signed,
            "issuer_org": issuer_org,
            "issuer_cn": issuer_cn,
            "valid_from": valid_from.strftime("%Y-%m-%d"),
            "valid_until": valid_until.strftime("%Y-%m-%d"),
            "days_to_expiry": days_to_expiry,
            "sans": sans,
            "has_wildcard": has_wildcard,
            "cert_type": cert_type,
            "tls_version": tls_version,
            "assessment": assessment,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_sans(x509) -> List[str]:
        try:
            ext = x509.extensions.get_extension_for_class(cx509.SubjectAlternativeName)
            return [str(name.value) for name in ext.value]
        except cx509.ExtensionNotFound:
            return []
        except Exception:
            return []

    @staticmethod
    def _name_attr(name, oid) -> Optional[str]:
        try:
            return name.get_attributes_for_oid(oid)[0].value
        except (IndexError, Exception):
            return None

    @staticmethod
    def _assess(
        days_to_expiry: int, self_signed: bool, tls_version: str, verified: bool
    ) -> str:
        if days_to_expiry < 0:
            return f"INVALID - certificate expired {abs(days_to_expiry)} days ago"
        if self_signed:
            return "Self-signed certificate detected"
        if not verified:
            return "INVALID - certificate verification failed"
        if days_to_expiry < 14:
            return f"WARNING - expires in {days_to_expiry} days"
        if tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            return f"Weak protocol - {tls_version} is deprecated"
        return "Valid - modern TLS"
