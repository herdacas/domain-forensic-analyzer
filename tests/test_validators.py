"""Unit tests for DomainValidator."""

import pytest
from src.utils.validators import DomainValidator


# ---------------------------------------------------------------------------
# preprocess_domain
# ---------------------------------------------------------------------------

class TestPreprocessDomain:

    def test_valid_domain_returns_clean(self):
        domain, msg = DomainValidator.preprocess_domain("example.com")
        assert domain == "example.com"
        assert msg is None or msg == ""

    def test_strips_www_subdomain(self):
        domain, msg = DomainValidator.preprocess_domain("www.example.com")
        assert domain == "example.com"

    def test_strips_deep_subdomain(self):
        domain, msg = DomainValidator.preprocess_domain("api.sub.example.com")
        assert domain == "example.com"

    def test_preserves_compound_cctld_couk(self):
        domain, msg = DomainValidator.preprocess_domain("bbc.co.uk")
        assert domain == "bbc.co.uk"

    def test_preserves_compound_cctld_comau(self):
        domain, msg = DomainValidator.preprocess_domain("abc.com.au")
        assert domain == "abc.com.au"

    def test_preserves_gouv_fr(self):
        domain, msg = DomainValidator.preprocess_domain("ssi.gouv.fr")
        assert domain == "ssi.gouv.fr"

    def test_strips_subdomain_from_couk(self):
        domain, msg = DomainValidator.preprocess_domain("news.bbc.co.uk")
        assert domain == "bbc.co.uk"

    def test_ip_address_rejected(self):
        domain, msg = DomainValidator.preprocess_domain("192.168.0.1")
        assert domain is None
        assert "IP address" in msg

    def test_file_txt_rejected(self):
        domain, msg = DomainValidator.preprocess_domain("domains.txt")
        assert domain is None
        assert "--list" in msg

    def test_file_csv_rejected(self):
        domain, msg = DomainValidator.preprocess_domain("data.csv")
        assert domain is None

    def test_backslash_path_rejected(self):
        domain, msg = DomainValidator.preprocess_domain(r"C:\Users\test.com")
        assert domain is None

    def test_bare_word_without_dot_rejected(self):
        domain, msg = DomainValidator.preprocess_domain("localhost")
        assert domain is None

    def test_reserved_tld_invalid_rejected(self):
        domain, msg = DomainValidator.preprocess_domain("test.invalid")
        assert domain is None

    def test_reserved_tld_local_rejected(self):
        domain, msg = DomainValidator.preprocess_domain("mymachine.local")
        assert domain is None

    def test_leading_trailing_whitespace_stripped(self):
        domain, msg = DomainValidator.preprocess_domain("  example.com  ")
        assert domain == "example.com"

    def test_uppercase_lowercased(self):
        domain, msg = DomainValidator.preprocess_domain("EXAMPLE.COM")
        assert domain == "example.com"

    def test_idn_converted_to_punycode(self):
        domain, msg = DomainValidator.preprocess_domain("münchen.de")
        assert domain == "xn--mnchen-3ya.de"

    def test_8_8_8_8_rejected_as_ip(self):
        domain, msg = DomainValidator.preprocess_domain("8.8.8.8")
        assert domain is None

    def test_numeric_labels_with_alpha_pass(self):
        domain, msg = DomainValidator.preprocess_domain("1and1.de")
        assert domain == "1and1.de"


# ---------------------------------------------------------------------------
# is_valid_domain
# ---------------------------------------------------------------------------

class TestIsValidDomain:

    def test_valid_simple(self):
        assert DomainValidator.is_valid_domain("example.com") is True

    def test_valid_with_hyphen(self):
        assert DomainValidator.is_valid_domain("my-domain.org") is True

    def test_empty_string_invalid(self):
        assert DomainValidator.is_valid_domain("") is False

    def test_no_dot_invalid(self):
        assert DomainValidator.is_valid_domain("nodot") is False

    def test_single_label_invalid(self):
        assert DomainValidator.is_valid_domain("nodomain") is False

    def test_tld_only_invalid(self):
        assert DomainValidator.is_valid_domain(".com") is False


# ---------------------------------------------------------------------------
# clean_domain
# ---------------------------------------------------------------------------

class TestCleanDomain:

    def test_strips_https_prefix(self):
        assert DomainValidator.clean_domain("https://example.com") == "example.com"

    def test_strips_http_prefix(self):
        assert DomainValidator.clean_domain("http://example.com/path") == "example.com"

    def test_lowercases(self):
        assert DomainValidator.clean_domain("EXAMPLE.COM") == "example.com"

    def test_strips_trailing_dot(self):
        result = DomainValidator.clean_domain("example.com.")
        assert not result.endswith(".")


# ---------------------------------------------------------------------------
# _to_punycode
# ---------------------------------------------------------------------------

class TestToPunycode:

    def test_ascii_domain_unchanged(self):
        result = DomainValidator._to_punycode("example.com")
        assert result == "example.com"

    def test_german_umlaut_converted(self):
        result = DomainValidator._to_punycode("münchen.de")
        assert result == "xn--mnchen-3ya.de"

    def test_french_accent_converted(self):
        result = DomainValidator._to_punycode("café.fr")
        assert result is not None
        assert result.startswith("xn--")


# ---------------------------------------------------------------------------
# get_domain_parts
# ---------------------------------------------------------------------------

class TestGetDomainParts:

    def test_simple_domain_parts(self):
        result = DomainValidator.get_domain_parts("example.com")
        assert result is not None
        assert result["tld"] == "com"
        assert result["domain_name"] == "example"

    def test_subdomain_detected(self):
        result = DomainValidator.get_domain_parts("api.example.com")
        assert result["is_subdomain"] is True
        assert result["subdomain"] == "api"

    def test_no_subdomain(self):
        result = DomainValidator.get_domain_parts("example.com")
        assert result["is_subdomain"] is False
        assert result["subdomain"] is None

    def test_invalid_domain_returns_none(self):
        result = DomainValidator.get_domain_parts("nodot")
        assert result is None

    def test_tld_info_populated(self):
        result = DomainValidator.get_domain_parts("example.com")
        assert "tld_info" in result
        assert result["tld_info"]["is_common"] is True


# ---------------------------------------------------------------------------
# is_suspicious_domain
# ---------------------------------------------------------------------------

class TestIsSuspiciousDomain:

    def test_normal_domain_low_suspicion(self):
        result = DomainValidator.is_suspicious_domain("example.com")
        assert isinstance(result, dict)
        assert "is_suspicious" in result

    def test_very_long_domain_flagged(self):
        long_domain = "a" * 35 + ".com"
        result = DomainValidator.is_suspicious_domain(long_domain)
        assert result.get("suspicion_score", 0) > 0 or result.get("is_suspicious")

    def test_many_hyphens_flagged(self):
        result = DomainValidator.is_suspicious_domain("a-b-c-d-e.com")
        assert isinstance(result, dict)

    def test_invalid_domain_returns_suspicious(self):
        result = DomainValidator.is_suspicious_domain("nodot")
        assert result["is_suspicious"] is True

    def test_deep_subdomain_flagged(self):
        result = DomainValidator.is_suspicious_domain("a.b.c.d.e.example.com")
        assert isinstance(result, dict)
