"""Unit tests for Colors utility class."""

import pytest
from src.utils.colors import Colors


class TestColorsReturnType:

    def test_success_returns_string(self):
        result = Colors.success("OK")
        assert isinstance(result, str)
        assert "OK" in result

    def test_error_returns_string(self):
        result = Colors.error("FAIL")
        assert isinstance(result, str)
        assert "FAIL" in result

    def test_warning_returns_string(self):
        assert isinstance(Colors.warning("warn"), str)

    def test_info_returns_string(self):
        assert isinstance(Colors.info("info"), str)

    def test_header_returns_string(self):
        assert isinstance(Colors.header("TITLE"), str)

    def test_critical_returns_string(self):
        assert isinstance(Colors.critical("CRITICAL"), str)

    def test_highlight_returns_string(self):
        assert isinstance(Colors.highlight("text"), str)

    def test_dim_returns_string(self):
        assert isinstance(Colors.dim("dim text"), str)

    def test_format_ip_returns_string(self):
        result = Colors.format_ip("1.2.3.4")
        assert isinstance(result, str)
        assert "1.2.3.4" in result

    def test_format_domain_returns_string(self):
        result = Colors.format_domain("example.com")
        assert isinstance(result, str)

    def test_investigation_separator_returns_string(self):
        result = Colors.investigation_separator(40)
        assert isinstance(result, str)
        assert len(result) >= 40

    def test_section_header_returns_string(self):
        result = Colors.section_header("TEST SECTION", 40)
        assert isinstance(result, str)
        assert "TEST SECTION" in result

    def test_risk_level_low(self):
        result = Colors.risk_level("LOW")
        assert isinstance(result, str)
        assert "LOW" in result

    def test_risk_level_high(self):
        result = Colors.risk_level("HIGH")
        assert isinstance(result, str)
        assert "HIGH" in result

    def test_risk_level_medium(self):
        result = Colors.risk_level("MEDIUM")
        assert isinstance(result, str)

    def test_risk_level_critical(self):
        result = Colors.risk_level("CRITICAL")
        assert isinstance(result, str)

    def test_format_status_positive(self):
        result = Colors.format_status("SUCCESS", is_positive=True)
        assert isinstance(result, str)

    def test_format_status_negative(self):
        result = Colors.format_status("FAILED", is_positive=False)
        assert isinstance(result, str)

    def test_is_color_supported_returns_bool(self):
        result = Colors.is_color_supported()
        assert isinstance(result, bool)
