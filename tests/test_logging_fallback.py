"""Regression coverage for scans without loguru."""
import logging
from unittest.mock import patch

from src.core.domain_analyzer import DomainAnalyzer


def test_standard_logger_accepts_context_and_initializes_modules(caplog):
    with patch('src.core.domain_analyzer.LOGURU_AVAILABLE', False), caplog.at_level(logging.DEBUG):
        analyzer = DomainAnalyzer()
        assert 'dns' in analyzer.modules
        assert 'whois' in analyzer.modules
        analyzer.logger.error('Module failed', error='test failure', domain='example.com')
        analyzer.logger.warning('Timeout', timeout=10)
        analyzer.logger.info('Complete', successful_modules=2)
    assert 'test failure' in caplog.text
    assert 'System initialization complete' in caplog.text
