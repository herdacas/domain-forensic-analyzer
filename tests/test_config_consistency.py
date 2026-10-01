"""Settings and the API clients must share one configuration model."""

import pytest

import config.settings as settings_module
from config.settings import get_settings

SERVICES = ("securitytrails", "virustotal", "abuseipdb", "whoisxml")


def test_settings_loads_without_errors():
    settings = get_settings()
    assert settings is not None


def test_api_config_accessible():
    settings = get_settings()
    assert hasattr(settings, 'api_config')
    assert hasattr(settings.api_config, 'virustotal_api_key')
    assert hasattr(settings.api_config, 'securitytrails_api_key')


def test_scan_settings_accessible():
    settings = get_settings()
    assert hasattr(settings, 'scan_settings')
    assert hasattr(settings.scan_settings, 'dns_timeout')


def test_settings_singleton_behavior():
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2


def test_settings_module_does_not_shadow_runtime_apiconfig():
    """Only src.config.api_config.APIConfig exists; no second, differently shaped class."""
    assert not hasattr(settings_module, "APIConfig")


def test_settings_snapshot_mirrors_runtime_loader(tmp_path, monkeypatch):
    """Settings.api_config must expose exactly what SecureAPIManager gives the clients."""
    import json
    from src.config.api_config import SecureAPIManager
    for service in SERVICES:
        monkeypatch.delenv(f"{service.upper()}_API_KEY", raising=False)
    (tmp_path / "config").mkdir()
    config_file = tmp_path / "config/api_keys.json"
    config_file.write_text(json.dumps({
        "virustotal": "file_key_vt_123456789",
        "abuseipdb": {"api_key": "file_key_abuse_123456789"},
    }))
    manager = SecureAPIManager.__new__(SecureAPIManager)
    manager.project_root, manager.config_file, manager.api_configs = tmp_path, config_file, {}
    manager._load_configurations()
    monkeypatch.setattr(settings_module, "SecureAPIManager", lambda: manager)
    monkeypatch.setenv("OUTPUT_DIRECTORY", str(tmp_path / "reports"))

    settings = settings_module.Settings()
    for service in SERVICES:
        runtime = manager.get_api_config(service)
        assert getattr(settings.api_config, f"{service}_api_key") == (runtime.api_key if runtime else None)
        if runtime:
            assert getattr(settings.api_config, f"{service}_base_url") == runtime.base_url


@pytest.mark.parametrize("service", SERVICES)
def test_default_base_urls_come_from_runtime_defaults(service):
    from src.config.api_config import _DEFAULTS
    assert getattr(settings_module.APISettings(), f"{service}_base_url") == _DEFAULTS[service][0]
