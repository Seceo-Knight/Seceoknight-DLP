import os

import pytest


def _reload_settings(monkeypatch, **env):
    """
    Reload app.core.config.settings with patched environment variables.

    We re-import the module after clearing it from sys.modules so that the global
    `settings = Settings()` is recreated using the new env vars.
    """
    import sys
    import importlib

    for k, v in env.items():
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)

    # Ensure required secrets are present to avoid Settings(...) validation errors
    monkeypatch.setenv("SECRET_KEY", os.environ.get("SECRET_KEY", "test-secret-key-min-32-chars-123456"))
    monkeypatch.setenv("POSTGRES_PASSWORD", os.environ.get("POSTGRES_PASSWORD", "test-postgres-pass"))
    monkeypatch.setenv("MONGODB_PASSWORD", os.environ.get("MONGODB_PASSWORD", "test-mongo-pass"))

    sys.modules.pop("app.core.config", None)
    mod = importlib.import_module("app.core.config")
    return mod.settings


def test_cors_origins_parses_json_list(monkeypatch):
    settings = _reload_settings(
        monkeypatch,
        CORS_ORIGINS='["http://localhost:3000","http://192.168.1.63:3000"]',
    )
    assert settings.CORS_ORIGINS == ["http://localhost:3000", "http://192.168.1.63:3000"]


def test_cors_origins_parses_comma_separated(monkeypatch):
    settings = _reload_settings(
        monkeypatch,
        CORS_ORIGINS="http://localhost:3000, http://192.168.1.63:3000",
    )
    assert settings.CORS_ORIGINS == ["http://localhost:3000", "http://192.168.1.63:3000"]


def test_allowed_hosts_parses_json_list(monkeypatch):
    settings = _reload_settings(
        monkeypatch,
        ALLOWED_HOSTS='["localhost","127.0.0.1","192.168.1.63"]',
    )
    assert settings.ALLOWED_HOSTS == ["localhost", "127.0.0.1", "192.168.1.63"]


def test_allowed_hosts_parses_comma_separated(monkeypatch):
    settings = _reload_settings(
        monkeypatch,
        ALLOWED_HOSTS="localhost, 127.0.0.1, 192.168.1.63",
    )
    assert settings.ALLOWED_HOSTS == ["localhost", "127.0.0.1", "192.168.1.63"]


def test_invalid_json_list_raises(monkeypatch):
    with pytest.raises(ValueError):
        _reload_settings(monkeypatch, CORS_ORIGINS='["http://localhost:3000",')


