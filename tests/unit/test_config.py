from app.core.config import Settings


def test_settings_defaults():
    settings = Settings()
    assert settings.app_name == "AI Red Team"
    assert settings.api_host == "127.0.0.1"
    assert settings.api_port == 8080
    assert "http://localhost:*" in settings.allowed_targets
    assert settings.require_explicit_authorization is True


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv("API_HOST", "0.0.0.0")
    monkeypatch.setenv("API_PORT", "9000")
    monkeypatch.setenv("DEBUG", "true")

    settings = Settings()
    assert settings.api_host == "0.0.0.0"
    assert settings.api_port == 9000
    assert settings.debug is True
