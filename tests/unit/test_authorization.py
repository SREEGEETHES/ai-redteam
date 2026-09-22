import pytest

from app.security.authorization import AuthorizationError, TargetAuthorizationGuard


def test_guard_allows_localhost_by_default():
    guard = TargetAuthorizationGuard()
    assert guard.is_allowed("http://localhost:8000") is True
    assert guard.is_allowed("http://127.0.0.1:8080") is True


def test_guard_blocks_external_by_default():
    guard = TargetAuthorizationGuard()
    assert guard.is_allowed("http://example.com") is False
    assert guard.is_allowed("https://api.openai.com") is False


def test_guard_allows_configured_patterns():
    guard = TargetAuthorizationGuard(allowed_patterns=["http://localhost:*", "http://10.0.0.*"])
    assert guard.is_allowed("http://localhost:8000") is True
    assert guard.is_allowed("http://10.0.0.5:8000") is True
    assert guard.is_allowed("http://192.168.1.1") is False


def test_guard_require_explicit_false_allows_all():
    guard = TargetAuthorizationGuard(require_explicit=False)
    assert guard.is_allowed("http://example.com") is True


def test_guard_authorize_or_raise():
    guard = TargetAuthorizationGuard()
    guard.authorize_or_raise("http://localhost:8000")

    with pytest.raises(AuthorizationError):
        guard.authorize_or_raise("http://example.com")


def test_guard_invalid_scheme():
    guard = TargetAuthorizationGuard(require_explicit=False)
    assert guard.is_allowed("ftp://localhost") is False
    assert guard.is_allowed("ws://localhost") is False
