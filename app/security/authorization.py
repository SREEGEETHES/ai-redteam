import re
from urllib.parse import urlparse

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class AuthorizationError(Exception):
    pass


class TargetAuthorizationGuard:
    def __init__(self, allowed_patterns: list[str] = None, require_explicit: bool = None):
        self.allowed_patterns = allowed_patterns or settings.allowed_targets
        self.require_explicit = require_explicit if require_explicit is not None else settings.require_explicit_authorization
        self._compiled_patterns = [self._compile_pattern(p) for p in self.allowed_patterns]

    def _compile_pattern(self, pattern: str) -> re.Pattern:
        regex = pattern.replace(".", r"\.").replace("*", ".*")
        return re.compile(f"^{regex}$")

    def is_allowed(self, target_url: str) -> bool:
        parsed = urlparse(target_url)

        if parsed.scheme not in ("http", "https"):
            logger.warning("invalid_scheme", url=target_url, scheme=parsed.scheme)
            return False

        if self.require_explicit:
            for pattern in self._compiled_patterns:
                if pattern.match(target_url):
                    logger.info("target_allowed", url=target_url)
                    return True

            logger.warning("target_not_authorized", url=target_url, allowed_patterns=self.allowed_patterns)
            return False

        return True

    def authorize_or_raise(self, target_url: str) -> None:
        if not self.is_allowed(target_url):
            raise AuthorizationError(
                f"Target {target_url} is not authorized for scanning. "
                f"Allowed patterns: {self.allowed_patterns}. "
                f"Use --allow-remote flag or configure allowed_targets in settings."
            )

    def add_allowed_pattern(self, pattern: str) -> None:
        self.allowed_patterns.append(pattern)
        self._compiled_patterns.append(self._compile_pattern(pattern))


default_guard = TargetAuthorizationGuard()
