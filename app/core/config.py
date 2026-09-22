
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "AI Red Team"
    app_version: str = "0.1.0"
    debug: bool = False
    environment: str = "development"

    api_host: str = "127.0.0.1"
    api_port: int = 8080

    database_url: str = "sqlite:///./data/redteam.db"

    allowed_targets: list[str] = Field(
        default_factory=lambda: ["http://localhost:*", "http://127.0.0.1:*"],
        description="Allowed target patterns for scanning",
    )

    require_explicit_authorization: bool = True

    max_requests_per_scan: int = 100
    max_tokens_per_scan: int = 50000
    max_runtime_seconds: int = 300
    max_tool_calls_per_scan: int = 50

    ollama_base_url: str | None = "http://localhost:11434"
    openai_api_key: str | None = None
    openai_base_url: str | None = None
    anthropic_api_key: str | None = None

    log_level: str = "INFO"
    log_format: str = "json"

    taxonomy_version: str = "owasp-llm-2026"

    default_scan_budget: dict = Field(
        default_factory=lambda: {
            "max_requests": 100,
            "max_tokens": 50000,
            "max_runtime_seconds": 300,
            "max_tool_calls": 50,
        }
    )


settings = Settings()
