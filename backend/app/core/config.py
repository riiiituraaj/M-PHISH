import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    app_env: str = os.getenv("APP_ENV", "development")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    crawler_timeout_seconds: int = int(os.getenv("CRAWLER_TIMEOUT_SECONDS", "15"))
    max_redirects: int = int(os.getenv("MAX_REDIRECTS", "5"))
    max_crawler_requests: int = int(os.getenv("MAX_CRAWLER_REQUESTS", "100"))
    investigation_rate_limit: int = int(os.getenv("INVESTIGATION_RATE_LIMIT", "30"))
    rate_window_seconds: int = int(os.getenv("RATE_WINDOW_SECONDS", "60"))
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///m_phish.db")
    api_key: str = os.getenv("M_PHISH_API_KEY", "")
    ai_provider: str = os.getenv("AI_PROVIDER", "fallback")
    groq_api_key: str = os.getenv("GROQ_API_KEY", "")
    ai_model: str = os.getenv("AI_MODEL", "openai/gpt-oss-20b")
    enable_playwright: bool = os.getenv("ENABLE_PLAYWRIGHT", "false").lower() == "true"


settings = Settings()
