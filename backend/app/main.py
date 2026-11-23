"""M-PHISH application entry point. Run migrations before starting the service."""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .analysis import build_report, quick_check
from .api import install
from .core.config import settings
from .core.logging import configure_logging
from .core.network import parse_target


def validate_target(url):
    from fastapi import HTTPException

    try:
        parse_target(url)
    except ValueError as error:
        raise HTTPException(400, str(error)) from None


@asynccontextmanager
async def lifespan(app):
    if os.getenv("APP_ENV") == "production":
        if not os.getenv("DATABASE_URL", "").startswith("postgresql") or not os.getenv("REDIS_URL"):
            raise RuntimeError("Production requires PostgreSQL and Redis.")
        if not os.getenv("WEB_ORIGINS", "").startswith("https://"):
            raise RuntimeError("Production requires explicit HTTPS WEB_ORIGINS.")
    yield


configure_logging(settings.log_level)
app = FastAPI(
    title="M-PHISH",
    version="0.2.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
install(app, build_report, quick_check)
