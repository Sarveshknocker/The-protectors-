"""FastAPI security layer: validated settings, headers, CORS allow-list, rate limiting, safe errors.

deps: pip install fastapi pydantic-settings slowapi
Usage:
    from security import settings, install_security, limiter
    app = FastAPI(docs_url=None if settings.environment == "production" else "/docs")
    install_security(app)

    @app.post("/auth/login")
    @limiter.limit("10/15minutes")
    async def login(request: Request, body: LoginIn): ...
"""
from __future__ import annotations

import logging
import uuid
from typing import Literal

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("security")


class Settings(BaseSettings):
    """Fails fast at import time if required secrets are missing or weak."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: Literal["development", "test", "production"] = "development"
    database_url: SecretStr
    secret_key: SecretStr = Field(min_length=32)
    cors_origins: list[str] = []  # JSON list in env: CORS_ORIGINS='["https://app.example.com"]'


settings = Settings()  # type: ignore[call-arg]
limiter = Limiter(key_func=get_remote_address, default_limits=["300/15minutes"])

SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "X-Frame-Options": "DENY",
    # JSON API: nothing should ever execute from these responses.
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}


def _problem(status: int, title: str, request_id: str, **extra) -> JSONResponse:
    return JSONResponse(
        {"type": "about:blank", "title": title, "status": status, "requestId": request_id, **extra},
        status_code=status,
        media_type="application/problem+json",
    )


def install_security(app: FastAPI) -> None:
    app.state.limiter = limiter

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,  # exact origins only; never ["*"] with credentials
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
        max_age=600,
    )

    @app.middleware("http")
    async def headers_and_request_id(request: Request, call_next):
        incoming = request.headers.get("x-request-id", "")
        request.state.request_id = incoming if 8 <= len(incoming) <= 64 and incoming.replace("-", "").isalnum() else str(uuid.uuid4())
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        response.headers["X-Request-Id"] = request.state.request_id
        if "server" in response.headers:
            del response.headers["server"]
        return response

    @app.exception_handler(RateLimitExceeded)
    async def rate_limited(request: Request, exc: RateLimitExceeded):
        return _problem(429, "Too many requests", getattr(request.state, "request_id", ""))

    @app.exception_handler(RequestValidationError)
    async def invalid(request: Request, exc: RequestValidationError):
        errors = [{"path": ".".join(map(str, e["loc"])), "message": e["msg"]} for e in exc.errors()]
        return _problem(400, "Invalid request", getattr(request.state, "request_id", ""), errors=errors)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        title = exc.detail if exc.status_code < 500 and isinstance(exc.detail, str) else "Error"
        return _problem(exc.status_code, title, getattr(request.state, "request_id", ""))

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        rid = getattr(request.state, "request_id", "")
        log.exception("unhandled error", extra={"request_id": rid})  # full detail in logs only
        return _problem(500, "Internal Server Error", rid)
