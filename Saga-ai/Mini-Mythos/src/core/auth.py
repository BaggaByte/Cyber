# src/core/auth.py
"""
Enterprise API Key Authentication Middleware
Validates X-API-Key header on protected routes.
"""
from __future__ import annotations

import secrets
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from core.config import get_settings

_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: str | None = Security(_API_KEY_HEADER)) -> str:
    """
    FastAPI dependency: validates the X-API-Key header.
    If auth is disabled in settings, always passes.
    """
    settings = get_settings()

    if not settings.enable_auth:
        return "auth-disabled"

    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Constant-time comparison to prevent timing attacks
    if not secrets.compare_digest(api_key, settings.nexus_api_key):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key",
        )

    return api_key
