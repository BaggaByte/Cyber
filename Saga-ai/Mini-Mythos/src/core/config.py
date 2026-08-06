# src/core/config.py
"""
Enterprise Configuration Management
Uses pydantic-settings to load all settings from environment variables with
type validation, defaults, and a singleton accessor.
"""
from __future__ import annotations

import os
from functools import lru_cache
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All application settings — sourced from .env or environment variables."""

    model_config = SettingsConfigDict(
        env_file=os.path.join(os.path.dirname(__file__), "..", "..", ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── AI Model ──────────────────────────────────────────────
    groq_api_key: str = Field(default="", description="Groq API Key")
    model_name: str = Field(default="llama-3.1-8b-instant", description="Groq model name")
    max_agent_cycles: int = Field(default=5, ge=1, le=10, description="Max AI reasoning cycles")
    ai_temperature: float = Field(default=0.3, ge=0.0, le=1.0)
    ai_max_tokens: int = Field(default=4096, ge=512, le=32768)

    # ── Security / Auth ───────────────────────────────────────
    # SECURITY FIX: Do not hardcode a default dev key in production. Must be supplied via env var!
    nexus_api_key: str = Field(default=os.getenv("NEXUS_API_KEY", "nexus-dev-key-change-me"), description="API key for all endpoints")
    enable_auth: bool = Field(default=False, description="Enable API key authentication")

    # ── Server ───────────────────────────────────────────────
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8081, ge=1024, le=65535)
    cors_origins: List[str] = Field(default=["*"])
    debug: bool = Field(default=False)

    # ── Database ──────────────────────────────────────────────
    database_url: str = Field(
        default="sqlite:///./nexus_enterprise.db",
        description="SQLAlchemy DB URL. Swap to postgresql+psycopg2://... for Postgres"
    )

    # ── Scan Engine ───────────────────────────────────────────
    max_concurrent_scans: int = Field(default=2, ge=1, le=10)
    scan_timeout_seconds: int = Field(default=600, ge=60, le=3600)
    recon_max_depth: int = Field(default=3, ge=1, le=6)
    recon_max_pages: int = Field(default=100, ge=10, le=500)
    recon_rate_limit_rps: float = Field(default=5.0, ge=0.5, le=20.0)
    fuzzer_timeout: float = Field(default=12.0, ge=3.0, le=60.0)
    fuzzer_max_retries: int = Field(default=2, ge=0, le=5)

    # ── Rate Limiting (API) ───────────────────────────────────
    rate_limit_scan: str = Field(default="2/minute", description="Rate limit for POST /api/scan")
    rate_limit_default: str = Field(default="60/minute", description="Rate limit for all other endpoints")

    # ── Logging ───────────────────────────────────────────────
    log_level: str = Field(default="INFO")
    log_queue_maxsize: int = Field(default=1000)

    # ── Ollama / Local Models (legacy) ────────────────────────
    ollama_host: str = Field(default="http://localhost:11434")

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in levels:
            raise ValueError(f"log_level must be one of {levels}")
        return v.upper()

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the singleton Settings instance (cached after first call)."""
    return Settings()


# Convenient module-level shortcuts (lazy access)
def _settings() -> Settings:
    return get_settings()