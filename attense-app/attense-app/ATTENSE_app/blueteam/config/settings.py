"""
settings.py — Runtime Configuration
=====================================
Reads environment variables and provides typed settings
to every component via dependency injection.

Swap values per environment:
    development  → .env file
    production   → actual env vars / secrets manager
"""

from __future__ import annotations
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── Service identity ──────────────────────────────────────────────────────
    service_name: str = "blueteam"
    environment: str = "development"
    log_level: str = "INFO"

    # ── TheHive integration ───────────────────────────────────────────────────
    hive_url: str = "http://localhost:9000"
    hive_api_key: str = "changeme"
    # Shared secret for validating Hive webhook requests (HMAC-SHA256)
    # TheHive is internal to this container so this is optional hardening
    webhook_secret: str = "changeme-webhook"

    # ── Sandbox / Target Agent ────────────────────────────────────────────────
    sandbox_url: str = "http://localhost:8020"

    # ── Cortex-Lite: Threat Intelligence Enrichment ───────────────────────────
    # Leave empty to disable gracefully — the alert workflow is unaffected.
    virustotal_api_key: str = ""        # https://www.virustotal.com/gui/join-us
    abuseipdb_api_key: str = ""         # https://www.abuseipdb.com/register

    # ── Event Store ───────────────────────────────────────────────────────────
    event_store_type: str = "memory"   # "memory" | "postgres" | "kafka"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
