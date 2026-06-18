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
    # When true, every raised alert is auto-promoted to a case (alert → case),
    # which fires the CaseCreated webhook and auto-attaches the attacker log.
    # Set false to restore the analyst-driven model (analyst promotes manually).
    auto_create_case: bool = True
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
        # Read config from a local .env (dev) AND from a mounted secrets file.
        # `secrets/blueteam.env` is generated/refreshed by scripts/setup_thehive.py
        # (it writes HIVE_API_KEY=<the ATTENSE org key> after creating the org in
        # TheHive) and bind-mounted into the container at /run/secrets/blueteam.env.
        # Later files win over earlier ones. NOTE: a real OS env var still wins over
        # any env_file, so HIVE_API_KEY must NOT be set in docker-compose
        # `environment:` — it is delivered exclusively via this file so a
        # `docker restart attense_app` picks up a freshly fetched key.
        env_file = (".env", "/run/secrets/blueteam.env")
        env_file_encoding = "utf-8"
