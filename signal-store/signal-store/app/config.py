"""
config.py – Central configuration for ATTENSE Signal Mapper.

All settings are read from environment variables (or a .env file).
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── Input ─────────────────────────────────────────────────────────────────
    # Path to the Wazuh alerts JSON file (mounted read-only from wazuh-manager)
    wazuh_alerts_path: str = "/wazuh/alerts/alerts.json"

    # ── Output ────────────────────────────────────────────────────────────────
    # "file"  → append one JSON line per event to OUTPUT_PATH
    # "http"  → POST each event to EVENT_STORE_URL
    output_mode: str = "file"                          # "file" | "http"
    output_path: str = "/out/mapped_events.jsonl"      # used when output_mode=file
    event_store_url: str = "http://event-store-mock:8000/events"  # used when output_mode=http

    # ── HTTP retry (output_mode=http) ─────────────────────────────────────────
    http_retry_attempts: int = 5       # max POST attempts before giving up
    http_retry_min_wait: float = 1.0   # minimum backoff (seconds)
    http_retry_max_wait: float = 30.0  # maximum backoff (seconds)

    # ── HTTP API (Signal Mapper's own FastAPI health/ingest endpoint) ─────────
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    # Public URL where other services reach this signal-store's /ingest.
    # Documentation only — not consumed by signal-store itself; the red-team
    # notifier reads this env var (SIGNAL_STORE_URL) directly.
    signal_store_url: str = "http://signal-store:8005"

    # ── Reader ────────────────────────────────────────────────────────────────
    # Seconds to wait for the alerts file to appear before aborting
    file_wait_timeout: int = 120
    # Polling interval when no new lines are available
    poll_interval: float = 0.5


settings = Settings()
