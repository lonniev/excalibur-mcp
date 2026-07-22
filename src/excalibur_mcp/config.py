"""eXcalibur-mcp settings loaded from environment variables.

With nsec-only bootstrap, Settings contains only the operator's Nostr
identity and tuning parameters.  All secrets (BTCPay, X/Twitter API keys)
are delivered via Secure Courier credential templates.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """eXcalibur MCP server settings.

    Only one env var is required to boot: TOLLBOOTH_NOSTR_OPERATOR_NSEC.
    Everything else has sensible defaults or is delivered via Secure Courier.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Nostr identity (one env var to boot) ─────────────────────────
    tollbooth_nostr_operator_nsec: str | None = None
    tollbooth_nostr_relays: str | None = None

    # ── Tuning (defaults are fine) ───────────────────────────────────
    seed_balance_sats: int = 0
    dpyc_registry_cache_ttl_seconds: int = 300

    # Public URL of the scheduled-post cron Worker (scheduler-worker). The
    # operator-gated `scheduler_pending` tool reads the Worker's owner-private
    # pending state from here, authenticating AS the operator (no shared secret).
    scheduler_worker_url: str = "https://excalibur-scheduler.lonniev.workers.dev"

    # ── Constraint Engine (opt-in) ───────────────────────────────────
    constraints_enabled: bool = False
    constraints_config: str | None = None
