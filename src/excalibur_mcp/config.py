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

    # ── Credit economics (tuning with defaults) ──────────────────────
    seed_balance_sats: int = 0
    credit_ttl_seconds: int | None = 604800  # 7 days
    dpyc_registry_cache_ttl_seconds: int = 300

    # ── Domain tuning ────────────────────────────────────────────────
    excalibur_vault_dir: str | None = None

    # ── Constraint Engine (opt-in) ───────────────────────────────────
    constraints_enabled: bool = False
    constraints_config: str | None = None
