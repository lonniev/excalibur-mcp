"""eXcalibur-mcp settings loaded from environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """eXcalibur MCP server settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # BTCPay Server (for Lightning invoices)
    btcpay_host: str | None = None
    btcpay_store_id: str | None = None
    btcpay_api_key: str | None = None
    btcpay_tier_config: str | None = None
    btcpay_user_tiers: str | None = None

    # Credit seeding for new users (0 = disabled)
    seed_balance_sats: int = 0

    # DPYC registry resolution (replaces dpyc_operator_npub / dpyc_authority_npub env vars)
    dpyc_registry_url: str = "https://raw.githubusercontent.com/lonniev/dpyc-community/main/members.json"
    dpyc_registry_cache_ttl_seconds: int = 300

    # Credit expiration
    credit_ttl_seconds: int | None = 604800  # 7 days

    # Commerce vault backend (pick one)
    neon_database_url: str | None = None  # Primary (serverless Postgres)

    # OpenTimestamps Bitcoin anchoring
    tollbooth_ots_enabled: str | None = None  # "true" to enable
    tollbooth_ots_calendars: str | None = None  # Comma-separated URLs

    # Credential vault location
    excalibur_vault_dir: str | None = None

    # Secure Courier (Nostr DM credential exchange)
    tollbooth_nostr_operator_nsec: str | None = None
    tollbooth_nostr_relays: str | None = None  # Comma-separated relay URLs

    # Constraint Engine (opt-in)
    constraints_enabled: bool = False
    constraints_config: str | None = None  # JSON string

    def to_tollbooth_config(self):
        """Build a TollboothConfig for passing to tollbooth library tools."""
        from tollbooth.config import TollboothConfig
        return TollboothConfig(
            constraints_enabled=self.constraints_enabled,
            constraints_config=self.constraints_config,
        )
