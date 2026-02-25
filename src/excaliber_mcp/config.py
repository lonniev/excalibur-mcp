"""eXcaliber-mcp settings loaded from environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """eXcaliber MCP server settings."""

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

    # Tollbooth royalty (operator originator payout)
    tollbooth_royalty_address: str | None = None
    tollbooth_royalty_percent: float = 0.02
    tollbooth_royalty_min_sats: int = 10

    # Authority certificate verification (Ed25519 public key PEM)
    authority_public_key: str | None = None
    credit_ttl_seconds: int | None = 604800  # 7 days

    # Commerce vault backend (pick one)
    neon_database_url: str | None = None  # Primary (serverless Postgres)

    # Credential vault location
    excaliber_vault_dir: str | None = None
