# eXcalibur MCP

**Sword-swift posting of pretty tweets to X (Twitter) via AI agents, monetized with Bitcoin Lightning.**

[![Version](https://img.shields.io/badge/version-0.8.0-blue)](https://github.com/lonniev/excalibur-mcp)
[![Python](https://img.shields.io/badge/python-3.10+-green)](https://python.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

eXcalibur is a [FastMCP](https://github.com/jlowin/fastmcp) server that lets AI agents post to X (Twitter) with rich Unicode formatting and optional images. Patron authentication uses X OAuth2 Authorization Code + PKCE — no credentials appear in chat. Tool calls are metered with [Tollbooth DPYC](https://github.com/lonniev/tollbooth-dpyc) pre-funded Lightning balances — Don't Pester Your Customer.

Part of the [DPYC Honor Chain](https://github.com/lonniev/dpyc-community).

## Getting Started

Connect via FastMCP Cloud — no local install needed:

```
https://www.fastmcp.cloud/mcp/lonniev/excalibur-mcp
```

### Patron Onboarding (OAuth2 + PKCE)

1. **Get your Nostr npub** — use the dpyc-oracle's `how_to_join()` tool, or any Nostr client.
2. **Call `begin_oauth(npub=<npub>)`** — returns an authorization URL.
3. **Open the URL in your browser** and authorize the app on X.
4. **Call `check_oauth_status(npub=<npub>)`** — completes the token exchange and activates your session.

Sessions are keyed by npub. Tokens are stored in the Neon vault and auto-refresh on expiry.

## Available Tools

### Standard Tools (from the wheel)

Standard DPYC tools are registered by `register_standard_tools()` from [tollbooth-dpyc](https://github.com/lonniev/tollbooth-dpyc). These include session management, credit operations, Secure Courier, pricing, notarization, and Oracle delegation. Each tool is identified by a deterministic UUID v5.

| Category | Tools |
|----------|-------|
| Session & Billing | `session_status`, `check_balance`, `account_statement`, `account_statement_infographic`, `restore_credits`, `service_status`, `check_price`, `check_authority_balance` |
| Secure Courier | `request_credential_channel`, `receive_credentials`, `forget_credentials` |
| Purchase | `purchase_credits`, `check_payment` |
| Pricing & Constraints | `get_pricing_model`, `set_pricing_model`, `reset_pricing_model`, `list_constraint_types` |
| Notarization | `notarize_ledger`, `list_notarizations`, `get_notarization_proof` |
| Onboarding | `get_operator_onboarding_status`, `get_patron_onboarding_status` |
| Oracle (delegated) | `oracle_about`, `oracle_how_to_join`, `oracle_lookup_member`, `oracle_get_tax_rate`, `oracle_network_advisory` |

### Domain Tools (eXcalibur-specific)

| Tool | Cost | Description |
|------|------|-------------|
| `begin_oauth` | Free | Start X OAuth2 Authorization Code + PKCE flow; returns authorization URL |
| `check_oauth_status` | Free | Poll for browser authorization and exchange code for tokens |
| `post_tweet` | ad valorem | Post to X with markdown-to-Unicode rich text formatting |
| `post_tweet_image` | ad valorem | Post with an image URL or SVG banner (rendered to PNG) |

All tools that take an `npub` also accept a `proof: str` parameter for operator proof attestation.

## Architecture

```
src/excalibur_mcp/
  server.py        FastMCP server — domain tools + register_standard_tools()
  config.py        Pydantic settings from environment variables
  oauth_flow.py    X-specific OAuth2 Authorization Code + PKCE wrapper
  vault.py         In-memory Bearer token session cache (keyed by npub)
  x_client.py      X API v2 client with OAuth 2.0 Bearer token auth
  formatter.py     Markdown -> Unicode rich text (bold, italic, headers)
  actor.py         OperatorProtocol implementation for tool catalog
```

**Key design choices:**

- **OAuth2 Authorization Code + PKCE** — patron tokens acquired via browser flow, stored in Neon vault, auto-refreshed on expiry. No OAuth 1.0a.
- **UUID v5 tool identity** — every tool (standard and domain) has a deterministic UUID derived from its capability name. Pricing, constraints, and billing all key on UUID.
- **Standard tools from the wheel** — `register_standard_tools()` provides all DPYC infrastructure tools. Only domain-specific X/Twitter tools are defined in `server.py`.
- **Markdown to Unicode** converts `**bold**`, `*italic*`, and `# headers` to Unicode characters that render in tweets without markup syntax.

## Self-Hosting

### Environment Variables

#### X OAuth2 App (Operator Credentials)

| Variable | Required | Description |
|----------|----------|-------------|
| `client_id` | Yes | X OAuth2 Client ID (from X Developer Portal) |
| `client_secret` | Yes | X OAuth2 Client Secret (from X Developer Portal) |

These are delivered via Secure Courier (`service="excalibur-operator"`) along with BTCPay credentials.

#### BTCPay Server

| Variable | Required | Description |
|----------|----------|-------------|
| `btcpay_host` | Yes | BTCPay Server URL |
| `btcpay_store_id` | Yes | Store ID for invoices |
| `btcpay_api_key` | Yes | API key with invoice permissions |

#### DPYC Identity & Commerce

| Variable | Required | Description |
|----------|----------|-------------|
| `SEED_BALANCE_SATS` | No | Starter credits for new users (default: 0) |
| `CREDIT_TTL_SECONDS` | No | Credit expiration (default: 604800 = 7 days) |
| `NEON_DATABASE_URL` | No | Neon Postgres URL for persistent ledger |
| `DPYC_REGISTRY_URL` | No | DPYC community registry URL (auto-resolved from GitHub) |
| `DPYC_REGISTRY_CACHE_TTL_SECONDS` | No | Registry cache TTL (default: 300) |

#### Secure Courier

| Variable | Required | Description |
|----------|----------|-------------|
| `TOLLBOOTH_NOSTR_OPERATOR_NSEC` | Yes | Operator's Nostr secret key for DM encryption |
| `TOLLBOOTH_NOSTR_RELAYS` | No | Comma-separated relay URLs |

#### OpenTimestamps

| Variable | Required | Description |
|----------|----------|-------------|
| `TOLLBOOTH_OTS_ENABLED` | No | `"true"` to enable Bitcoin anchoring |
| `TOLLBOOTH_OTS_CALENDARS` | No | Comma-separated OTS calendar URLs |

## Development

```bash
# Install in development mode
cd excalibur-mcp
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
.venv/bin/pytest tests/

# Type checking
mypy src/excalibur_mcp/

# Formatting
black src/ tests/
ruff check src/ tests/
```

## Trademarks

DPYC, Tollbooth DPYC, and Don't Pester Your Customer are trademarks of Lonnie VanZandt. See the [TRADEMARKS.md](https://github.com/lonniev/dpyc-community/blob/main/TRADEMARKS.md) in the dpyc-community repository for usage guidelines.

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
