# eXcalibur MCP

**Sword-swift posting of pretty tweets to X (Twitter) via AI agents, monetized with Bitcoin Lightning.**

[![Version](https://img.shields.io/badge/version-0.6.9-blue)](https://github.com/lonniev/excalibur-mcp)
[![Python](https://img.shields.io/badge/python-3.10+-green)](https://python.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

eXcalibur is a [FastMCP](https://github.com/jlowin/fastmcp) server that lets AI agents post to X (Twitter) with rich Unicode formatting and optional images. Credentials are delivered via encrypted Nostr DMs (the "Secure Courier") so they never appear in chat. Tool calls are metered with [Tollbooth DPYC™](https://github.com/lonniev/tollbooth-dpyc) pre-funded Lightning balances — Don't Pester Your Customer™.

Part of the [DPYC™ Honor Chain](https://github.com/lonniev/dpyc-community).

## Getting Started

Connect via FastMCP Cloud — no local install needed:

```
https://www.fastmcp.cloud/mcp/lonniev/excalibur-mcp
```

### First-Time Onboarding (Secure Courier)

1. **Get your Nostr npub** — use the dpyc-oracle's `how_to_join()` tool, or any Nostr client.
2. **Call `request_credential_channel(recipient_npub=<npub>)`** — a welcome DM arrives in your Nostr inbox.
3. **Reply to the welcome DM** with your X API credentials in the JSON format shown. Credentials travel on an encrypted Nostr channel and never appear in this chat.
4. **Call `receive_credentials(sender_npub=<npub>)`** — credentials are vaulted. Returning users just call `receive_credentials` again — vault-first lookup activates instantly, no relay I/O needed.

## Available Tools

### Free (Session & Billing)

| Tool | Description |
|------|-------------|
| `health` | Version and runtime status |
| `service_status` | BTCPay connectivity, Secure Courier status, component versions |
| `session_status` | Current session state (active, expired, or missing) |
| `request_credential_channel` | Open Secure Courier Nostr DM channel for credential delivery |
| `receive_credentials` | Pick up NIP-44 encrypted credentials from Nostr relay or vault cache |
| `forget_credentials` | Delete vaulted credentials for key rotation or re-delivery |
| `register_credentials` | *(Legacy)* Store credentials via passphrase — prefer Secure Courier |
| `activate_session` | *(Legacy)* Decrypt stored credentials via passphrase — prefer `receive_credentials` |
| `purchase_credits` | Create a Lightning invoice to fund your balance |
| `check_payment` | Poll invoice settlement and credit balance |
| `restore_credits` | Emergency recovery — re-credit from a paid invoice lost to cache/vault issues |
| `check_balance` | Balance, tier info, and usage summary |
| `account_statement` | 30-day purchase and usage ledger history |

### Paid

| Tool | Cost | Description |
|------|------|-------------|
| `post_tweet` | 1 api_sat | Post to X with markdown-to-Unicode rich text formatting |
| `post_tweet` (with image) | 2 api_sats | Post with an image URL (fetched and uploaded, up to 5 MB) |
| `account_statement_infographic` | 1 api_sat | SVG dark-themed infographic of your account activity |

## Secure Courier Protocol

Credentials never appear in the chat window. They travel on a separate, encrypted Nostr channel:

```
You (Nostr client)              eXcalibur (Operator)           Claude (Chat)
     |                                |                            |
     |    [NIP-44 encrypted DM]       |                            |
     |------------------------------->|   receive_credentials()    |
     |                                |<---------------------------|
     |                                |--- decrypt, validate ----->|
     |                                |    store in vault          |
     |                                |--- session activated ----->|
     |                                |                            |
     |    [relay copy deleted]        |                            |
```

- **NIP-44** (AES-256-CBC) encryption between your Nostr key and the operator's key
- Relay copy **deleted via NIP-09** after successful pickup
- Subsequent sessions retrieve from the vault — no relay I/O needed
- On first-time receipt, a **credential card** (`ncred1...`) is DM'd back for scan-and-paste reuse

The Secure Courier is provided by [Tollbooth DPYC™](https://github.com/lonniev/tollbooth-dpyc) — eXcalibur doesn't manage auth internally.

## Actor Protocol

The `ExcaliburOperator` class (in `actor.py`) satisfies `OperatorProtocol` from [Tollbooth DPYC™](https://github.com/lonniev/tollbooth-dpyc). It's a thin delegation layer over existing `server.py` tool functions.

```python
from excalibur_mcp.actor import ExcaliburOperator
from tollbooth import OperatorProtocol

assert isinstance(ExcaliburOperator(), OperatorProtocol)
```

The actor exposes:

- **`slug`** — returns `"excalibur"` for tool-name prefixing
- **`tool_catalog()`** — returns `list[ToolPathInfo]` metadata for all protocol tools

| Path | Tools | Status |
|------|-------|--------|
| Hot (local ledger) | `check_balance`, `account_statement`, `account_statement_infographic`, `restore_credits`, `service_status` | Implemented — delegates to server.py |
| Hot (Secure Courier) | `session_status`, `request_credential_channel`, `receive_credentials`, `forget_credentials` | Implemented — Tollbooth DPYC™ Secure Courier |
| Delegation (Authority) | `purchase_credits`, `check_payment`, `certify_credits`, `register_operator`, `operator_status` | Live — MCP-to-MCP via Authority |
| Delegation (Oracle) | `lookup_member`, `how_to_join`, `get_tax_rate`, `about`, `network_advisory` | Live — MCP-to-MCP via Oracle |

Payment processing and certificate acquisition are delegated to the Tollbooth Authority via MCP-to-MCP calls. Community queries route directly to the DPYC™ Oracle.

## Self-Hosting

### Environment Variables

#### X API (Operator Credentials)

| Variable | Required | Description |
|----------|----------|-------------|
| `X_API_KEY` | Yes | Operator's X API consumer key |
| `X_API_SECRET` | Yes | Operator's X API consumer secret |
| `X_ACCESS_TOKEN` | No | Operator's X access token (STDIO fallback) |
| `X_ACCESS_TOKEN_SECRET` | No | Operator's X access token secret (STDIO fallback) |

#### BTCPay Server

| Variable | Required | Description |
|----------|----------|-------------|
| `BTCPAY_HOST` | Yes | BTCPay Server URL |
| `BTCPAY_STORE_ID` | Yes | Store ID for invoices |
| `BTCPAY_API_KEY` | Yes | API key with invoice permissions |
| `BTCPAY_TIER_CONFIG` | No | JSON tier multiplier config |
| `BTCPAY_USER_TIERS` | No | JSON mapping npubs to tier names |

#### DPYC™ Identity & Commerce

| Variable | Required | Description |
|----------|----------|-------------|
| `SEED_BALANCE_SATS` | No | Starter credits for new users (default: 0) |
| `CREDIT_TTL_SECONDS` | No | Credit expiration (default: 604800 = 7 days) |
| `NEON_DATABASE_URL` | No | Neon Postgres URL for persistent ledger |
| `DPYC_REGISTRY_URL` | No | DPYC™ community registry URL (auto-resolved from GitHub) |
| `DPYC_REGISTRY_CACHE_TTL_SECONDS` | No | Registry cache TTL (default: 300) |

> **Note:** `DPYC_OPERATOR_NPUB` and `DPYC_AUTHORITY_NPUB` are no longer needed — Operator and Authority npubs are now resolved automatically from the [DPYC™ community registry](https://github.com/lonniev/dpyc-community).

#### Royalty Payouts

| Variable | Required | Description |
|----------|----------|-------------|
| `TOLLBOOTH_ROYALTY_ADDRESS` | No | Lightning Address for royalty payouts |
| `TOLLBOOTH_ROYALTY_PERCENT` | No | Royalty percentage (default: 0.02) |
| `TOLLBOOTH_ROYALTY_MIN_SATS` | No | Minimum royalty payout in sats (default: 10) |

#### Secure Courier

| Variable | Required | Description |
|----------|----------|-------------|
| `TOLLBOOTH_NOSTR_OPERATOR_NSEC` | Yes | Operator's Nostr secret key for DM encryption |
| `TOLLBOOTH_NOSTR_RELAYS` | No | Comma-separated relay URLs |
| `EXCALIBUR_VAULT_DIR` | No | Credential vault directory (default: `~/.excalibur/vault`) |

#### OpenTimestamps

| Variable | Required | Description |
|----------|----------|-------------|
| `TOLLBOOTH_OTS_ENABLED` | No | `"true"` to enable Bitcoin anchoring |
| `TOLLBOOTH_OTS_CALENDARS` | No | Comma-separated OTS calendar URLs |

## Architecture

```
src/excalibur_mcp/
  server.py        FastMCP server — 15 tools, Tollbooth credit gating
  config.py        Pydantic settings from environment variables
  vault.py         PBKDF2+Fernet credential vault (OWASP 2023, 600k iterations)
  x_client.py      X API v2 client with OAuth 1.0a manual signing
  formatter.py     Markdown → Unicode rich text (bold, italic, headers)
  infographic.py   SVG account statement generator (dark theme, sword/gold branding)
```

**Key design choices:**

- **OAuth 1.0a manual signing** — not authlib — because X API v2 JSON payloads require signing the *body*, which most OAuth libraries don't support correctly.
- **PBKDF2+Fernet** for at-rest credential encryption with 600,000 iterations (OWASP 2023 recommendation).
- **Markdown → Unicode** converts `**bold**`, `*italic*`, and `# headers` to Unicode characters that render in tweets without markup syntax.

## Development

```bash
# Install in development mode
cd excalibur-mcp
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests (161 tests across 8 test files)
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
