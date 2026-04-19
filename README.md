# eXcalibur MCP

Sword-swift posting of pretty tweets to X (Twitter) via AI agents, monetized
with Bitcoin Lightning micropayments through the DPYC(TM) Tollbooth protocol.

[![Version](https://img.shields.io/badge/version-0.8.0-blue)](https://github.com/lonniev/excalibur-mcp)
[![Python](https://img.shields.io/badge/python-3.12+-green)](https://python.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

eXcalibur is a [FastMCP](https://github.com/jlowin/fastmcp) server that lets
AI agents post to X (Twitter) with rich Unicode formatting and optional images.
Patron authentication for X uses OAuth2 Authorization Code + PKCE -- no
credentials appear in chat. Operator credentials (X app keys, BTCPay) arrive
via human-in-the-loop Secure Courier and are stored in the operator's
per-operator Neon vault schema. Tool calls are metered with
[Tollbooth DPYC(TM)](https://github.com/lonniev/tollbooth-dpyc) pre-funded
Lightning balances -- Don't Pester Your Customer.

Part of the [DPYC(TM) Honor Chain](https://github.com/lonniev/dpyc-community).

## Getting Started

Connect via FastMCP Cloud -- no local install needed:

```
https://www.fastmcp.cloud/mcp/lonniev/excalibur-mcp
```

### Step 1: Check Session

Call `excalibur_session_status` to see your current session state. If you have
an active session with funded credits, you are ready to post.

### Step 2: X OAuth2 + PKCE (Patron Credentials for X)

1. Get your Nostr npub -- use the dpyc-oracle's `how_to_join()` tool, or any
   Nostr client.
2. Call `excalibur_begin_oauth(npub=<npub>)` -- returns an `authorize_url`.
   Open the primary `authorize_url` (not a shortlink) in your browser and
   authorize the app on X.
3. Call `excalibur_check_oauth_status(npub=<npub>)` -- completes the code
   exchange, vaults the tokens, and activates your session.

Sessions are keyed by npub. Tokens are stored in the Neon vault and
auto-refresh on expiry.

### Step 3: Secure Courier (Operator Credentials)

Operator credentials (X OAuth2 app keys, BTCPay connection) are delivered via
Secure Courier (`service="excalibur-operator"`). This is a human-in-the-loop
flow: the operator consciously approves each credential delivery via their
Nostr client. On `receive_credentials`, the relay DM is destructively drained
-- credentials exist only in the Neon vault after receipt.

## Credits Model

Tool calls cost `api_sats` per call. Credits have a `tranche_lifetime` --
each purchase creates a tranche that expires after the configured lifetime.
Auth and balance tools are always free. Use `excalibur_check_balance` to see
your balance and tranche expiry. Top up via `excalibur_purchase_credits`.

## Available Tools

### Standard Tools (from the wheel)

Standard DPYC(TM) tools are registered by `register_standard_tools()` from
[tollbooth-dpyc](https://github.com/lonniev/tollbooth-dpyc). These include
session management, credit operations, Secure Courier, pricing, notarization,
and Oracle delegation. Each tool is identified by a deterministic UUID v5.

| Category | Tools |
|----------|-------|
| Session & Billing | `session_status`, `check_balance`, `account_statement`, `account_statement_infographic`, `restore_credits`, `service_status`, `check_price`, `check_authority_balance` |
| Secure Courier | `request_credential_channel`, `receive_credentials`, `forget_credentials` |
| Npub Proof | `request_npub_proof`, `receive_npub_proof` |
| Purchase | `purchase_credits`, `check_payment` |
| Pricing & Constraints | `get_pricing_model`, `set_pricing_model`, `reset_pricing_model`, `list_constraint_types` |
| Notarization | `notarize_ledger`, `list_notarizations`, `get_notarization_proof` |
| Onboarding | `get_operator_onboarding_status`, `get_patron_onboarding_status` |
| Oracle (delegated) | `oracle_about`, `oracle_how_to_join`, `oracle_lookup_member`, `oracle_get_tax_rate`, `oracle_network_advisory` |

### Domain Tools (eXcalibur-specific)

| Tool | Cost | Description |
|------|------|-------------|
| `begin_oauth` | Free | Start X OAuth2 Authorization Code + PKCE flow; returns `authorize_url` |
| `check_oauth_status` | Free | Complete the browser authorization and exchange the code for tokens |
| `post_tweet` | ad valorem | Post to X with markdown-to-Unicode rich text formatting |
| `post_tweet_image` | ad valorem | Post with an image URL or SVG banner (rendered to PNG) |

All tools that take an `npub` also accept a `proof: str` parameter for
kind-27235 Schnorr proof attestation.

## Security

- **Npub identity** -- Patrons are identified by a Nostr public key (`npub`),
  not an email or password. One keypair per role, managed by the user.
- **Kind-27235 Schnorr proof** -- Tool calls carry an NIP-98-style Schnorr
  signature proving the caller controls the claimed npub. Proof is cached for
  ~1 hour; renew via `request_npub_proof` / `receive_npub_proof`.
- **Human-in-the-loop Secure Courier** -- Credential delivery requires
  conscious operator approval via Nostr DM. On receipt, the relay message is
  destructively drained so secrets exist only in the encrypted Neon vault.
- **Per-operator Neon schema** -- Each operator's credentials are stored in an
  isolated Postgres schema with a dedicated LOGIN role. No cross-operator
  access.

## Architecture

```
src/excalibur_mcp/
  server.py        FastMCP server -- domain tools + register_standard_tools()
  config.py        Pydantic settings from environment variables
  oauth_flow.py    X-specific OAuth2 Authorization Code + PKCE wrapper
  vault.py         In-memory Bearer token session cache (keyed by npub)
  x_client.py      X API v2 client with OAuth 2.0 Bearer token auth
  formatter.py     Markdown -> Unicode rich text (bold, italic, headers)
  actor.py         OperatorProtocol implementation for tool catalog
```

**Key design choices:**

- **OAuth2 Authorization Code + PKCE** -- Patron tokens acquired via browser
  flow. `begin_oauth` returns the primary `authorize_url` (not a shortlink);
  `check_oauth_status` completes the exchange. Tokens stored in Neon vault,
  auto-refreshed on expiry. No OAuth 1.0a.
- **UUID v5 tool identity** -- Every tool (standard and domain) has a
  deterministic UUID derived from its capability name. Pricing, constraints,
  and billing all key on UUID.
- **Standard tools from the wheel** -- `register_standard_tools()` provides
  all DPYC(TM) infrastructure tools. Only domain-specific X/Twitter tools are
  defined in `server.py`.
- **Markdown to Unicode** -- Converts `**bold**`, `*italic*`, and `# headers`
  to Unicode characters that render in tweets without markup syntax.

## Self-Hosting

### Environment Variables

#### DPYC(TM) Identity (required to boot)

| Variable | Required | Description |
|----------|----------|-------------|
| `TOLLBOOTH_NOSTR_OPERATOR_NSEC` | Yes | Operator's Nostr secret key for identity bootstrap and DM encryption |

This is the only env var required to start. All other secrets (X app keys,
BTCPay credentials) arrive via Secure Courier credential templates and are
stored in the per-operator Neon vault schema.

#### Operator Credentials (via Secure Courier)

These are delivered via Secure Courier (`service="excalibur-operator"`), not
set as environment variables:

| Credential | Description |
|------------|-------------|
| `client_id` | X OAuth2 Client ID (from X Developer Portal) |
| `client_secret` | X OAuth2 Client Secret (from X Developer Portal) |
| `btcpay_host` | BTCPay Server URL |
| `btcpay_store_id` | Store ID for invoices |
| `btcpay_api_key` | API key with invoice permissions |

#### Optional Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `SEED_BALANCE_SATS` | No | Starter credits for new users (default: 0) |
| `CREDIT_TTL_SECONDS` | No | Tranche lifetime in seconds (default: 604800 = 7 days) |
| `NEON_DATABASE_URL` | No | Neon Postgres URL for persistent ledger |
| `TOLLBOOTH_NOSTR_RELAYS` | No | Comma-separated relay URLs |
| `TOLLBOOTH_OTS_ENABLED` | No | `"true"` to enable Bitcoin anchoring |
| `TOLLBOOTH_OTS_CALENDARS` | No | Comma-separated OTS calendar URLs |

## Troubleshooting

### Cold start

On first request after deploy, the service may take a few seconds to
initialize Neon connections and load the pricing model. The runtime handles
this with inline retry -- the caller receives the result after the warm-up
completes, not a "service unavailable" error.

### Credential lifecycle states

Credential-related responses describe the current lifecycle state with clear
guidance, not error messages:

| State | Meaning | Next step |
|-------|---------|-----------|
| `no_session` | No npub recognized | Call `session_status` with your npub |
| `awaiting_oauth` | OAuth flow started, browser not yet authorized | Open the `authorize_url` and authorize |
| `awaiting_courier` | Secure Courier channel opened, credentials not yet received | Reply via Nostr client with credentials JSON |
| `proof_expired` | Npub proof cache expired (~1 hour) | Call `request_npub_proof` then `receive_npub_proof` |
| `insufficient_balance` | Credits exhausted or tranche expired | Call `purchase_credits` to top up |

### Common tool call situations

- **"proof is required"** -- Call `request_npub_proof` then
  `receive_npub_proof` to prove npub ownership. The cache expires after ~1
  hour; renew with a fresh request/receive cycle.
- **"Insufficient credit balance"** -- Call `purchase_credits` to top up.
  Check tranche expiry with `check_balance`.
- **"Operator credentials not configured"** -- Operator setup issue, not the
  patron's problem.

**Don't Pester Your Customer:** Do NOT ask the patron to re-authenticate,
re-authorize, or re-do OAuth unless the response specifically says the upstream
token is expired or invalid.

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

## DPYC(TM) Ecosystem

- [dpyc-community](https://github.com/lonniev/dpyc-community) -- Registry + governance
- [tollbooth-dpyc](https://github.com/lonniev/tollbooth-dpyc) -- Python SDK for Tollbooth monetization
- [tollbooth-authority](https://github.com/lonniev/tollbooth-authority) -- Authority MCP service
- [thebrain-mcp](https://github.com/lonniev/thebrain-mcp) -- Personal Brain MCP service
- [excalibur-mcp](https://github.com/lonniev/excalibur-mcp) -- Twitter MCP service
- [dpyc-oracle](https://github.com/lonniev/dpyc-oracle) -- Community concierge

## Trademarks

DPYC, Tollbooth DPYC, and Don't Pester Your Customer are trademarks of
Lonnie VanZandt. See the
[TRADEMARKS.md](https://github.com/lonniev/dpyc-community/blob/main/TRADEMARKS.md)
in the dpyc-community repository for usage guidelines.

## License

Apache License 2.0 -- see [LICENSE](LICENSE) for details.
