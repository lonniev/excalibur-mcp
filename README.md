# eXcalibur MCP

Sword-swift posting of pretty tweets to X (Twitter) via AI agents, monetized
with Bitcoin Lightning micropayments through the DPYC(TM) Tollbooth protocol.

[![Version](https://img.shields.io/badge/version-0.34.4-blue)](https://github.com/lonniev/excalibur-mcp)
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

Part of the [DPYC(TM) Social Contract](https://github.com/lonniev/dpyc-community).

## Getting Started

Connect via Horizon -- no local install needed:

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
| OAuth (X) | `begin_oauth`, `check_oauth_status` |
| Oracle (delegated) | `oracle_about`, `oracle_how_to_join`, `oracle_lookup_member`, `oracle_get_tax_rate`, `oracle_network_advisory` |

### Domain Tools (eXcalibur-specific)

Domain tools are defined in `server.py` (with storage handlers under
`tools/`). Prices are set by the operator's pricing model -- preview any
call with `check_price`. Read and auth tools are free.

**Posting to X**

| Tool | Description |
|------|-------------|
| `post_tweet` | Post a text tweet with markdown-to-Unicode rich text formatting |
| `post_tweet_image` | Post a tweet with a hero banner image (image URL or SVG rendered to PNG) |
| `get_x_profile` | Fetch the connected X account's handle and name for this patron (free) |

**Stored posts (drafts & scheduling)**

| Tool | Description |
|------|-------------|
| `create_post` | Store a new post (draft or scheduled); returns its `post_id` |
| `get_post` | Read one stored post by id (owner-scoped) |
| `list_posts` | List your stored posts, server-side sorted, filtered, and paginated |
| `update_post` | Patch a stored post (`doc`, `publish_at`, `recurrence`, `status`) |
| `delete_post` | Delete a stored post (soft delete by default) |

**Snippets & Voice**

| Tool | Description |
|------|-------------|
| `list_snippets` | List your saved post snippets (server-side sorted/filtered/paginated) |
| `get_snippet` | Read one saved snippet by id |
| `save_snippet` | Save a reusable snippet (opening/footer/CTA) |
| `delete_snippet` | Delete a saved snippet (free, owner-scoped) |
| `get_voice` | Read your saved writing Voice (profile blurb + banned words) |
| `save_voice` | Save your per-npub writing Voice |

**AI editorial & dynamic blocks**

| Tool | Description |
|------|-------------|
| `refine_post_region` | Refine a flagged region of a post with an LLM, server-side |
| `resolve_dynamic_block` | Start resolving a dynamic (prompt-backed) post block; returns a claim check |
| `fetch_dynamic_block` | Redeem a `resolve_dynamic_block` claim check (free, proof-gated) |

**Scheduler**

| Tool | Description |
|------|-------------|
| `process_scheduled_posts` | Publish every due scheduled post (operator-only) |
| `get_scheduler_log` | Read recent scheduler-tick outcomes |
| `scheduler_status` | The scheduler's configuration and current status (free; any proven patron) |
| `scheduler_pending` | What the scheduled-post cron Worker is waiting on (operator-only) |
| `scheduler_check_now` | Run one scheduler tick now (operator-only) |

OAuth flow tools (`begin_oauth`, `check_oauth_status`) are now standard tools
provided by the wheel (see the Standard Tools table above).

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
  x_client.py      X API v2 client with OAuth 2.0 Bearer token auth
  formatter.py     Markdown -> Unicode rich text (bold, italic, headers)
  refine.py        Server-side editorial refinement for the post editor
  resolve.py       Server-side resolution of dynamic (prompt-backed) post blocks
  scheduler.py     Scheduled-post firing (publishes due posts on the owner's behalf)
  tools/           Domain storage handlers (posts, snippets, voices)
  db/              eXcalibur persistence on the wheel's NeonVault (posts, scheduler runs, migrations)
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

Certified operators bootstrap their Neon database URL from the Authority via
encrypted Nostr DM -- `NEON_DATABASE_URL` is not read from the environment.

#### Optional Tuning

| Variable | Description |
|----------|-------------|
| `TOLLBOOTH_NOSTR_RELAYS` | Comma-separated relay URLs (overrides defaults) |
| `SEED_BALANCE_SATS` | Starter credits for new users (default: 0) |
| `DPYC_REGISTRY_CACHE_TTL_SECONDS` | How long to cache the DPYC community registry (default: 300) |
| `CONSTRAINTS_ENABLED` | `"true"` to enable constraint engine evaluation on tool calls |
| `CONSTRAINTS_CONFIG` | Optional constraint-engine configuration payload |
| `SCHEDULER_WORKER_URL` | Public URL of the scheduled-post cron Worker (default: `https://excalibur-scheduler.lonniev.workers.dev`) |

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

- [tollbooth-dpyc](https://github.com/lonniev/tollbooth-dpyc) -- Python SDK for Tollbooth monetization (vault, auth, pricing, Lightning payments, Nostr identity)
- [dpyc-community](https://github.com/lonniev/dpyc-community) -- Governance registry: membership, advisories, threat model
- [dpyc-oracle](https://github.com/lonniev/dpyc-oracle) -- Community concierge (free onboarding + member lookup)
- [tollbooth-authority](https://github.com/lonniev/tollbooth-authority) -- Certification backbone (Schnorr-signed purchase-order certificates)
- [tollbooth-sample](https://github.com/lonniev/tollbooth-sample) -- Sample Operator (canonical template)
- [tollbooth-pricing-studio](https://github.com/lonniev/tollbooth-pricing-studio) -- iOS pricing-model editor / operator console
- [cypher-mcp](https://github.com/lonniev/cypher-mcp) -- Monetized graph answers: named Cypher templates over Neo4j/AuraDB
- [schwab-mcp](https://github.com/lonniev/schwab-mcp) -- Charles Schwab brokerage data
- [thebrain-mcp](https://github.com/lonniev/thebrain-mcp) -- TheBrain personal knowledge graph
- [excalibur-mcp](https://github.com/lonniev/excalibur-mcp) -- X/Twitter posting
- [taxsort-mcp](https://github.com/lonniev/taxsort-mcp) -- Tax classification + Cloudflare Pages UI
- [optionality-mcp](https://github.com/lonniev/optionality-mcp) -- Options analytics (brokerage-data operator)
- [tollbooth-oauth2-collector](https://github.com/lonniev/tollbooth-oauth2-collector) -- OAuth2 callback handler (advocate service)
- [tollbooth-shortlinks](https://github.com/lonniev/tollbooth-shortlinks) -- URL shortener utility

## Trademarks

DPYC, Tollbooth DPYC, and Don't Pester Your Customer are trademarks of
Lonnie VanZandt. See the
[TRADEMARKS.md](https://github.com/lonniev/dpyc-community/blob/main/TRADEMARKS.md)
in the dpyc-community repository for usage guidelines.

## License

Apache License 2.0 -- see [LICENSE](LICENSE) for details.
