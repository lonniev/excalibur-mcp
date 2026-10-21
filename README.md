# eXcalibur MCP

Sword-swift posting of pretty tweets to X (Twitter) via AI agents, monetized
with Bitcoin Lightning micropayments through the DPYC(TM) Tollbooth protocol.

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
https://excalibur-mcp.fastmcp.app/mcp
```

The web editor at <https://excalibur.tollbooth-dpyc.com> drives the same tools
from a browser.

### Step 1: Check Session

Call `excalibur_session_status` to see your current session state. If you have
an active session with funded credits, you are ready to post.

### Step 2: Prove Your Npub on the Connection

Identity rides on the connection, not on tool arguments. Connecting from an AI
assistant is an OAuth holder connection: call
`excalibur_request_npub_proof(patron_npub=<npub>)`, reply to the Nostr DM it
sends, then call `excalibur_receive_npub_proof(patron_npub=<npub>, nonce=<nonce>)`
once. The connection then holds your npub for the lifetime you chose in the
reply (up to 30 days), and every tool call passes only `npub`. A caller that
holds the nsec may instead sign each HTTP request (NIP-98).

### Step 3: X OAuth2 + PKCE (Patron Credentials for X)

1. Get your Nostr npub -- use the dpyc-oracle's `how_to_join()` tool, or any
   Nostr client.
2. Call `excalibur_begin_oauth(npub=<npub>)` -- returns an `authorize_url`.
   Open the primary `authorize_url` (not a shortlink) in your browser and
   authorize the app on X.
3. Call `excalibur_check_oauth_status(npub=<npub>)` -- completes the code
   exchange, vaults the tokens, and activates your session.

Sessions are keyed by npub. Tokens are stored in the Neon vault and
auto-refresh on expiry.

### Step 4: Secure Courier (Operator Credentials)

Operator credentials (X OAuth2 app keys, BTCPay connection) are delivered via
Secure Courier (`service="excalibur-operator"`). This is a human-in-the-loop
flow: the operator consciously approves each credential delivery via their
Nostr client. On `receive_credentials`, the relay DM is destructively drained
-- credentials exist only in the Neon vault after receipt.

## Credits Model

Tool calls cost `api_sats` per call. Each purchase creates a tranche; it
expires only if the operator's pricing model sets a `tranche_lifetime`.
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
| Secure Courier | `request_credential_channel`, `receive_credentials`, `forget_credentials`, `update_operator_credential`, `delete_operator_credential`, `update_patron_credential`, `delete_patron_credential`, `get_patron_credential_fields` |
| Npub Proof | `request_npub_proof`, `receive_npub_proof`, `check_proof_status`, `held_identities` |
| Purchase & Coupons | `purchase_credits`, `check_payment`, `mint_coupon`, `list_coupons`, `update_coupon`, `delete_coupon`, `redeem_coupon`, `list_my_coupons`, `forget_coupon` |
| Pricing & Constraints | `get_pricing_model`, `set_pricing_model`, `reset_pricing_model`, `list_constraint_types`, `list_canonical_identities` |
| Notarization | `notarize_ledger`, `list_notarizations`, `get_notarization_proof` |
| Onboarding & Adoption | `get_operator_onboarding_status`, `get_patron_onboarding_status`, `request_adoption`, `adoption_status`, `restore_neon_schema` |
| Nostr & Diagnostics | `get_nostr_profile`, `publish_nostr_profile`, `request_echo`, `report_issue` |
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
| `post_nostr_message` | Publish a public Nostr note (kind 1) for your proven npub, signed by an ephemeral scribe key that `p`-tags you |

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

**Conversation leads**

| Tool | Description |
|------|-------------|
| `find_conversations` | Search X for people asking questions you could answer; score and store them as leads |
| `list_conversations` | Page through your stored leads (free) |
| `reply_to_conversation` | Post your reply into a lead's thread on X and mark the lead engaged |
| `set_conversation_status` | Mark a lead new, seen, engaged or dismissed (free) |
| `list_conversation_queries` | List your saved conversation queries (free) |
| `save_conversation_query` | Create or update a saved conversation query (free) |
| `delete_conversation_query` | Delete a saved query; its leads are kept (free) |

**Post metrics**

| Tool | Description |
|------|-------------|
| `harvest_metrics` | Cadence-aware sweep that snapshots X metrics for sent posts (operator-only) |
| `get_post_metrics` | Read the metrics snapshot series for one of your posts |
| `post_performance` | Derived reach scores across your harvested post metrics |
| `post_performance_infographic` | SVG infographic of post performance |

**Scheduler**

| Tool | Description |
|------|-------------|
| `process_scheduled_posts` | Publish every due scheduled post (operator-only) |
| `get_scheduler_log` | Read recent scheduler-tick outcomes |
| `scheduler_status` | The scheduler's configuration and current status (free; any proven patron) |
| `scheduler_pending` | What the scheduled-post cron Worker is waiting on (operator-only) |
| `scheduler_check_now` | Run one scheduler tick now (any proven patron) |
| `scheduler_reissue` | Send the scheduler's proof request again, now (operator-only) |

OAuth flow tools (`begin_oauth`, `check_oauth_status`) are now standard tools
provided by the wheel (see the Standard Tools table above).

Tools that take an `npub` take only the `npub`: the connection proves it (see
Security).

## Security

- **Npub identity** -- Patrons are identified by a Nostr public key (`npub`),
  not an email or password. One keypair per role, managed by the user.
- **Identity on the connection** -- A connection proves its npub in one of
  two ways: each HTTP request is signed with the npub's key (NIP-98, kind
  27235), or an OAuth holder connection carries an Operator-signed grant
  earned through `request_npub_proof` / `receive_npub_proof`. The patron
  chooses the grant's lifetime, up to 30 days; `held_identities` and
  `check_proof_status` show what a connection holds.
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
  resolver.py      Builds one post's finished body (the slow half: dynamic blocks)
  publisher.py     Carries a finished body to X (the fast half: bill, post, record)
  scheduler.py     Scheduled-post firing (publishes due posts on the owner's behalf)
  conversation_scoring.py  Pure scoring + query composition for conversation leads
  metrics_harvest.py       Post-metrics harvest cadence and derived reach scores
  nostr_note.py    Public Nostr notes signed by an ephemeral scribe key
  tools/           Domain storage handlers (posts, snippets, voices, conversations, metrics)
  db/              eXcalibur persistence on the wheel's NeonVault (posts, snippets, voices,
                   conversations, metrics, scheduler runs, migrations)
modal_app.py       Detached runner for long dynamic-block resolves (Modal)
scheduler-worker/  Cloudflare Worker cron that fires due scheduled posts
frontend/          The web editor (excalibur.tollbooth-dpyc.com)
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
| `llm_api_key` | Optional. Model-router key (OpenRouter by default) for `refine_post_region` and dynamic blocks; posting works without it |
| `modal_token_id`, `modal_token_secret`, `modal_app_name` | Optional. Modal workspace that runs long dynamic-block resolves detached from the MCP host |
| `github_repo`, `github_token` | Optional. Where `report_issue` files patron field reports (token needs only `issues:write`) |

Certified operators bootstrap their Neon database URL from the Authority via
encrypted Nostr DM -- `NEON_DATABASE_URL` is not read from the environment.

#### Optional Tuning

| Variable | Description |
|----------|-------------|
| `SCHEDULER_WORKER_URL` | Public URL of the scheduled-post cron Worker (default: `https://excalibur-scheduler.lonniev.workers.dev`) |
| `RESOLVE_BLOCK_BUDGET_MAX_S` | Ceiling, in seconds, on one dynamic block's LLM run (default: 1800); the job, lease and runner timeouts are derived from it |

## Troubleshooting

### Cold start

On first request after deploy, the service may take a few seconds to
initialize Neon connections and load the pricing model. The runtime handles
this with inline retry -- the caller receives the result after the warm-up
completes, not a "service unavailable" error.

### Common tool call situations

Responses describe the current lifecycle state with guidance on the next step,
not bare error messages.

- **`proof_required`** -- The connection does not prove that npub (or its
  grant expired). Call `request_npub_proof`, reply to the DM, then
  `receive_npub_proof` once. `check_proof_status` shows how long a grant has
  left.
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
- [optionality-mcp](https://github.com/lonniev/optionality-mcp) -- Options-trading practice game
- [goodearth-mcp](https://github.com/lonniev/goodearth-mcp) -- Region-scoped climate analytics for small farms
- [beesknees-mcp](https://github.com/lonniev/beesknees-mcp) -- The Bee's Knees race game
- [roastify-mcp](https://github.com/lonniev/roastify-mcp) -- Roastify coffee catalog and packaging artwork
- [ChartRemotely-mcp](https://github.com/lonniev/ChartRemotely-mcp) -- Puts a security on a desktop chart remotely
- [tollbooth-web](https://github.com/lonniev/tollbooth-web) -- Shared browser SDK for operator front ends
- [tollbooth-oauth2-collector](https://github.com/lonniev/tollbooth-oauth2-collector) -- OAuth2 callback handler (advocate service)
- [tollbooth-shortlinks](https://github.com/lonniev/tollbooth-shortlinks) -- URL shortener utility

## Trademarks

DPYC, Tollbooth DPYC, and Don't Pester Your Customer are trademarks of
Lonnie VanZandt. See the
[TRADEMARKS.md](https://github.com/lonniev/dpyc-community/blob/main/TRADEMARKS.md)
in the dpyc-community repository for usage guidelines.

## License

Apache License 2.0 -- see [LICENSE](LICENSE) for details.
