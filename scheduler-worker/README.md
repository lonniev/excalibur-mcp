# eXcalibur Scheduler Worker

A Cloudflare Worker cron that fires eXcalibur's due scheduled posts.

## What it does

Every 30 minutes (on the hour and the half hour) the Worker calls the
operator-only `excalibur_process_scheduled_posts` MCP tool. The wider cadence
lets the Neon compute scale to zero between ticks instead of being pinned awake;
patrons who need immediacy use "Post now" in the UI. The MCP does everything else:
selects `scheduled` posts past their `publish_at`, bills each post's owner for
`post_tweet` (tranche-expiry guard intact), posts to X, stamps `last_sent_at`,
and reschedules from `recurrence` or retires the post past `cease_at`.

## No stored secrets — it honors the npub-proof protocol

A worker acting on an npub's behalf is just another actor. It does **not** hold
the operator's nsec and does **not** bake a proof token into a secret — and it
isn't even provisioned with the operator's npub. The MCP **is** the operator (it
holds the nsec), so each tick the worker asks it "who are you?" via the free,
unauthenticated `list_canonical_identities` tool, which returns `operator_npub`.
It then runs the same Secure Courier dance the FE and the Claude.ai chat use, and
caches only the short-lived token it gets back (in KV — the role localStorage
plays for the FE):

0. **Ask the MCP its npub** → `list_canonical_identities()` → `operator_npub`.
1. **No/expired token** → `request_npub_proof(operator_npub)` sends a Secure
   Courier DM to the operator npub. (Both proof tools are bootstrap — callable
   without prior auth.)
2. A **key-holder replies once** — the operator, via Pricing Studio or any
   nsec-holding agent. This reply is the consent.
3. Next tick → `receive_npub_proof(operator_npub, poison)` returns a proof token
   (≤30 days). It's **poison-scoped**, so polling only pops the matching reply —
   it never drains other DMs.
4. The token is cached in KV and used for `process_scheduled_posts`. Steady-state
   ticks make no courier calls at all.
5. At expiry the cycle repeats (~monthly): one DM, one reply, done. A lapsed or
   rejected token is cleared automatically; scheduled posts are never lost — they
   just wait for the next authorized tick.

The only configuration is **public**: the MCP URL. The operator npub is
discovered from the MCP at runtime, not provisioned.

## One-time setup (at deploy)

1. Confirm `MCP_URL` in `wrangler.toml` (no npub to set — it's self-discovered).
2. **Create the KV namespace** and paste its id into `wrangler.toml`:
   ```sh
   wrangler kv namespace create PROOF_KV
   ```
3. `npm install && wrangler deploy`.
4. **Authorize once:** the first tick (or `GET` the worker URL to trigger one)
   sends the proof DM to the operator npub. Reply from Studio (or any holder of
   the operator nsec). The next tick completes the proof and starts posting.

## Verify at deploy

- The Worker uses `@modelcontextprotocol/sdk` `StreamableHTTPClientTransport`
  against `MCP_URL`. Confirm the transport connects from the Workers runtime; if
  the SDK's streaming client misbehaves on Workers, fall back to a hand-rolled
  `initialize` + `tools/call` POST with the `mcp-session-id` header.
- Trigger a manual tick with `GET <worker-url>` and read the response string for
  the current phase (awaiting reply / posting / etc.).
