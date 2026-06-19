# eXcalibur Scheduler Worker

A Cloudflare Worker cron that fires eXcalibur's due scheduled posts. **Deploy is
deferred** — commit the source now; wire it up when the Cloudflare project for
the editorial FE is created.

## What it does

Every ~10 minutes the Worker calls the operator-only
`excalibur_process_scheduled_posts` MCP tool. The MCP does everything else:
selects `scheduled` posts past their `publish_at`, bills each post's owner for
`post_tweet` (tranche-expiry guard intact), posts to X, stamps `last_sent_at`,
and reschedules from `recurrence` or retires the post past `cease_at`.

The Worker holds **no operator nsec and no domain logic** — only the operator's
long-lived npub **proof_token**, the same proof mechanism patrons use.

## One-time setup (at deploy)

1. **Mint a long-lived operator proof.** As the operator, run the
   `request_npub_proof` → reply → `receive_npub_proof` flow for the *operator's*
   npub, requesting up to a 30-day delegation (e.g. `"30 days"`; the SDK caps at
   30). Keep the returned `proof_token`.
2. **Confirm `MCP_URL`** in `wrangler.toml` points at the deployed eXcalibur MCP
   streamable-HTTP endpoint, and that a single `tools/call` POST is accepted
   (FastMCP may require an initialize handshake / session header — adjust
   `src/index.ts` if so).
3. **Set secrets:**
   ```sh
   wrangler secret put OPERATOR_NPUB    # npub1...
   wrangler secret put OPERATOR_PROOF   # the proof_token from step 1
   ```
4. `wrangler deploy`.

## Renewal

The proof_token expires after the chosen delegation (≤30 days). Before it lapses,
repeat step 1 and update the `OPERATOR_PROOF` secret. A lapsed token makes the
tool reject the tick (`proof_required`) — posts stay `scheduled`, none are lost.
