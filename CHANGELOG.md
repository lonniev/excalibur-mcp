# Changelog

All notable changes to this project will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.28.2] — 2026-07-01

### Fixed — flag a selection that spans multiple blocks

- Selecting text across 2+ blocks used to be rejected for flagging (the handler required the whole selection to sit inside one block). The selection is now mapped onto every block it covers — the start block's tail, any whole middle blocks, and the end block's head — and the "Flag for AI" chiclet creates a flag in each. Single-block selections are unchanged. Parts that overlap an existing flag are skipped.

## [0.28.1] — 2026-07-01

### Changed — bigger, always-visible block action bar (was tiny hover-only icons over the text)

- The per-block actions (Edit, Make Dynamic, Flag, Delete, move) were tiny (14px) icons in a hover-only overlay positioned ON the block text — hard to hit (especially on touch, where there is no hover) and they obscured the words. Replaced with an always-visible action bar BELOW each block: touch-sized labelled buttons that never cover the text. Dynamic-block cards get the same treatment (visible Run / Make static / Delete row). Cross-block text selection is unchanged.
- Added a per-block "Flag" button (flags the whole block for AI review) so flagging no longer requires a precise text selection — the floating select-to-flag pill still works for phrases.

## [0.28.0] — 2026-06-30

### Added — long dynamic-block posts defer to the scheduler; the runtime budget reaches the LLM

- **Post Now hands the editor back for long posts.** In `handlePostNow`, if any dynamic block's runtime budget exceeds ~30s, the post is saved **unresolved** as `scheduled` at `now+10s` instead of resolving synchronously in the browser — so the author gets control back immediately. The cron worker resolves the blocks server-side and posts. (Static / short-budget posts still post inline.)
- **The author's runtime budget now drives the LLM call.** `resolve_block`/`build_anthropic_request` gain `timeout_seconds`; the scheduler passes each block's `runtimeLimit`, and the claim-check runner + detached closure thread it too. Previously every resolve was capped at a fixed 210s regardless of the declared budget.
- **Scheduler tick frequency raised to every minute** (`*/10` → `* * * * *`) so a "now+10s" post fires promptly, and the worker's MCP-call timeout raised `60s → 300s` to cover a real resolve.

### Fixed — overlapping cron ticks can no longer double-post

- `process_due_posts` now **atomically claims** each due post (`scheduled → sending`) before doing any work, so two overlapping ticks (far more likely at `*/1`) can never fire the same post twice. A held post is released back to `scheduled`; a `sending` post orphaned by a crashed/timed-out tick is reclaimed after a 20-minute lease (which safely exceeds the longest possible resolve). New `claim_due_post`/`release_claim`; `list_due` includes stale `sending` for reclaim; `mark_attempt` reverts a claimed post. New transient **Sending** status badge in the Posts list.

### Note
This is the pragmatic half of an on-demand long-running-task design (HTTP/TCP wants seconds; these resolves want wall-time). Budgets beyond what the worker can wait on are covered by the planned durable-executor follow-up; until then such a post's tick may time out and reclaim/retry — never double-post.

## [0.27.2] — 2026-06-30

### Changed — the resolve poll loop now follows the backend's cadence (one algorithm)

- `resolveDynamicBlock` used its own client-side backoff (`4s → ×1.6 → 15s`) and **ignored** the `poll_after_seconds` the backend returns. The backend now has the better, budget-aware algorithm (a long first wait sized to the author's declared runtime, then tightening as the deadline nears), so the FE follows that value **verbatim** — seeded from `start.poll_after_seconds` and updated from each `fetch_dynamic_block`'s `poll_after_seconds`. One cadence, owned server-side; no duplicate client backoff to drift.
- Dropped `POLL_START_MS`/`POLL_CEILING_MS`/`POLL_FACTOR`; added a `DEFAULT_POLL_SECONDS = 5` fallback used only if an older server omits the field. The overall client deadline (sized to the budget) is unchanged.

## [0.27.1] — 2026-06-30

### Fixed — Post Now no longer silently drops the Sent record (frontend-only)

- `handlePostNow` recorded a post as Sent after a successful tweet via `create_post`/`update_post`, but a soft-fail there (the tool's `catch_errors` returns `{success:false,…}` rather than throwing) was swallowed: a new post got only a quiet hint, and an **existing** post's `updatePost` result was ignored outright. So the tweet went out while the row silently stayed a draft and the UI still said "Posted." (This is what made the recent scheduler/dpop_token breakage so hard to trace from the browser.)
- Now both branches check the result and, on failure, **surface the `error_code` to the editor's error banner and `debugPush` it** to the debug panel — while still showing the live tweet URL — so an after-send save failure can never again be invisible.

## [0.27.0] — 2026-06-30

### Added — author-declared time budget per dynamic block (ad-valorem ready)

- A dynamic block now carries an optional **time budget** (`runtimeLimit`, seconds, clamped 60–900, default 210). The editor exposes it as a numeric input beside the web-lookup budget on each dynamic-block card.
- `resolve_dynamic_block` gains a top-level `runtime_limit_seconds` parameter. It sets the async job's runtime ceiling **and** is passed as the wheel's new `expected_seconds`, so the claim-check poll cadence trusts it (first poll ≈75% of the budget, then tightens) instead of a steady tick. Because it's a named tool argument, an operator can price it **ad valorem** via a `price_type="percent"` entry keyed to `runtime_limit_seconds` in Pricing Studio — no further code needed.
- The browser resolve loop now scales its client-side timeout to the declared budget (was a flat 5 min), so a long block can finish in Preview/Run.

### Changed — bump `tollbooth-dpyc[nostr,prefect]==0.59.0`

- Picks up `start_async_job(expected_seconds=...)` and the budget-aware `poll_backoff_seconds`.

## [0.26.0] — 2026-06-29

### Changed — adopt the wheel's `dpop_token` rename (lockstep with tollbooth-dpyc 0.57.0)

- Bump `tollbooth-dpyc[nostr,prefect]==0.57.0`, which renames the Secure Courier
  possession token to `dpop_token` everywhere it is code-/wire-visible — retiring
  `proof` (paid-call param), `proof_token` (request_npub_proof return), and
  `poison` (receive param). This is a lockstep change: a consumer on 0.57.0 still
  declaring `proof` fails every paid call, so eXcalibur moves in the same release.
- Backend: every domain tool's `proof: str = ""` parameter → `dpop_token: str = ""`
  (the wheel's `paid_tool` decorator now reads `dpop_token`).
- Frontend: the paid-call envelope sends `dpop_token` (was `proof`); the DM-login
  flow reads `dpop_token` from `request_npub_proof` and sends `dpop_token` to
  `receive_npub_proof` (were `proof_token` / `poison`). The retrieval/wait protocol
  is unchanged — symbol/wire-field rename only. The inline kind-27235 signing
  tactic keeps "proof" naming (it is a genuine proof).

## [0.25.1] — 2026-06-29

### Changed — editor surfaces the dynamic-block failure hint

- When a dynamic block can't resolve, the block already falls back to its
  fallback ("oops") text so the post stays publishable; now the editor's error
  line also appends the situation's `next_steps` (e.g. "Please try again later")
  and the `resolveDynamicBlock` wrapper passes the structured `error_code` /
  `transient` through, so future UX can branch on them. Frontend-only.

## [0.25.0] — 2026-06-29

### Added — dynamic-block failures become informative UX, not blank errors

- Bump `tollbooth-dpyc[nostr,prefect]==0.56.0` (adds `AsyncJobSituation`). Both the
  detached `shape_result` and the in-process runner now classify an Anthropic
  failure into a curated, frontend-facing situation — a machine `error_code`, safe
  copy, and a `transient` flag — instead of letting a raw HTTP error settle the
  job. The raw upstream status/body stay operator-side (Prefect logs); the DPYC
  patron never sees `400 … request_id …`.
- Mapped situations: `operator_llm_unfunded` (Anthropic "credit balance too low" —
  the real cause behind the recent 400s, reported as a 400 not a 402),
  `operator_llm_auth` (401/403), `upstream_rate_limited` (429, transient),
  `dynamic_block_empty` (2xx but no usable text), and a generic
  `dynamic_block_unresolved` fallback. `fetch_dynamic_block` returns these so the
  Posts Manager can branch its UX (retry vs. "service temporarily unavailable").

## [0.24.2] — 2026-06-29

### Changed — long-runner secrets are normal operator secrets

- Bump `tollbooth-dpyc[nostr,prefect]==0.55.3`, which removes the separate
  `dpyc-longrunner` credential service. The Prefect long-runner secrets
  (`prefect_api_url`, `prefect_api_key`, `closure_seal_key`) are now declared in
  eXcalibur's own `operator_credential_template` via the wheel-exported
  `LONGRUNNER_CREDENTIAL_FIELDS` (optional) — so they show in onboarding / the
  Pricing Studio and deliver via the normal Secure Courier card like every other
  operator secret. Template `version` 3 → 4.
- **Migration:** the three values, previously couriered under the `dpyc-longrunner`
  service, must be re-couriered once under `excalibur-operator`.

## [0.24.1] — 2026-06-29

### Fixed — dynamic-block resolution now actually runs on detached compute

- Bump `tollbooth-dpyc[nostr,prefect]==0.55.2`, which fixes `PrefectClosureExecutor`
  never authenticating to the operator's standalone Prefect account. Before this,
  `run_deployment` failed on the FastMCP/Horizon front (which sets its own
  `PREFECT_*` env) and the wheel silently fell back to the in-process runner — so
  resolve jobs ran on the recycling front after all (quick ones completed before a
  recycle and masked it). With 0.55.2 the dispatch reaches the detached pool.

## [0.24.0] — 2026-06-29

### Added — dynamic-block resolution runs on durable detached compute

- The 90–210s "resolve dynamic block" job no longer runs as an in-process
  `asyncio` task on Horizon's stateless front (which freezes/recycles mid-run and
  silently drops the work). It now offloads to the shared DPYC long-runner —
  detached Prefect-managed compute — via the generic closure path in
  `tollbooth-dpyc` 0.55.1. `resolve.py` is split into `build_anthropic_request`
  (the declarative request sealed into the closure, in-process, so the operator
  key never leaves as plaintext) and `extract_resolved_text` (shapes the detached
  result); `resolve_block` recomposes them, so the in-process runner and the
  scheduler still produce identical output and serve as the fallback.
- `server.py` registers the closure path with `register_job_spec("resolve_dynamic_block", …)`.
  No executor wiring and no credential-template changes here: the wheel
  auto-installs the detached executor once the operator has couriered the
  built-in `dpyc-longrunner` credentials, and serves in-process until then.
- Pin `tollbooth-dpyc[nostr,prefect]==0.55.1` (the `prefect` extra ships the
  `run_deployment` client used to dispatch detached runs).

## [0.23.1] — 2026-06-27

### Fixed — Posts list shows a loading state on every filter change

- Switching status tabs (or filters) refetches with MCP cold-start lag, but the
  loading entertainment only showed on the *first* load (`loading && posts.length
  === 0`); a tab switch kept the stale table on screen, so it looked like nothing
  happened and the human click-spammed the tabs. Now the `QuoteScroller` shows on
  any in-flight query, the tabs/refresh are disabled while loading (the clicked
  tab still highlights so the action reads as registered), and the refresh icon
  spins.

## [0.23.0] — 2026-06-27

### Added — dynamic-block resolution is async (claim check), surviving the edge cap

- Heavy dynamic prompts (paginate a collection, fetch product pages, web-search,
  generate) ran past the ~100s browser↔edge connection cap and failed with
  `Load failed` in Preview / Post-now. Reworked the interactive path to the
  DPYC **claim-check** pattern (wheel `start_async_job`/`fetch_async_job`):
  - `resolve_dynamic_block` now **starts a background job** and returns a claim
    check instantly (`{claim_check, status: "pending", poll_after_seconds}`).
  - New free companion `fetch_dynamic_block(claim_check)` is polled until the job
    is `done` (`result.text`); polling is short, so no single request idles past
    the edge cap. The fare is charged on the start call and refunded by the wheel
    if the job ultimately fails. Owner-scoped; the poll doubles as the watchdog
    (a stalled job re-kicks).
  - A `register_job_runner` runner loads the operator's vaulted key and calls the
    shared `resolve_block` core — the same code the scheduler calls directly, so
    scheduled fires are unchanged (already server-side).
  - FE `resolveDynamicBlock` now starts + polls under the hood (same
    `{success, text}` result), so Preview/Post-now callers are unchanged. Polling
    uses backoff (≈4s → ×1.6 → 15s ceiling) rather than the server's eager 3s
    hint, and `fetch_dynamic_block` is quiet in the debug log.
- Operator: price `fetch_dynamic_block` is free; `resolve_dynamic_block` keeps
  its existing price (charged on start).

## [0.22.0] — 2026-06-27

### Changed — dynamic blocks resolve in parallel, with sane timeouts

- A post's dynamic blocks now resolve **concurrently** (`asyncio.gather` in the
  scheduler, `Promise.all` in the editor's Post-now path) instead of
  sequentially, so a multi-dynamic post takes ~the slowest block, not the sum.
  Trade-off: blocks no longer see each other's resolved output (each gets static
  siblings + others' fallback as context) — independence for speed.
- **Timeouts made coherent** to kill the `MCP error -32001: Request timed out`:
  the resolver's Anthropic call timeout is 210s and the FE MCP client timeout for
  `resolve_dynamic_block` is 240s, so a too-slow run returns a clean
  refundable error from the server instead of a client-side `-32001`.
- Scheduler resilience unchanged and confirmed: a per-block resolve failure/timeout
  falls back (if set) or **holds the post for the next cron tick** — it never
  aborts the whole run.

### Fixed — inserting a dynamic snippet now carries its prompt + settings

- Inserting a dynamic snippet into a post produced an empty `<dynamic>` block:
  the insert built a block from the snippet's `text` body, which for a dynamic
  snippet is the composed `⟨dynamic⟩` **placeholder**, and it dropped
  domains/maxFetches. Insert now appends the snippet's stored **doc**
  (`parsePostDoc(s.doc, s.text)`), so the block carries the real prompt, fallback,
  allowed-domains, and max-fetches (static snippets still insert their text).
- Saving the focused block as a snippet from the **Post editor** now serializes a
  dynamic block's full settings into the snippet doc (previously it saved
  text-only, silently making a dynamic block static on save).

### Added — dynamic fragments are down-formatted to X-safe Unicode

- A dynamic prompt can ask for anything, but X renders only plain text with
  Unicode styling — so the resolved fragment is now normalized to X-safe output.
  New `formatter.to_x_text` strips HTML/JSX/XML tags, fenced code blocks, and
  markdown headings/image/link *syntax* (URLs left bare so X auto-links them),
  then converts inline `**bold**` / `*italic*` / `` `mono` `` to Unicode glyphs.
  `resolve_block` runs it on every fragment (Preview + scheduler).
- The resolver's system prompt now tells the model to format for X (plain text +
  Unicode emphasis, bare URLs) and to **down-format** any rich/structured/coded
  request (HTML, CSS, a JSX component, a table, a code block) to the closest
  plain X rendering — model-side down-conversion first, `to_x_text` as the net.
  (Also fixes the literal `[label](url)` markdown link that posted verbatim.)

### Fixed — dynamic fragments no longer leak the model's self-talk

- A resolved fragment sometimes carried Claude's between-tool narration ("The
  book is X… I now have enough detail to write the fragment.") glued onto the
  actual copy, because the resolver concatenated **all** of the response's text
  blocks. Now the model is told to wrap the finished fragment in `<post>…</post>`
  and keep all reasoning outside; `resolve.py` extracts only the tag contents
  (falling back to the text after the last tool block when tags are absent), so
  the deliverable is just the marketing copy.

### Changed — dynamic-block resolution no longer caps length at 280 chars

- X is long-form; the resolver's character budget (default 280, with a
  shorten-retry + hard truncation) was an artificial SMS-era limit. Removed it
  entirely — `char_budget`/`clamp_budget` and the length gate are gone from
  `resolve.py`, the `resolve_dynamic_block` tool, and the FE wrapper. The
  author's prompt now governs length ("one short sentence" vs "a few
  paragraphs"); the system prompt states there is no fixed character limit.
- Bumped the generation ceiling (`_MAX_TOKENS` 1500 → 4000, timeout 90s → 110s)
  so long-form fragments aren't truncated by the token cap, while staying under
  the FE's per-call timeout. (For truly massive output we'd switch to streaming —
  not needed for post fragments.)

### Added — dynamic blocks can fetch the web (author-scoped)

- The resolver now gives Claude the **`web_fetch`** server tool alongside
  `web_search` (both bumped to the `_20260209` dynamic-filtering variants), so a
  dynamic prompt can actually *read* a specific URL — e.g. "visit this page, pick
  a link, summarize it" — not just search the indexed web. (Search-only couldn't
  open un-indexed pages like a shop's paginated collection listings.)
- Web access is **author-controlled per block**, stored in the block's `doc`:
  an **allowed-domains** allowlist (comma/newline; blank = any URL the prompt
  references) and a **max-fetches** budget (1–25, default 5), surfaced as two
  inline fields on the dynamic-block card. They flow through
  `resolve_dynamic_block` → `resolve.py` into `web_fetch.allowed_domains` /
  `max_uses`, in both the editor Preview and the scheduler. No hardcoded domains.

### Changed — dynamic blocks are now block-level and inline (intuitive)

- Making a block dynamic is one click **on the block**: a wand toggle in the
  block's hover toolbar flips it between static text and a dynamic prompt — no
  trip through the Snippets tab.
- A dynamic block is a self-contained card: its **prompt** and **fallback** are
  edited inline, and a **Run** button resolves it in place to preview the result
  (or shows the fallback / error) — no need to toggle the global Preview.
- The Snippets tab's save form drops the "dynamic prompt" checkbox/fallback: a
  dynamic block already carries its dynamic-ness in its `doc`, so saving it as a
  snippet keeps it dynamic for free. The library per-row wand toggle and
  insert-as-dynamic remain.

### Fixed — dynamic flag now persists across reload

- `doc` (JSONB) can come back from the data layer as a parsed object **or a JSON
  string**; the editor only handled the object form, so the `dynamic`/`fallback`
  fields were silently dropped on reload (the "I can't set the toggle" symptom).
  Added `editorDoc.asDoc()` (mirrors the backend's `_as_dict`) and route
  `parsePostDoc` + `snippetIsDynamic`/`snippetFallback` through it.

### Added — toggle an existing snippet dynamic from the library

- The Snippets tab's library list gains a per-row **wand toggle** (next to the
  favorite star) to flip an existing snippet into or out of being a dynamic
  prompt — no need to re-save it through the "dynamic prompt" gesture. Toggling
  stores the flag in the snippet's `doc` and preserves any existing fallback.
- `save_snippet` now treats `favorite` as optional (`null` = leave unchanged) so
  a doc-only patch — e.g. the dynamic toggle — no longer resets the favorite
  flag. (This also fixes a latent bug where saving a snippet from the editor
  without passing favorite silently unfavorited it.)

### Changed — frontend major dependency bumps

- Adopted React 19, react-router-dom 7, TypeScript 6, Vite 8, and
  `@vitejs/plugin-react` 6 (build verified). React 19's types require an initial
  `useRef` argument — updated the three call sites. Tailwind CSS stays on v3 (v4
  is a config rewrite, deferred).

### Added — dynamic (agentic) post blocks

- A post block can now be **dynamic**: its text is a runnable prompt that is
  executed at post time (and in Preview), woven into the surrounding tweet in the
  author's Voice, and posted as the final rendition. A daily recurring post
  therefore re-resolves fresh every fire.
- **Gesture (no new editor):** write a normal text block, then **Save as Snippet
  → "dynamic prompt"**. The toggle flips the focused block to dynamic (with an
  optional fallback line) and stores a reusable dynamic snippet. Dynamic snippets
  insert as dynamic blocks and show a wand badge / chiclet.
- **Resolution** (`resolve.py` + new `resolve_dynamic_block` tool, mirroring
  `refine_post_region`): the operator's vaulted Anthropic key runs the prompt with
  Claude's server-side `web_search` tool for live facts, fitted to a character
  budget (length-gated with one shorten retry, then hard-capped). The key never
  leaves the server; the call is a metered fare, refunded on no-key / upstream
  failure / empty output.
- **Scheduler:** a due post carrying dynamic blocks is billed one
  `resolve_dynamic_block` fare on top of `post_tweet`, resolves each block, and
  composes the final text. A failed block falls back to its author text; a failed
  block with **no fallback holds the post** (refunding the resolve fare) — never a
  posted gap. Recurring occurrences snapshot the **resolved** text + a static
  rendered doc, so Sent history shows exactly what went out.
- **Preview** runs the same priced resolution as a dry-run, cached per block until
  its prompt changes so toggling Edit/Preview never re-bills.
- Dynamic-ness lives in the block's `doc` (posts and snippets) — **no DB
  migration**. Operator prices `resolve_dynamic_block` in Pricing Studio (new
  tools start unpriced).

## [0.21.0] — 2026-06-25

### Fixed — X API 402 now reads as "renew your subscription," and the scheduler stops looping on it

- **Symptom:** a scheduled post whose owner's X developer subscription had lapsed failed every tick with the opaque `x_api_error: X API 402: Unexpected response: 402`, re-firing every ~10 minutes forever (bill → X 402 → refund → leave `scheduled` → repeat). The human was never told what to do.
- **Cause:** `x_client` mapped any non-201/429/401/403 to a generic "Unexpected response," and the scheduler treated a 402 as a transient hold that the next tick would retry. A 402 from X is non-transient — it means the developer plan/tier behind the account's credentials no longer covers the write, and only a human renewing at developer.x.com can clear it.
- **Fix:**
  - `x_client.post_tweet` special-cases 402 with a clear detail instead of "Unexpected response: 402."
  - `_x_api_error_to_response` routes a 402 to the SDK's generic upstream-subscription situation (`tollbooth.upstream_payment.upstream_payment_situation`, `error_code` `upstream_subscription_required`) with renewal advice pointing at the X developer portal — `audience="patron"`, since each patron links their own X account.
  - The scheduler **pauses** a 402'd post (`posts.mark_paused` → `status='paused'`) so `list_due` stops returning it. The owner resumes by patching `status` back to `scheduled` after renewing. This ends the every-tick refire/refund loop.
- Requires `tollbooth-dpyc==0.53.0` (adds the generic upstream-402 handler). 401/403 behavior (re-authorize) is unchanged.

## [0.20.0] — 2026-06-22

### Added — server-persisted writing Voice (editable bans)

- New proof-gated, npub-scoped tools `get_voice` (read) and `save_voice` (write)
  persist the patron's writing **Voice** — a profile blurb plus a list of
  "banned construction" chips (`{text, on}`) — in a per-npub singleton `voice`
  table (Neon), mirroring the snippet pattern. They are **priceable**: they
  carry no pricing hint, so they begin unpriced (TBD) and the operator sets a
  price (or keeps them free at 0) in Pricing Studio like any new tool.
  `get_voice` returns an empty Voice (not an error) when none is saved yet, so
  the editor can seed its defaults.
- Bans are normalized server-side: blank entries dropped, de-duped by text
  (case-insensitive), `on` defaults to true.
- FE: the editor's **Voice** tab now loads/saves from the server instead of
  `localStorage`. Ban chips are fully editable — add (input + Add), edit
  (pencil, inline), remove (minus), and toggle (tap) — with an explicit **Save
  Voice** button, dirty/saving/saved status, and error surfacing.

## [0.19.0] — 2026-06-21

### Added — show the connected X @handle (personalization)

- New free, proof-gated `get_x_profile` tool calls X's `/users/me` with the
  patron's vaulted OAuth token and returns `{connected, username, name,
  profile_image_url}` (`x_client.get_me`).
- FE: the editor tweet-card preview now shows the author's real X **@handle**,
  display name, and avatar (cached per npub via `lib/xProfile.ts`, revalidated on
  open; falls back to the placeholder when X isn't connected). The Profile page's
  X panel shows "Connected · @handle".

## [0.18.0] — 2026-06-21

### Added — server-side regex + date filtering for Posts and Snippets

Both tables sorted and paginated server-side but had no search. Added a content
regex filter and a date range, filtered in SQL so pagination and totals reflect
the filtered set (the TaxSort pattern).

- `list_posts` / `list_snippets` gain `search`, `date_from`, `date_to`,
  `date_field`. `search` is a case-insensitive regex matched against the content
  (`text_cache` for posts; name OR body for snippets) via Postgres `~*`;
  `date_from`/`date_to` (`YYYY-MM-DD`, end-inclusive) bound a whitelisted
  `date_field` column (posts: created/updated/scheduled/sent; snippets:
  created/updated). All user input is parameterized; the same WHERE drives the
  `COUNT(*)` and the page.
- The regex is validated (`re.compile`) and length-capped in the tool layer —
  a bad pattern returns a refunded `tool_input_invalid` (new shared
  `tools/_filters.py`).
- FE: new shared `TableFilter` (monospace regex box submitted on Enter/button, a
  date-field selector + from/to range, Clear). Wired into PostsPage and
  SnippetsPage; every filter change resets to page 0; filtered-empty shows
  "No … match this filter."

## [0.17.1] — 2026-06-21

### Security — no cross-patron leak in the scheduler log

One worker serves all patrons, so `scheduler_runs` records every patron's
outcomes together. `get_scheduler_log` already owner-scoped the per-post entries,
but it still passed the **global `processed` count** through to every patron — a
cross-patron aggregate. `scheduler_runs.scope_runs` now recomputes `processed` to
the reader's own entry count; a patron's heartbeat is conveyed by `run_at` alone.
The operator still sees every tick in full.

## [0.17.0] — 2026-06-21

### Changed — every recurring posting becomes a visible Sent record

A recurring scheduled post reschedules itself in place, so each firing was
invisible: the row flipped back to `scheduled`, advanced its date, and the single
`tweet_url` was overwritten — no Sent record, no per-occurrence X URL. Now a
successful recurring fire **snapshots that occurrence as its own immutable Sent
post** (text + doc + that occurrence's X URL) via `posts.create_sent_occurrence`,
and the recurring template advances separately. A non-recurring scheduled post is
unchanged (the row itself becomes Sent).

### Changed — scheduler visibility now reaches the post author, not just the operator

A successful recurring fire was invisible to the author: the post simply
rescheduled to its next date with no on-list sign it had posted, and the
scheduler log was operator-gated so the author's FE session (a patron npub, not
the operator npub) always saw the misleading "no new ticks".

- **Successful fires now show on the post.** `list_posts` surfaces `last_sent_at`;
  PostsPage shows "✓ last posted <time>" on any post that has fired (including a
  recurring post back in `scheduled`), and the X preview link now shows whenever
  a `tweet_url` exists (was `sent`-only).
- **`get_scheduler_log` is owner-scoped** (was operator-only). It's now free +
  proof-gated: the operator sees every tick in full; any other proven patron sees
  the per-tick heartbeat (proof the Worker ran) plus only the per-post outcomes
  for their own posts. The scheduler tags each summary entry with its `owner`
  npub; `scheduler_runs.scope_runs` does the filtering.
- DebugPanel empty/error messages reworded ("no ticks recorded yet (the Worker
  runs every 10 min)" / proof-needed) — no more "no new ticks".

## [0.16.0] — 2026-06-21

### Fixed — scheduler audit ring wrote/read nothing (the "no new ticks" bug)

`scheduler_runs` was missing from `_DOMAIN_TABLES`, so `db.neon._qualify` never
schema-qualified it. Because Neon's HTTP SQL API ignores `search_path`, every
`record_run`/`list_runs` hit the wrong schema and failed — silently for the
best-effort write, and as an error dict for the read, so the FE always showed
"scheduler: no new ticks". Added `scheduler_runs` to `_DOMAIN_TABLES`.

### Added — visible "attempted" marker on held scheduled posts

Sign-of-life for the cron Worker: when it tries a due post but holds it back for
access (X token), finance (balance), network (X API), or content reasons, it now
stamps the post instead of leaving it silently `scheduled`.

- New `posts.last_attempt_at` + `last_attempt_reason` columns (idempotent ALTERs);
  `scheduler.process_due_posts` stamps every held attempt via new
  `posts.mark_attempt` (best-effort), and a successful fire clears the reason.
- `list_posts` / `get_post` surface both fields.
- FE PostsPage shows a ⚠ chip on a held scheduled post (e.g. "out of credits",
  "X access expired") with the raw reason + time in the tooltip.
- DebugPanel renders a `processed=0` tick as "scheduler … · alive · nothing due"
  so the heartbeat reads as life, not failure.

## [0.15.0] — 2026-06-21

### Added — scheduler-tick visibility in the FE debug log

The Cloudflare cron Worker runs on the edge, so its `process_scheduled_posts`
ticks were invisible in the browser — which hid *why* a due post wasn't reaching
X (e.g. owner balance 0 → `insufficient_balance` skip, or an expired X token →
`oauth_token_expired`). The MCP now records each tick and the FE pulls it into
the existing DebugPanel.

- **`scheduler_runs` audit ring** (`db/neon.py`, new `db/scheduler_runs.py`): a
  single-operator JSONB table; `process_scheduled_posts` records its outcome
  summary every tick (best-effort — an audit-write failure never undoes posting),
  pruned to the newest 50 runs.
- **New `get_scheduler_log` tool** (operator-only, free): returns recent ticks
  with per-post skip/error reasons.
- **FE DebugPanel** gains a "Scheduler ↻" button (+ optional 60s auto-poll) that
  merges Worker ticks into the log, red-highlighting skips/errors. Non-operator
  sessions see nothing (the tool is operator-gated).

## [0.14.1] — 2026-06-21

### Fixed — scheduled-post fire surfaces its tweet URL/id (found by a live test)

- **`get_post` now returns `tweet_url`.** The column existed and `list_posts`
  returned it, but the single-post read dropped it — so the editor opening a
  `sent` post couldn't preview the posted tweet.
- **The scheduler summary reports the real `tweet_id`** (it read `result["id"]`
  → always null; `x_client.post_tweet` returns `tweet_id`/`tweet_url`) and now
  also includes `tweet_url` per posted item. Storage was already correct — only
  the summary was wrong.

### Changed — Schedule tab shows a month calendar instead of intent JSON (FE)

- The editor's Schedule tab dropped the raw publish-intent JSON dump for a
  compact month calendar marking the post's **start**, each **recurrence
  occurrence**, and the **cease** date (‹ › to scan months). Mirrors the BE
  recurrence math (daily/weekly add days; monthly adds months, clamped to month
  length).

## [0.14.0] — 2026-06-21

### Added — Snippets are a first-class peer of Posts

- **Snippets are now editable like Posts.** A snippet carries the same `doc`
  block/flag document a post does (new idempotent `doc JSONB` column on
  `snippets`), so the editor — emoji picker, divider, Unicode formatting,
  flag→refine — is identical for both. New `get_snippet(snippet_id)` tool
  (free, owner-scoped) reads one snippet's full row; `save_snippet` accepts an
  optional `doc`.
- **Snippets have their own page + nav entry**, peer to Posts. Both Posts and
  Snippets render as sortable, paginated tables; the snippet editor reuses the
  shared block editor (no Post-now/Schedule), and the editor's insert-snippet /
  save-block-as-snippet affordances work while editing either kind.

### Changed — list tools adopt the Journal offset/sort pagination model

- **BREAKING: `list_posts` and `list_snippets` switched from cursor to
  server-side sort + offset pagination** (the Optionality Journal model). Both
  now take `sort_col` / `sort_dir` / `page` / `page_size` and return
  `{… , total, page, page_size}`. The opaque-cursor codec is removed. Sort keys
  come from a fixed whitelist (`list_posts`: `created|updated|status|scheduled`;
  `list_snippets`: `favorite|created|updated|name`) — caller input only selects
  a key, never reaching the query as raw SQL. `list_snippets` returns full rows
  (incl. `doc`) so editor chiclets can insert text directly.

## [0.13.0] — 2026-06-20

### Added — every send stamps last_sent_at + stores the tweet URL

- **`last_sent_at` is now stamped on every send.** Transitioning a post to
  `sent` (the FE's Post It, via create or update) stamps `last_sent_at = NOW()`
  server-side; the scheduler already did. So manual and scheduled posts both
  record their fire time.
- **The posted tweet's URL is stored on the post.** New `tweet_url` column
  (idempotent `ADD COLUMN IF NOT EXISTS` for existing tables); `create_post`
  and `update_post` accept it, `mark_sent` persists it (COALESCE-guarded for
  recurrence), and it's returned by `get_post` and `list_posts`.

## [0.12.1] — 2026-06-20

### Fixed — posts can be marked "sent" (Post It now flips the row)

- `create_post` / `update_post` rejected `status="sent"` (`tool_input_invalid`),
  so a successful **Post It** posted to X but the draft never moved to **Sent**.
  `sent` is a valid terminal status (it's in the table contract and the
  scheduler sets it) — added it to the create and patch allow-lists.

## [0.12.0] — 2026-06-20

### Added — Neon-backed snippet library (server-side, npub-scoped)

- **Snippet library now persists in Neon**, not the browser. Three new free,
  proof-gated, owner-scoped tools — `list_snippets`, `save_snippet`,
  `delete_snippet` — store a patron's reusable post fragments (openings,
  footers, CTAs) under their npub. Favorites surface as one-click chiclets in
  the editor.
- New `snippets` table (id, npub, name, body, favorite, timestamps) created
  idempotently in `db.neon._ensure_domain_schema`; `db.snippets` is the thin
  owner-scoped SQL layer and `tools.snippets` the validation/dispatch layer.
- **Free + proof-gated:** managing your own snippets carries no fare, but every
  call verifies npub ownership and is scoped to `npub = $1`, so a patron can
  only ever read or write their own snippets. The browser previously kept these
  in `localStorage` (device-local, unsynced) — they now follow the npub.

## [0.11.0] — 2026-06-20

### Changed — "Refine with Claude" is now server-side + metered (BREAKING)

- **Removed `get_anthropic_key`** — it handed the operator's Anthropic key to
  every proven patron's browser (key exposure) and the resulting direct
  browser→Anthropic calls bypassed the Lightning toll entirely. Gone.
- **Added `refine_post_region(region, full_text, instruction, voice, bans, npub, proof)`**
  — a **paid** tool. The editor sends the flagged region + tweet context +
  voice/bans; the MCP calls Anthropic with the operator's **vaulted** key
  (never exposed to the browser) and returns 3 suggestions. The AI cost is a
  metered tollbooth fare; the fare is **refunded** if no key is configured or
  the upstream call fails. New module `excalibur_mcp/refine.py`.
- Frontend: the editor's Refine button now calls `refine_post_region` instead
  of fetching the key and calling Anthropic directly (deleted `lib/claude.ts`).
- Operator action after deploy: reconcile the pricing model in Pricing Studio
  to price the new `refine_post_region` tool (seed hint: flat 25 sats) and drop
  the stale `get_anthropic_key` entry.

## [0.10.1] — 2026-06-19

### Added — FE-direct "Refine with Claude" key delivery (TaxSort tactic)

- **`get_anthropic_key`** — a free, proof-gated tool that hands the operator's
  Anthropic API key to a proven patron so the editorial FE can call Claude
  directly (no per-refine MCP round-trip). Mirrors taxsort-mcp. Returns
  `{key}` or `{key: null, message}` when none is configured.
- **`anthropic_api_key`** added to the operator credential template (optional,
  sensitive) — delivered via Secure Courier. Posting works without it; it only
  enables the editor's refine loop.

### Changed
- Bumped tollbooth-dpyc pin to **0.48.1** (picks up the `check_price`
  tool_not_priced fix).

## [0.10.0] — 2026-06-19

### Added — stored posts + priced CRUD (editorial face-lift, backend)

- **eXcalibur now stores posts, not just posts them.** A new `posts` table in the
  operator's NeonVault holds the editable Doc (blocks + flags + voice + bans +
  schedule) as `jsonb`, with `text_cache`, `publish_at`/`recurrence`/`cease_at`/
  `last_sent_at`, and a `client_req_id` for idempotency. Schema is created lazily
  via `db/neon.py::_ensure_domain_schema` (canonical DDL in `db/migrations/0001_initial.sql`).
- **Five metered, npub-authorized CRUD tools:** `create_post` (write), `get_post`
  (read), `list_posts` (read, keyset-paginated), `update_post` (write, patch
  semantics), `delete_post` (write, soft delete → `status='archived'`, opt-in
  `hard`). Reads are cheap, writes pricier, `create` highest (seed prices; tune in
  the pricing studio). Every statement is owner-scoped — no cross-npub access.
- **Idempotency without double-charge.** A repeated `client_req_id` on
  `create`/`update` returns the prior result and refunds the duplicate debit
  (`rollback_debit`), so debounced FE autosave retries never double-spend.

### Added — scheduled-post publishing

- **`process_scheduled_posts`** — an operator-only (`restricted`) tool that fires
  every due `scheduled` post: it bills each post's owner for `post_tweet` (tranche-
  expiry guard intact), publishes on their behalf, stamps `last_sent_at`, and
  reschedules from `recurrence` or retires the post past `cease_at`. Insufficient
  balance / unavailable OAuth are situations — the post is left scheduled, never
  dropped.
- **Cloudflare Worker cron source** (`scheduler-worker/`, deploy deferred) triggers
  the tick by impersonating the operator via its long-lived npub proof_token.

### Changed
- Requires **tollbooth-dpyc 0.48.0** (npub proof delegation cap raised 7 → 30 days),
  enabling multi-day editorial sessions and the unattended scheduler proof_token.
- Refactored the X-post path into a shared `_resolve_x_client` helper used by both
  the interactive `post_tweet` tool and the scheduler (DRY); no wire-API change.

## [0.9.1] — 2026-06-11
- chore: track tollbooth-dpyc through 0.44.15 — SDK audit hardening (correctness fixes for credit-tranche expiration in 0.44.9 and proof-reply handling in 0.44.10; blocking mypy + coverage gates). No wire-API changes.

## [0.9.0] — 2026-05-19

### Changed — sync with tollbooth-dpyc 0.25.0

Picks up the wheel's runtime-name + DRY pass:

- **Identity proofs sign the runtime tool name** (`<slug>_<capability>` —
  e.g. `<slug>_check_balance`). The bare capability seed never crosses the
  server boundary. (wheel 0.24.0)
- **Oracle delegations mount under `<slug>_oracle_*`** — every wire-exposed
  tool on this operator now shares the same slug prefix. (wheel 0.24.1)
- **`register_standard_tools` returns the `@tool` decorator** — the slug
  literal now appears exactly once in this server's bootstrap. (wheel 0.25.0)


## [0.8.0] — 2026-04-13

- security: add proof parameter to all tools with npub
- update debit_or_deny call for Either return type
- chore: pin tollbooth-dpyc>=0.5.0

## [0.7.0] — 2026-04-12

- remove Horizon OAuth — sessions keyed by npub, no fallback code

## [0.6.36] — 2026-04-11

- chore: pin tollbooth-dpyc>=0.4.9 — credential validator fix

## [0.6.35] — 2026-04-11

- chore: pin tollbooth-dpyc>=0.4.8 — ncred fix, courier diagnostics

## [0.6.34] — 2026-04-11

- chore: pin tollbooth-dpyc>=0.4.6
- Add credential_validator: validates btcpay + client_id + client_secret

## [0.6.33] — 2026-04-11

- chore: pin tollbooth-dpyc>=0.4.0, rename debit_or_error to debit_or_deny
- split post_tweet into two proper MCP tools
- restore tiered pricing: post_tweet (write) + post_tweet_image (heavy)
- fix: unify post_tweet capability, remove stale post_social_media
- chore: pin tollbooth-dpyc>=0.3.3
- chore: pin tollbooth-dpyc>=0.3.2 — lazy MCP name resolution
- chore: pin tollbooth-dpyc>=0.3.1 — function name MCP stamping
- chore: pin tollbooth-dpyc>=0.3.0 — single tool identity model
- chore: pin tollbooth-dpyc>=0.2.17 for slug namespace filtering
- chore: pin tollbooth-dpyc>=0.2.16
- fix: remove empty Horizon auth helpers section
- chore: pin tollbooth-dpyc>=0.2.14
- chore: pin tollbooth-dpyc>=0.2.13
- feat: UUID-keyed internals — paid_tool and registry use UUID, not short names
- chore: pin tollbooth-dpyc>=0.2.11
- chore: pin tollbooth-dpyc>=0.2.10
- chore: pin tollbooth-dpyc>=0.2.9
- chore: pin tollbooth-dpyc>=0.2.8
- chore: pin tollbooth-dpyc>=0.2.7
- chore: pin tollbooth-dpyc>=0.2.6 for reset_pricing_model
- chore: pin tollbooth-dpyc>=0.2.5
- chore: pin tollbooth-dpyc>=0.2.4 for security fix + legacy UUID fallback
- chore: pin tollbooth-dpyc>=0.2.3 for pricing cache fix
- fix: lint — import ordering, unused import
- fix: lint — remove unused json imports
- feat: UUID-based tool identity — TOOL_COSTS → TOOL_REGISTRY
- fix: store PKCE verifier in vault, not in-memory
- chore: pin tollbooth-dpyc>=0.2.1 — requires PKCE + refresh_access_token
- feat: X OAuth2 Authorization Code + PKCE — replace OAuth 1.0a entirely
- fix: lint — import order, unused os import, unused restore_detail
- fix: remove legacy env vars and dead FileVault code
- fix: use X Dev Portal field names, separate patron/operator credentials cleanly
- fix: X API app keys in operator vault, no env vars — nsec-only principle
- fix: combine patron access tokens with operator app keys in _ensure_session
- chore: pin tollbooth-dpyc>=0.2.0 — clean Neon schema isolation
- chore: pin tollbooth-dpyc>=0.1.173 for onboarding late-attach fix
- chore: pin tollbooth-dpyc>=0.1.172 for credential vault diagnostics
- fix: clear credential state reporting for humans and agents
- fix: improve vault_bootstrapping diagnostics, validate credential fields
- chore: pin tollbooth-dpyc>=0.1.171 — don't cache empty ledgers on cold start
- fix: cold start bugs — patron-facing guidance, remove activate_session, pin >=0.1.170
- chore: pin tollbooth-dpyc>=0.1.169 for session_status lifecycle
- feat: use wheel's themed infographic, delete local copy, pin >=0.1.167
- fix: DRY cleanup — remove redundant health(), fix operator_id → npub
- fix: add onboarding status methods and catalog entries to actor
- chore: pin tollbooth-dpyc>=0.1.165 for demurrage constraint rename
- chore: pin tollbooth-dpyc>=0.1.164 for tranche_expiration constraint
- chore: pin tollbooth-dpyc>=0.1.163 for authority_client npub fix
- chore: pin tollbooth-dpyc>=0.1.162 for patron onboarding status
- fix: pin tollbooth-dpyc>=0.1.161
- chore: pin tollbooth-dpyc>=0.1.160
- fix: lifecycle-aware session guidance for all patron-facing states
- fix: .fastmcp.yaml must declare TOLLBOOTH_NOSTR_OPERATOR_NSEC for bootstrap

## [0.6.31] — 2026-03-29

- chore: pin tollbooth-dpyc>=0.1.159, bump to v0.6.31
- refactor: adopt SessionCache from tollbooth wheel
- refactor: delegate boilerplate to runtime, add Neon vault persistence, annotate npub
- chore: bump tollbooth-dpyc to >=0.1.155
- refactor: strip fastmcp.json to nsec-only
- chore: bump tollbooth-dpyc to >=0.1.152
- chore: require Python >=3.12 (matches Horizon)
- chore: bump tollbooth-dpyc to >=0.1.150
- chore: bump tollbooth-dpyc to >=0.1.147
- chore: bump tollbooth-dpyc to >=0.1.144
- chore: bump tollbooth-dpyc to >=0.1.143
- chore: bump tollbooth-dpyc to >=0.1.138
- chore: bump tollbooth-dpyc to >=0.1.137
- chore: bump tollbooth-dpyc to >=0.1.136
- chore: bump tollbooth-dpyc to >=0.1.135
- chore: bump tollbooth-dpyc to >=0.1.134
- chore: bump tollbooth-dpyc to >=0.1.132
- chore: bump tollbooth-dpyc to >=0.1.131
- chore: bump tollbooth-dpyc to >=0.1.128
- chore: bump tollbooth-dpyc to >=0.1.127
- refactor: dual credential templates, nsec-only Settings
- refactor: npub required in tool descriptions + dead code cleanup
- feat: credential field descriptions for user guidance
- chore: bump tollbooth-dpyc to >=0.1.109
- feat: restore operator-specific Secure Courier greeting
- fix: relax catalog count assertions — catalog evolves with wheel
- fix: ignore N806 (MockClient naming convention in tests)
- fix: ruff auto-fix import sorting + unused imports
- fix: remove unused OperatorProtocol import + ruff lint config
- fix: lint cleanup — unused imports + ignore E501
- feat: add CI workflow + clean up tests for OperatorRuntime
- chore: bump tollbooth-dpyc to >=0.1.108 (infographic restored)
- chore: bump tollbooth-dpyc to >=0.1.107
- refactor: use OperatorRuntime + register_standard_tools
- refactor: npub is required on all credit tools — no session cache
- refactor: _ensure_dpyc_session accepts explicit npub override

## [0.6.30] — 2026-03-22

- chore: bump version to 0.6.30 for release
- chore: bump tollbooth-dpyc to >=0.1.100 (notarization catalog + remove get_tax_rate)

## [0.6.29] — 2026-03-22

- chore: bump tollbooth-dpyc to >=0.1.98 (cache migration fix)
- chore: bump tollbooth-dpyc to >=0.1.97 (tranche TTL expiry)
- chore: bump tollbooth-dpyc to >=0.1.96 for pricing model bridge
- chore: bump tollbooth-dpyc to >=0.1.95 for certify_credits rename
- refactor: rename certifier.certify() to certify_credits()
- chore: bump tollbooth-dpyc to >=0.1.94 for rollback tranche expiry
- chore: nudge deploy for tollbooth-dpyc v0.1.93 PyPI release
- chore: bump tollbooth-dpyc to >=0.1.93
- chore: add fastmcp.json for Horizon deployment config
- chore: nudge deploy for tollbooth-dpyc v0.1.92 release
- Merge pull request #58 from lonniev/chore/bump-tollbooth-0.1.92
- chore: bump tollbooth-dpyc to >=0.1.92 for ACL support
- fix: extract operator_proof from model_json instead of separate tool arg (#57)
- feat: wire operator catalog conformance check at startup, bump to 0.6.29

## [0.6.28] — 2026-03-14

- chore: bump tollbooth-dpyc to >=0.1.91
- feat: gate set_pricing_model to operator-only (Step 0C)
- feat: wire pricing CRUD tools for operator self-service (#56)
- chore: bump tollbooth-dpyc to >=0.1.83 (#55)

## [0.6.27] — 2026-03-09

- chore: bump tollbooth-dpyc to >=0.1.82, version 0.6.27 (#54)
- chore: bump tollbooth-dpyc to >=0.1.81, version 0.6.26 (#53)

## [0.6.25] — 2026-03-08

- chore: bump version to 0.6.25
- Merge pull request #52 from lonniev/refactor/lookup-cache-path
- refactor: remove redundant dpyc_registry_url config

## [0.6.24] — 2026-03-07

- chore: bump version to 0.6.24
- docs: add instructions block + clarify patron npub in tool docstrings (#51)

## [0.6.23] — 2026-03-07

- Merge pull request #50 from lonniev/feat/invoice-dm-delivery
- feat: wire invoice DM delivery via Secure Courier
- chore: bump version to 0.6.22 (#49)

## [0.6.22] — 2026-03-07

- feat: add EXPIRES column to account statement infographic (#48)

## [0.6.21] — 2026-03-07

- fix: remove legacy royalty payout config and params (#47)
- chore: bump to v0.6.20 for clean deploy (native Twitter media for banners)
- fix: upload banner PNG as native Twitter media instead of PostImg
- fix: use correct PostImg upload endpoint with token
- fix: follow redirects on PostImg upload (301 fix)
- fix: switch PostImg to official API endpoint
- fix: replace svglib+reportlab with PyMuPDF for banner SVG→PNG
- fix: pin svglib<1.6.0 to avoid pycairo C dep on FastMCP Cloud
- chore: force redeploy for v0.6.14 (svglib+reportlab)

## [0.6.14] — 2026-03-06

- Merge pull request #46 from lonniev/fix/svglib-renderer
- fix: replace Playwright with svglib+reportlab for banner SVG→PNG

## [0.6.13] — 2026-03-06

- Merge pull request #45 from lonniev/fix/playwright-renderer
- fix: replace cairosvg with Playwright for banner rendering

## [0.6.12] — 2026-03-06

- Merge pull request #44 from lonniev/fix/banner-svg-only
- fix: simplify banner to SVG-only, make cairosvg a required dep

## [0.6.11] — 2026-03-06

- Merge pull request #43 from lonniev/feat/banner-postimg
- chore: bump version to 0.6.11
- feat: add banner_svg_or_png to post_tweet via PostImages upload

## [0.6.10] — 2026-03-06

- chore: bump version to 0.6.10, pin tollbooth-dpyc>=0.1.76
- fix: resolve 22 pre-existing test failures across 4 test files (#42)
- Merge pull request #41 from lonniev/feat/constraint-gate
- feat: wire ConstraintGate into debit flow (opt-in, off by default)
- chore: update README for current architecture (#40)
- chore: trigger FastMCP Cloud redeploy for tollbooth-dpyc 0.1.75
- chore: pin tollbooth-dpyc>=0.1.75 + surge pricing constraint (#39)
- Merge pull request #38 from lonniev/chore/ecosystem-links
- chore: pin tollbooth-dpyc>=0.1.74 for ECOSYSTEM_LINKS
- chore: add ecosystem_links to service_status response

## [0.6.9] — 2026-03-04

- Merge pull request #37 from lonniev/fix/post-tweet-cost
- fix: set post_tweet cost to 5 api_sats, post_tweet_image to 10
- Merge pull request #36 from lonniev/chore/pin-073
- chore: trigger FastMCP Cloud redeploy for tollbooth-dpyc 0.1.73
- Merge pull request #35 from lonniev/feat/pin-trademark
- chore: pin tollbooth-dpyc>=0.1.72 + trademark notices
- chore: trigger FastMCP Cloud redeploy for tollbooth-dpyc 0.1.70
- feat: auto-restore DPYC identity from vault on cold start (#34)
- chore: trigger FastMCP Cloud redeploy for tollbooth-dpyc 0.1.66

## [0.6.8] — 2026-03-03

- Merge pull request #33 from lonniev/feat/auto-certify-purchase
- feat: auto-certify purchase_credits via server-to-server OAuth

## [0.6.7] — 2026-03-03

- Merge pull request #32 from lonniev/feat/slug-prefixing
- feat: slug-prefix all MCP tools with "excalibur_" to avoid name collisions
- feat: ExcaliburOperator protocol conformance (#31)
- Merge pull request #30 from lonniev/feat/dynamic-relay-negotiation
- feat: dynamic relay negotiation + bump tollbooth-dpyc to >=0.1.62
- Merge pull request #29 from lonniev/chore/bump-tollbooth-dpyc-0.1.57
- chore: bump tollbooth-dpyc to >=0.1.57
- chore: bump tollbooth-dpyc to >=0.1.53 (#28)
- Merge pull request #27 from lonniev/chore/bump-tollbooth-dpyc-0.1.52
- chore: bump tollbooth-dpyc to >=0.1.52

## [0.6.5] — 2026-03-01

- chore: force redeploy after NSEC-only identity migration
- Merge pull request #26 from lonniev/feat/nsec-only-registry-resolution
- NSEC-only registry resolution: derive authority npub at runtime (v0.6.5)

## [0.6.4] — 2026-03-01

- Merge pull request #25 from lonniev/feat/courier-greeting
- Resolve merge conflict, bump to v0.6.4
- Pass operator greeting to Secure Courier open_channel
- Bump tollbooth-dpyc minimum to >=0.1.49 (scan-all-DMs fix) (#24)
- Bump tollbooth-dpyc minimum to >=0.1.49 (scan-all-DMs fix)

## [0.6.3] — 2026-02-28

- Bump tollbooth-dpyc to >=0.1.48 (NIP-44v2 cipher fix) (#23)

## [0.6.2] — 2026-02-28

- Merge pull request #22 from lonniev/refactor/dry-version
- DRY version: read from importlib.metadata, bump to 0.6.2

## [0.6.1] — 2026-02-28

- Fix __init__.py version to match pyproject.toml (0.6.1)
- Bump version to 0.6.1
- Force redeploy to FastMCP Cloud
- Trigger redeploy — tollbooth-dpyc 0.1.45 now on PyPI
- Remove unused authlib dep, bump tollbooth-dpyc to >=0.1.45 (#21)
- Merge pull request #20 from lonniev/feat/readme
- Add comprehensive README with Secure Courier and tool documentation
- Bridge Secure Courier credentials to passphrase vault (#19)
- Bump tollbooth-dpyc minimum to >=0.1.44 (bare-key repair) (#18)
- Bump tollbooth-dpyc minimum to >=0.1.43 (lenient JSON parsing) (#17)
- Bump tollbooth-dpyc minimum to >=0.1.42 (smart-quote sanitization) (#16)

## [0.6.0] — 2026-02-27

- Add service_status tool + bump tollbooth-dpyc to >=0.1.41 (#15)

## [0.5.0] — 2026-02-27

- Release 0.5.0

## [0.4.2] — 2026-03-09

- chore: bump tollbooth-dpyc to >=0.1.82, version 0.6.27 (#54)
- chore: bump tollbooth-dpyc to >=0.1.81, version 0.6.26 (#53)
- chore: bump version to 0.6.25
- Merge pull request #52 from lonniev/refactor/lookup-cache-path
- refactor: remove redundant dpyc_registry_url config
- chore: bump version to 0.6.24
- docs: add instructions block + clarify patron npub in tool docstrings (#51)
- Merge pull request #50 from lonniev/feat/invoice-dm-delivery
- feat: wire invoice DM delivery via Secure Courier
- chore: bump version to 0.6.22 (#49)
- feat: add EXPIRES column to account statement infographic (#48)
- fix: remove legacy royalty payout config and params (#47)
- chore: bump to v0.6.20 for clean deploy (native Twitter media for banners)
- fix: upload banner PNG as native Twitter media instead of PostImg
- fix: use correct PostImg upload endpoint with token
- fix: follow redirects on PostImg upload (301 fix)
- fix: switch PostImg to official API endpoint
- fix: replace svglib+reportlab with PyMuPDF for banner SVG→PNG
- fix: pin svglib<1.6.0 to avoid pycairo C dep on FastMCP Cloud
- chore: force redeploy for v0.6.14 (svglib+reportlab)
- Merge pull request #46 from lonniev/fix/svglib-renderer
- fix: replace Playwright with svglib+reportlab for banner SVG→PNG
- Merge pull request #45 from lonniev/fix/playwright-renderer
- fix: replace cairosvg with Playwright for banner rendering
- Merge pull request #44 from lonniev/fix/banner-svg-only
- fix: simplify banner to SVG-only, make cairosvg a required dep
- Merge pull request #43 from lonniev/feat/banner-postimg
- chore: bump version to 0.6.11
- feat: add banner_svg_or_png to post_tweet via PostImages upload
- chore: bump version to 0.6.10, pin tollbooth-dpyc>=0.1.76
- fix: resolve 22 pre-existing test failures across 4 test files (#42)
- Merge pull request #41 from lonniev/feat/constraint-gate
- feat: wire ConstraintGate into debit flow (opt-in, off by default)
- chore: update README for current architecture (#40)
- chore: trigger FastMCP Cloud redeploy for tollbooth-dpyc 0.1.75
- chore: pin tollbooth-dpyc>=0.1.75 + surge pricing constraint (#39)
- Merge pull request #38 from lonniev/chore/ecosystem-links
- chore: pin tollbooth-dpyc>=0.1.74 for ECOSYSTEM_LINKS
- chore: add ecosystem_links to service_status response
- Merge pull request #37 from lonniev/fix/post-tweet-cost
- fix: set post_tweet cost to 5 api_sats, post_tweet_image to 10
- Merge pull request #36 from lonniev/chore/pin-073
- chore: trigger FastMCP Cloud redeploy for tollbooth-dpyc 0.1.73
- Merge pull request #35 from lonniev/feat/pin-trademark
- chore: pin tollbooth-dpyc>=0.1.72 + trademark notices
- chore: trigger FastMCP Cloud redeploy for tollbooth-dpyc 0.1.70
- feat: auto-restore DPYC identity from vault on cold start (#34)
- chore: trigger FastMCP Cloud redeploy for tollbooth-dpyc 0.1.66
- Merge pull request #33 from lonniev/feat/auto-certify-purchase
- feat: auto-certify purchase_credits via server-to-server OAuth
- Merge pull request #32 from lonniev/feat/slug-prefixing
- feat: slug-prefix all MCP tools with "excalibur_" to avoid name collisions
- feat: ExcaliburOperator protocol conformance (#31)
- Merge pull request #30 from lonniev/feat/dynamic-relay-negotiation
- feat: dynamic relay negotiation + bump tollbooth-dpyc to >=0.1.62
- Merge pull request #29 from lonniev/chore/bump-tollbooth-dpyc-0.1.57
- chore: bump tollbooth-dpyc to >=0.1.57
- chore: bump tollbooth-dpyc to >=0.1.53 (#28)
- Merge pull request #27 from lonniev/chore/bump-tollbooth-dpyc-0.1.52
- chore: bump tollbooth-dpyc to >=0.1.52
- chore: force redeploy after NSEC-only identity migration
- Merge pull request #26 from lonniev/feat/nsec-only-registry-resolution
- NSEC-only registry resolution: derive authority npub at runtime (v0.6.5)
- Merge pull request #25 from lonniev/feat/courier-greeting
- Resolve merge conflict, bump to v0.6.4
- Pass operator greeting to Secure Courier open_channel
- Bump tollbooth-dpyc minimum to >=0.1.49 (scan-all-DMs fix) (#24)
- Bump tollbooth-dpyc minimum to >=0.1.49 (scan-all-DMs fix)
- Bump tollbooth-dpyc to >=0.1.48 (NIP-44v2 cipher fix) (#23)
- Merge pull request #22 from lonniev/refactor/dry-version
- DRY version: read from importlib.metadata, bump to 0.6.2
- Fix __init__.py version to match pyproject.toml (0.6.1)
- Bump version to 0.6.1
- Force redeploy to FastMCP Cloud
- Trigger redeploy — tollbooth-dpyc 0.1.45 now on PyPI
- Remove unused authlib dep, bump tollbooth-dpyc to >=0.1.45 (#21)
- Merge pull request #20 from lonniev/feat/readme
- Add comprehensive README with Secure Courier and tool documentation
- Bridge Secure Courier credentials to passphrase vault (#19)
- Bump tollbooth-dpyc minimum to >=0.1.44 (bare-key repair) (#18)
- Bump tollbooth-dpyc minimum to >=0.1.43 (lenient JSON parsing) (#17)
- Bump tollbooth-dpyc minimum to >=0.1.42 (smart-quote sanitization) (#16)
- Add service_status tool + bump tollbooth-dpyc to >=0.1.41 (#15)
- Add runtime version reporting to health endpoint (#14)
- Bump tollbooth-dpyc minimum to >=0.1.40 (dual-protocol DM + timestamp fix) (#13)
- Bump tollbooth-dpyc minimum to >=0.1.39 (base64 padding fix) (#12)
- Add Secure Courier onboarding guidance to tool metadata and error responses (#11)
- Bump tollbooth-dpyc minimum to >=0.1.38 (NIP-17 gift-wrapped DMs) (#10)
- Bump tollbooth-dpyc minimum to >=0.1.37 (ConstraintGate middleware) (#9)
- Refactor Secure Courier to use shared SecureCourierService (#8)
- Merge pull request #7 from lonniev/feat/infographic-port
- Bump tollbooth-dpyc minimum to >=0.1.34 (relay diagnostics + DM notifications)
- Add account_statement_infographic tool with Excalibur-branded SVG
- Merge pull request #6 from lonniev/feat/unified-onboarding
- Bump tollbooth-dpyc minimum to >=0.1.33 (conversational DM + NIP-17)
- Establish DPYC identity and seed balance in Secure Courier receive
- Merge pull request #5 from lonniev/feat/welcome-dm-profile
- Add welcome DM flip and Nostr profile publishing
- Add PNG version of avatar for Nostr profile compatibility
- Add eXcalibur MCP avatar for Nostr operator profile
- chore: empty commit to force Horizon redeploy
- Merge pull request #3 from lonniev/fix/license-spelling
- Merge pull request #4 from lonniev/fix/courier-template-v2
- Reduce X credential template to 2 fields (access_token pair only)
- Fix last excaliber → excalibur typo in LICENSE
- chore: empty commit to force Horizon redeploy
- Wire Secure Courier tools for out-of-band X API credential delivery (#2)
- chore: empty commit to force Horizon redeploy
- Support long-form posts and optional image attachments
- Rename excaliber → excalibur across package and codebase
- Migrate to Nostr Schnorr certificate verification
- Enforce credit gating in all modes; populate .env.example
- Add Tollbooth credit gating and monetization infrastructure
- Add multi-tenant credential vault with per-user X API OAuth
- Trigger Horizon redeploy
- Add FastMCP Cloud (Horizon) deployment config
- Merge pull request #1 from lonniev/feat/post-tweet
- Fix OAuth 1.0a signing: manual header instead of authlib
- Add post_tweet tool with markdown → Unicode formatting
- Initial project scaffolding for eXcaliber-mcp

