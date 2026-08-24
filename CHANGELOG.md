# Changelog

All notable changes to this project will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.40.0] — 2026-08-24

### Fixed — A patron could see the scheduler was stuck, but not why, and could do nothing about it

A patron watching the Scheduler saw a red "Scheduler stalled" dot, no explanation,
and no move to make (#517).

**"Stalled" was the wrong word.** Health is derived purely from run-row age
(>100 min = three missed ticks), but only `process_scheduled_posts` opens a run
row, and an unauthorized Worker never gets that far: every tick parks at the
proof DM and writes nothing. The one state with a known cause and a human
waiting on it was reported as the state with neither. `deriveSchedulerState` now
takes the Worker's authorization phase — already carried on the free
`scheduler_status` — and reports `unauthorized` ("Scheduler awaiting approval",
amber), which outranks every age verdict because it explains them.

**The pending card hid itself from everyone but the operator**, phrase and all.
The phrase stays operator-only — an impostor knowing it is the attack the
Device-Grant second surface defends against — but a parked scheduler is not a
secret, and the patron's posts are the ones not going out. Patrons now get the
banner and the poke, fed from `scheduler_status`; `scheduler_pending` is still
called only when the viewer IS the operator, which also stops the misleading
"proof cache invalid" error patrons logged on every poll.

`scheduler_check_now` drops from `restricted` to `free` (proof-gated, unbilled)
so that poke is reachable. The old gate read as caution and was fiction: it
proxies the Worker's `/tick`, an unauthenticated public route whose URL is
hardcoded in this public repo. A poke carries no authority — a tick can only
claim a reply the operator's own nsec signed, fire posts already due, or re-DM
the operator.

Also: `SchedulerHealth` called `deriveSchedulerState` with no lease argument, so
the Posts toolbar judged "still resolving" against the 60-minute fallback while
the Scheduler page used the served value. Both now use the served lease.

### Changed — Performance page: chart Time of day, standard loader, sortable table, drop Link column

Four UX fixes on the Performance view (#364):

1. **Time of day** is a continuous 24-hour local-time bar chart (gaps = untried hours),
   with per-bucket `n=` labels and dimmed provisional bars when n<3. Hover still shows UTC.
2. Metrics load uses the site-standard **QuoteScroller** instead of bare "Loading…".
3. **Posts by reach** columns are client-sortable; **Posted** is its own compact date column
   (no longer a subtitle under the title) so chronological order is one click.
4. Per-row **Link** placement is removed from the table (it read "Body" for every row and
   burned width). Capture is unchanged; the existing **Link placement and reach** aggregate
   panel remains, now with sample size. Clicks stay on the row.

Backend cohorts (`time_of_day`, `link_placement`) now return `{median, n}` per bucket so the
chart and panel can encode sample size. FE still accepts legacy bare numbers.

### Fixed — Breakout ratio never crossed 1.0 because followers were the wrong denominator

The Performance column labeled "Breakout ratio" divided impressions by follower
count. At a few hundred followers with typical post impressions in the tens to
low hundreds, every cell landed between 0.08× and 0.50× — the metric could not
fire, and the label disagreed with what the number actually meant (follower
saturation, not out-of-network pickup). X does not deliver a post to every
follower either, so the fraction was never a good proxy for breakout at any
scale.

Breakout now matches Escape velocity's shape on a later horizon: final reach
(t+28d when harvested, else the furthest reading) ÷ the patron's own rolling
median final impressions. The two headline columns read as a pair — early
momentum vs baseline, final reach vs baseline. Values are suppressed ("—")
until at least five posts contribute a final reading, so a two-post median
does not pretend to discriminate. The Followers card stays on the page as
context only; it is no longer an input to the ratio. Column label unchanged;
tooltip and tool docstring now describe the personal-median math.

### Fixed — the release reached Horizon but not the container that does the work

`modal_app.py` is where scheduled dynamic posts are *resolved* — the LLM call, the web
lookups, the fare. Horizon only dispatches. Nothing ever deployed it: it was pushed by
hand once, on 2026-08-06, and then main moved.

0.38.0 raised the block ceiling 900s → 1800s and bumped the SDK to 0.83.0, the version
that makes `clamp_timeout` honour a caller-supplied maximum. Both shipped to Horizon.
Neither reached Modal. For a day the scheduler dispatched intending 1800s while the
container cut every block back to 900s, and the "provider is out of credit" message from
the same release stayed invisible. The release was green, tagged, and inert.

The image builds from `pyproject.toml` and mounts `excalibur_mcp` at **deploy** time.
`add_local_python_source(copy=False)` skips an image *rebuild* on a code change, not the
redeploy — so a source change with no redeploy leaves Modal running code that exists
nowhere else. `deploy-modal.yml` therefore triggers on "what Modal executes changed",
not on "modal_app.py changed", and again on `release: published` — checking out the
released tag, so the container ends up on the commit that was actually released.

CI holds a **deploy** credential, deliberately not the operator's identity. Two different
things are needed to run a service and the platforms already keep them apart: what the
service *runs as* is the nsec, set once in Horizon's env and in the Modal Secret
`excalibur-operator`; what *authorizes a deploy* is a platform token. This job only
performs the second, so it holds only the second.

The considered alternative was to give CI the nsec and read the Modal tokens out of the
operator vault, where their delivery to the **runtime** is codified. That would hand a
build runner the credential unlocking every operator secret — X API keys, BTCPay, patron
sessions — to obtain the weakest one in the system. A Modal token can redeploy an app; it
cannot open the vault.

The cost is that the deploy can no longer compare the app name it deploys against the
`modal_app_name` the runtime resolves from the vault. `tests/test_modal_app.py` pins it
instead, so a rename fails loudly until the vault half is acknowledged rather than
silently leaving the scheduler dispatching to a function that does not exist.

The post-deploy assertion is "the live container runs this commit's content", not "a
version stamped with this commit exists" — the two differ, and the first run of the
workflow failed on the difference. Modal deduplicates: when the image, the function spec
and the mounted source are byte-identical to what is live it cuts no new version. That is
the invariant holding, and it is the *common* case, because the paths filter is
deliberately wider than the image — a merge touching only CI config, tests or docs
correctly changes nothing to run.

Also pins the **outermost** budget ring in tests. Every other ring had one; this one was
invisible to in-process assertions because the timeout is baked into the deployment. The
first deployed version carried a literal `timeout=3600`, nesting by luck at the ceiling
of the day.

## [0.39.7] — 2026-08-22

### Changed — track tollbooth-dpyc 0.88.0

A relay down for a moment no longer becomes a permanent verdict.
The bootstrap relay poll is retried on a bounded ladder, and a
transient failure is no longer cached for the life of the process.

## [0.39.6] — 2026-08-23

### Changed — track tollbooth-dpyc 0.87.3

Recovering an orphaned job now uses the detached executor it was
dispatched to. The recovery path never resolved the executor, so a job
orphaned by a container recycle was retried in-process on the new front
— bypassing the detached runner precisely when it was the point.
`resolve_dynamic_block` and `resolve_post_body` are exactly that shape.

## [0.39.5] — 2026-08-22

### Changed — track tollbooth-dpyc 0.87.3

Recovering an orphaned job now uses the detached executor it was
dispatched to. The recovery path never resolved the executor, so a
job orphaned by a container recycle was retried in-process on the
new front — bypassing the detached runner precisely when it was
the point.

## [0.39.4] — 2026-08-22

### Changed — track tollbooth-dpyc 0.87.2

An object argument a client serialised as a JSON string is now parsed
rather than refused as `dict_type`. This is the fix for `update_post`
rejecting a large `patch` — the payload was never malformed and its size
was never the variable; the client had simply encoded it one time more
than the schema asks. A 10 KB object was always accepted; a 12-byte
string never was.

## [0.39.3] — 2026-08-22

### Changed — track tollbooth-dpyc 0.87.2

An object argument a client serialised as a JSON string is now parsed
rather than refused as `dict_type`. Fixes `update_post` rejecting a
large patch and `update_design_text` rejecting a multi-key edits
object.

## [0.39.2] — 2026-08-22

### Changed — track tollbooth-dpyc 0.87.1

Picks up the relay-reliability work: `COURIER_RELAY_UNREACHABLE` so an
unreachable pinned rendezvous is no longer reported as the patron never
replying, relay-failure reporting to the Oracle, and a publish that counts
only when the relay acknowledges that exact event.

## 0.39.1 — 2026-08-17

### Changed — track tollbooth-dpyc 0.86.0 (GitHub-free bootstrap)

Picks up the GitHub-free operator bootstrap: relays and Authority resolution now come from the Oracle via MCP, so this operator no longer reads the dpyc-community registry on GitHub — closing the fleet-wide bootstrap SPOF.

## 0.39.0 — 2026-08-10

### Added — the Performance page answers questions instead of listing numbers

Tier 1 rates and a time-of-day cohort, a continuous 24-hour local chart in place of a sparse
UTC table, a sortable posts-by-reach table whose headers fit their columns, and the breakout
ratio re-based on rolling median final reach so a thin corpus reads as a thin corpus rather
than a missing follower count. Column names live in one place now, with a full name for
`title` and `aria-label` and a short one for the visible label.

### Added — times render in the patron's own zone

A Profile selector sets an IANA timezone and the app renders in it, rather than making the
reader convert from UTC. The Profile page also surfaces an expired X token on the account
card instead of letting a stale credential look healthy, and the Nostr profile collapses with
an avatar badge.

### Fixed — a test whose fixture expired took main red with no commit

`test_publish_one_anchors_the_next_slot_on_publish_at` read the wall clock: `publish_one`
takes `sent_at` from `_now()` and the fixture asserted the next weekly slot was a specific
date. Once real time passed that instant, `_next_state` correctly skipped the occurrence —
it must never schedule into the past — and the test failed while reporting the right answer.
Two innocent PRs looked broken. The clock is pinned now, and the other date literals in that
file were audited rather than only the one that fired.

### Changed — track tollbooth-dpyc 0.85.0

Picks up `check_authority_balance`, which failed for every operator, and the shared
param-default binding.

### Changed — CI runs the check the deploy runs

The `test` job inspects the deploy entrypoint, the check Horizon performs at build time —
placed in `test` rather than appended, since this repo's last job is `worker`. `release.yml`
notes extraction accepts this CHANGELOG's heading style instead of publishing a 16-byte body.

## 0.38.0 — 2026-08-07


### Changed — resolve budgets are derived from one configured ceiling

Five coupled durations were authored independently in three Python modules and two
frontend files, each comment quoting the others' values. They are nested rings — a
block's LLM budget inside a job attempt, inside the claim lease, inside the runner's
timeout — and inverting any adjacent pair has a specific failure: a lease shorter than
the attempt it guards declares a live resolve orphaned and hands it to a second worker.

Now only the innermost is authored (`RESOLVE_BLOCK_BUDGET_MAX_S`, default 1800s, up from
a hardcoded 900). `Settings` derives the rest, and `gt=1.0` on the safety factor makes an
inversion unrepresentable rather than merely tested for. Retuning the ceiling moves every
ring with no code edit.

`scheduler_status` now serves `resolve_budgets`, so the editor's time-budget input and
the scheduler view's lease bound are **fetched** rather than hand-copied. The frontend's
duplicate clamp is gone: a second ceiling carrying its own copy of the first is how a
legal budget got silently cut back.

### Fixed — an unfunded model provider says so

A dynamic block that failed because the operator's provider account was empty reported
`resolve_failed:HTTPStatusError` — the one cause a fallback most needs to name, because
unlike a short `runtimeLimit` no edit to the post can fix it. `_fallback_reason` was
stringifying an `httpx.HTTPStatusError` and discarding the status it was holding, so the
wheel's bare-402 rule was unreachable. It now passes the status, and the badge reads
"the operator's model provider is out of credit — top it up". Cost an evening of posts on
2026-08-06.

### Fixed — resolution consumed the template it was building from

A dynamic block's prompt IS its `text`, and the resolver wrote each answer back
into `doc` — the authored row. So the first firing of a recurring template
replaced every prompt with that firing's output and marked the block `resolved`.
Advancing the recurrence never restored it and `doc` has no history, so the
template was destroyed by its own first success.

Nothing reported it. Later firings found no pending blocks, called no model,
charged no fare, and reposted the frozen words on schedule. Where resolution had
failed, what froze was the block's fallback text — the visible form of the bug,
and the only one that looked wrong. A block with **no** fallback was the sole
survivor: that path refuses rather than writes.

Authored and derived state are now two columns. `doc` changes only under a human
edit; `render` holds what a firing built, and is cleared when the recurrence
advances. The resolve path no longer holds a write handle on `doc` at all,
asserted in SQL rather than in dicts.

Two further defects surfaced in the same mechanism:

- `resolve_attempts` increments on every claim, including successful ones, and is
  capped at 5. Nothing reset it, so a healthy recurring template stopped
  resolving after its fifth firing — silently, by dropping off the work-list.
  Advancing now resets it; a genuinely broken template still trips the cap,
  because it never reaches that statement.
- Templates flattened before this fix carry `resolved: true` in their authored
  doc. Honouring it keeps them frozen; ignoring it runs last firing's output as
  the prompt and bills the owner for fluent posts nobody wrote. They now pause
  with `template_prompt_lost`, naming the affected blocks. **The prompts are not
  recoverable** — `doc` has no history and sent occurrences hold rendered text —
  so the block must be re-authored, then Resumed.

The Cloudflare cron trigger is deployed empty while this ships; restore
`crons = ["*/30 * * * *"]` in `scheduler-worker/wrangler.toml` once the MCP is
running this code.

### Fixed — the ⓘ annotations on Performance opened where nobody could see them

Every `Tip` on the page did open on hover — the panel reached `opacity: 1`
exactly as written. It was then clipped away by its own ancestors. `overflow-x-auto`
computes `overflow-y: auto`, so the table's horizontal scroller clips vertically
too, and the card around it adds `overflow-hidden`. An `absolute` panel hanging
below the trigger has nowhere to go: a header tooltip surfaced as a sliver, a
body-row tooltip as a one-pixel line of border. The three metrics that most
needed explaining — Trend, Escape velocity, Breakout ratio — were the three
whose explanations were unreachable.

The panel is now portalled to `<body>` and positioned `fixed` from the trigger's
client rect, so no ancestor can clip it. Being free of the layout also lets it be
clamped to the viewport, which the old `-translate-x-1/2` panel could not be —
the right-most columns previously ran their explanation off the edge of the
window. It flips above the trigger when the space below is short, follows the
trigger on scroll and resize, and answers to touch (tap to open, tap away to
dismiss) as well as hover and keyboard focus.

Verified in a headless browser against the real component: summary widget, table
header and last-row cell all render fully inside the viewport, in light and dark,
at 1280px and 390px wide.

### Changed — Performance page reads without a legend

The Followers widget carried both a lucide `Users` glyph and a `👥` emoji: one
concept, two icons. The emoji is gone.

"Curve" named the shape of a thing without saying what was plotted. It is now
"Trend", and it carries the same `Tip` treatment as every other metric on the
page — impressions at each snapshot, oldest to newest.

The Escape velocity and Breakout ratio legend chips in the table header are
folded into the columns they described. The columns had abbreviated to `EV` and
`BR` precisely because the legend was there to expand them; with the glyph and
full name in the header cell, the reader no longer looks in two places.

### Fixed — the link-placement panel promised a comparison it could not make

`_detect_link_placement` reads the outgoing body text, so it can only ever
return `body` or `none` — it cannot see a link in a first reply. `first_reply`
lives in a schema comment and a unit test; nothing stamps it in production. The
panel nonetheless offered "link-in-body vs. link-in-first-reply vs. no link",
and with a single cohort it rendered one median with nothing to compare against.

It now renders only when the corpus actually holds two or more placement
groups, and the title ("Link placement and reach") and tip describe what the
harvester can produce rather than what was hoped for.

### Fixed — the small Refresh spinner was too faint to read as "working"

`RefreshButton`'s `sm` scale goes h-8/h-4 → h-10/h-5. The fix lives in the
shared component rather than in a per-page override, so the Performance and
Scheduler page headers stay the same size — the drift this component was
written to prevent.

### Changed — frontend moved to Tailwind CSS v4

Tailwind v4 relocated its PostCSS plugin, so a bare dependency bump could not
build. The frontend now uses the first-party `@tailwindcss/vite` plugin, and the
PostCSS layer is gone with it — `postcss.config.js`, `autoprefixer`, and
`postcss` are removed, since v4 vendor-prefixes via Lightning CSS.

`tailwind.config.js` is deleted in favour of CSS-first configuration in
`src/index.css`. `darkMode: "class"` becomes
`@custom-variant dark (&:is(.dark *))`, which the dark/light/system picker in
`lib/theme.ts` depends on: without it every `dark:` utility would quietly fall
back to `prefers-color-scheme` while the build still passed. The `content` array
becomes explicit `@source` directives. `@tailwindcss/typography` is dropped —
no `prose` class was ever used.

Utility renames (`rounded`→`rounded-sm`, `rounded-sm`→`rounded-xs`,
`outline-none`→`outline-hidden`) were verified value-equivalent against a v3
baseline build. One deliberate visual change: the hero `<h1>` carries
`leading-tight sm:text-4xl`, and v4 lets the explicit `leading-tight` win where
v3 let `text-4xl`'s bundled line-height override it, so the heading renders at
the 45px it asks for instead of 40px.

### Changed — track tollbooth-dpyc 0.83.0

Consumes the caller-supplied `maximum` on `clamp_timeout`, without which the configured
block ceiling would still be cut to the wheel's 900s fallback.

## 0.37.3 — 2026-08-01


### Fixed — X's reason for declining a post is no longer thrown away

Post `bdbe1818` paused with:

```
x_api_error: X API 402: X API subscription or access tier does not cover this request
```

Every word after the status code was **ours**, written months earlier.
`x_client.py` parsed X's response body, raised a canned sentence, and kept the
body only in `.raw`, which nothing surfaced. Asked "what is wrong with this
post?", the record could not answer.

And the canned sentence was wrong: a 792-character sibling from the same account
posted cleanly thirty minutes earlier, so a lapsed subscription is precisely
what it was not.

`_x_says()` reads all three shapes X uses — `detail`, `title`, and the legacy
`errors: [{message}]` list — plus a raw-text fallback, and every error branch now
uses it (429, 401/403, 402, non-201, non-200, media upload). The fallback fires
only when X truly said nothing, and it says *"X declined this request and gave no
reason"* rather than inventing one.

`publisher.py` splits the two: `reason` is a stable `x_api_error: <status>` a
surface can switch on, `detail` is X's own words. They used to be concatenated,
so the FE could only pattern-match prose — prose we had written.

`attemptLabel` stops asserting a cause: a 402 reads "X declined it (402)" with
X's sentence in the tooltip, and 429 / 401 / 403 get their own labels now that
the status code survives.

## 0.37.2 — 2026-08-01


### Fixed — the scheduler Worker was undeployable, and nothing checked

v0.37.1 merged green and `deploy-worker.yml` then failed on `npm ci`:

```
lock file's @cloudflare/workers-types@4.20260627.1 does not satisfy ^5.0.0
lock file's typescript@5.9.3 does not satisfy ^7.0.0
```

Pre-existing drift, not introduced by that release — `scheduler-worker/package-lock.json`
carried root version `0.1.0` while the manifest had moved through 0.3.0 to
0.4.0, and the devDependency majors were raised (around #285) without ever
regenerating the lock. The local `npm run typecheck` that "passed" ran against
the OLD installed deps, so nobody had ever compiled this Worker on the versions
its own manifest asks for.

Lock regenerated. It typechecks clean on TypeScript 7 and workers-types 5.

### Added — CI builds the scheduler Worker

The Worker had no pre-merge check of any kind. The only thing that ever built it
was `deploy-worker.yml`, which runs *after* merge — so a lock/manifest
disagreement could only ever be discovered by leaving `main` undeployable.

New `worker` job runs `npm ci` (which fails outright on lock drift) and
`npm run typecheck`. Same always-runs / skip-the-expensive-steps shape as the
`frontend` job added after #285, in the one corner that still lacked it.

## 0.37.1 — 2026-07-31


### Fixed — the scheduler could never spend an authorization it held

`RENEW_BEFORE_MS = 24h` was an absolute constant gating the ONLY path that fires
posts from a cached token:

```js
if (state?.phase === "active" && state.expiresAt - now > RENEW_BEFORE_MS)
```

How long an npub authorization lasts is a **human's choice at reply time**, not
something the code can know. The operator granted 2 hours on 2026-07-31, so
`2h > 24h` was false on every tick: the Worker held a valid token, refused to
spend it, fell through to "request a fresh proof", and DM'd for approval again.
It posted only inside the same tick that completed a proof — which is why
nothing ran between 19:30 and 23:03 while the queue sat due.

The lead is now a share of what was actually granted
(`RENEW_AT_REMAINING_FRACTION = 0.25`), so a 30-day grant renews with days to
spare and a 2-hour grant renews with 30 minutes — the same proportion of notice
either way. A fixed window also punished the cautious answer: a deliberately
short grant produced a machine that asked permission every half hour and never
used it.

`ProofState` gains `issuedAt`, without which the granted lifetime is unknowable
after the fact. A state written by an older build has none and is re-requested
once; every state after that carries one.

`/status` now reports `grantedForMinutes` and `spendable`. A Worker holding a
good token it declines to spend used to be indistinguishable from one holding
nothing — both read "pending" on the next tick, which is exactly how this hid.
`renewsBeforeExpiryHours` is replaced by `renewsAtRemainingPercent`.


### Fixed — a reconnected X account was still being told to reconnect

A post reading `Sending · Reconnect X · working…` — three states that cannot all
be true at once, on an account that had just been reauthorized.

`last_attempt_reason` records what was true at the LAST attempt and nothing
rewrites it afterwards. The row rendered it as a live instruction:

- The **Reconnect X** button was gated on the reason alone — not on the post's
  status, so it showed while a publisher was mid-flight (`claim_due_post` moves
  `scheduled → sending` without clearing the reason, deliberately: if that
  attempt then dies silently, the old reason is the only trace left), and not on
  whether X was currently connected, so it survived the reconnect that fixed it.
- The warning chiclet likewise kept saying "X access expired" about an account
  that had been working for hours.

The button now additionally requires `scheduled`/`paused` **and** that
`getXConnection()` does not report `connected`. Only a definite `connected`
suppresses it — `indeterminate` still offers the door, since a warming vault is
not evidence the account is fine.

When X *is* connected, an OAuth reason renders as history rather than a warning:
muted, and prefixed `last attempt:` instead of the warning glyph.

## 0.37.0 — 2026-07-31


### Fixed — a held post says why, in the words of whatever refused

The scheduler reported `oauth_token_expired` on held posts; the operator
reconnected X; the grant was dead again within hours. X refresh tokens carrying
`offline.access` do not age out in hours. On 30 Jul five posts were held for it
at 18:00, 18:30, 19:00 and 19:30 — and on 31 Jul one post produced four
different verdicts on the same credentials in three hours (`warming_up`,
`oauth_refresh_unavailable`, two silences, `oauth_token_expired`).

`publisher._hold` / `_pause` kept only the situation's `error_code`, dropping the
sentence that said which failure it was. Behind that, the SDK was collapsing five
unrelated causes into that one code — see tollbooth-dpyc 0.77.0, which splits
them and adds `refresh_token_lost` for the real culprit here: a token renewal
that reached X and whose answer was lost, retiring a refresh token X had already
rotated.

Both now travel. A hold records `reason` (the code a surface switches on) **and**
`detail` (the provider's own words, redacted), and both are stamped on the post
row — new `last_attempt_detail` column, added idempotently like its siblings.

### Fixed — a lost audit write no longer erases a publication

On 31 Jul three ticks launched a publisher for post `056c9d73` and the traffic
log showed only the launches. The posts were released correctly; it was the audit
INSERT that failed, and `_record` swallowed it — so a tick that dispatched work
it never heard back from was indistinguishable from a publisher that died with
its container. The write is retried once, a loss that survives is logged at
ERROR, and the post row's `last_attempt_reason` / `last_attempt_detail` remain
the durable record regardless.

### Fixed — the FE stops offering "Connect X" for problems reconnecting can't fix

`attemptLabel` gained the new codes, worded by audience:
`refresh_token_lost` → "X renewal was cut off — reconnect once";
`operator_app_credentials_rejected` → "operator's X app was refused";
`refresh_failed_unclassified` → "renewal failed — retrying". `detail` renders
under the reason in the Scheduler traffic log, in the Posts chiclet tooltip, and
on its own line in the debug panel. `OAUTH_NEEDED_CODES` gains the two codes that
genuinely need a reconnect and pointedly excludes the operator-side faults.

### Changed — track tollbooth-dpyc 0.77.0

Required, not optional: `restore_oauth_session` returns an `OAuthSituation`
rather than a string.

## 0.36.3 — 2026-07-31


### Fixed — a post X never confirmed was retried, and went out twice

X created tweet `…0735014637900` at 20:06:16 on 2026-07-30. The read timed out,
so the answer never came back. The post was **held**, the 20:30 tick published
the same content again as `…7064064160148`, and eXcalibur recorded only the
second — leaving the first live on X with no row anywhere. Two tweets, 25
minutes apart, one of them invisible to the app that sent it.

`x_client` already had this right: `_post_retrying_connect` retries **only** the
connect phase, and says why — *"A ReadTimeout means the request DID reach X and
we merely never saw the answer — the tweet may already be live."* That
discipline was undone one level up, where a read timeout fell into the
publisher's generic `except Exception` and became an ordinary hold. A hold means
"safe to try again", which is the one thing nobody knows here.

Failures where the request was already on the wire — `ReadTimeout`,
`WriteTimeout`, `RemoteProtocolError`, `ReadError` — now **pause** the post with
`x_post_outcome_unknown`, and the Posts list labels it *"X didn't confirm —
check your timeline"*. Only a human can look at X and say whether the tweet
exists, so the label sends them there rather than guessing on their behalf.

A connect failure deliberately still holds: nothing was sent, the one phase
that is safe to retry has already been retried, and pausing a post for a blip
would strand it. The rule is about ambiguity, not about timeouts.

## 0.36.2 — 2026-07-30


### Fixed — one scheduled slot published two tweets

Template `844c6b64` tweeted the same scheduled occurrence twice on 2026-07-30,
41 minutes apart. Both snapshots carried the identical `publish_at`
(`11:40:25.129589`) and two different tweet URLs.

It was invisible in the scheduler log. The publication row is written *after*
the state writes, so the death that causes this bug also erases its own
evidence — the log showed each post publishing exactly once, and only the post
rows disagreed. A log that cannot record a failure is not evidence of its
absence.

What happened: `post_tweet` succeeded, `create_sent_occurrence` succeeded, and
`mark_sent` never ran. The template stayed `sending`, still carrying the
`last_attempt_at` from its claim. Twenty-eight minutes later the next tick asked
"is this claim older than 20 minutes?", found that it was, re-claimed the post,
and published it again.

Three layers, none of them sufficient alone:

- **Atomic.** `record_occurrence_and_advance` writes the occurrence snapshot and
  advances the template in ONE data-modifying CTE. Either both land or neither
  does; there is no longer a state in which the tweet is recorded but the
  template still looks unpublished.
- **Fenced.** That same UPDATE is the test-and-set. It matches only while the
  publisher still holds the claim it was handed — `claim_due_post` already
  stamps `last_attempt_at` on every claim, which makes it a fencing token with
  no new column. A re-claim moves the stamp, the CTE yields nothing, and the
  publisher reports `posted_claim_lost` rather than overwriting the new owner.
  Nothing can un-send a tweet; the least it can do is say so out loud.
- **Bounded.** `_CLAIM_LEASE` 20 → 45 minutes. A lease shorter than the
  30-minute cron is not crash recovery — it guarantees every in-flight publisher
  is declared dead by the very next tick. A test now reads
  `scheduler-worker/wrangler.toml` and asserts lease > cron, so the arithmetic
  cannot regress silently.

Plus a unique index on `(template_id, publish_at)` — the natural idempotency key
for a scheduled occurrence — as the backstop for any path the above misses. It
will refuse to create while a duplicate pair already exists in the table; that
logged failure is the finding, not noise.

## 0.36.1 — 2026-07-30


### Fixed — the Scheduler page said less about the scheduler than Posts did

Both pages answer the same question from the same `get_scheduler_log` rows, but
with two bodies of code. `SchedulerPage` kept its own copy of the freshness
thresholds and a `health()` that produced only a dot and a label — under a
comment reading *"mirrors SchedulerHealth"*, which is the tell. A mirror drifts,
and this one had: going to the **primary** Scheduler page showed strictly less
than the Posts toolbar, with no Sending / Retrying / Soon / Paused badges at all.

Meaning now lives in `lib/schedulerState`, rendering in `SchedulerStatusLine`. A
page supplies rows; it does not get to decide what they mean. The line renders as
a fragment rather than a box, so each surface keeps its own container — Posts a
button that refreshes on click, Scheduler a plain span beside the title — and
that container is the only thing the two are still allowed to differ on.

Adopting the shared derivation also fixes a real defect the Scheduler page had:
it read freshness from `runs[0].run_at`, the newest row of **any** kind. A
publication lands minutes after the tick that launched it, so one arriving could
refresh the timestamp and make a dying cron look alive. Freshness comes from the
newest *tick* now, which is why that logic existed in the first place.

An empty log reads "Scheduler quiet" rather than the page's own "No tick logged
yet" — one vocabulary instead of two; the tooltip still says no run is logged.

## 0.36.0 — 2026-07-30


Three controls and labels that didn't mean what they said.

### Fixed — "3 Scheduled" counted a subset and read as the whole rotation

The scheduler badge counted posts *held on the last run* — a subset of Scheduled —
but wore the status name, so beside a dozen scheduled posts "3 Scheduled" looked
like a broken count rather than a warning about three of them.

It says **"Retrying 3"** now, which is what those posts are doing, and matches the
words the Posts list already uses for the same situations ("X didn't answer —
retrying"). The tooltip still names the Scheduled filter, so the click-through
survives. This is a deliberate exception to the rule that every badge word is one
of the six Post statuses, and the rule's comment now records why.

### Added — a healthy scheduler says what's coming

"Scheduler healthy" never said whether anything was actually queued. A new
**"ⓘ 9 Soon"** carries the forecast, read from `upcoming.count` on the newest
tick — which `get_scheduler_log` already returns and the Scheduler tab already
renders per row.

Deliberately NOT counted by listing Scheduled posts: `list_posts` is a paid tool
and this component polls every five minutes, so that would have billed the owner
on a timer, forever, to render a badge. It appears only while the scheduler is
healthy — a forecast read off a tick that may not run is a promise the badge
cannot keep.

### Fixed — one Refresh control instead of two

Posts had a 48px icon button that spun while loading; Scheduler had a small text
button that neither spun nor disabled. Same verb, same job, two affordances to
learn, and only one of them admitted it was working.

Both now use `RefreshButton`, which fixes the glyph, the spin, the disabled state
and the accessible name in one place so they cannot drift again; `size` is the
only knob. SchedulerPage gains the busy state it never had.

## 0.35.0 — 2026-07-30


Ships everything below, which had been sitting merged-but-unreleased on `main` —
including the label work that was inert until the wheel bump landed with it.

### Fixed — a rejected X token renews itself, and a held post has somewhere to go

Two halves of the same complaint: the scheduler blamed X for everything, and on the
occasions it was right about X, the owner had nowhere to click.

`_x_api_error_to_response` mapped an interactive 401/403 straight to
`oauth_token_expired` and set `needsXConnect` — sending owners to reconnect a working
account — while `publisher.py`'s `_X_NON_TRANSIENT = {402}` treated the very same 401 as
transient and self-healing. Both were in this repo, disagreeing, and the interactive one
was wrong: a post that 401'd at 23:00 posted cleanly an hour later. A 401 now routes
through the wheel's `invalidate_oauth_access_token`, which retires the cached expiry so
the next call spends the refresh token, and reports the retryable `oauth_token_rejected`
instead of a re-authorization demand.

The Posts list labels that one **"renewing X access — retrying"**, joining
`oauth_refresh_unavailable` in the set of reasons that must read as a wait rather than a
chore.

And for the reasons that genuinely *are* the owner's to fix, a held post now offers
**Reconnect X →** beside the reason, routing to the Profile panel that already runs the
whole OAuth dance. Before this the row named the problem and left the owner to guess
that the cure lived on another page. It is gated on `OAUTH_NEEDED_CODES` — widened to
include `oauth_unavailable`, and documented to exclude the two self-healing codes,
because offering "reconnect" is never free: on a provider that rotates refresh tokens,
re-authorizing to chase a blip discards a working grant.

### Changed — track tollbooth-dpyc 0.76.0

Bumped the pinned SDK to 0.76.0, which carries the serialized refresh (one refresh at a
time per patron), the retryable/terminal split, and the `invalidate_oauth_access_token`
primitive the 401 fix above depends on.

### Fixed — four posts, one refresh token, four "X access expired"

The 22:30 tick found four posts due, launched four publishers, and held all four for
`oauth_token_expired` inside 24 seconds. X was connected and nothing had expired.

The cause is upstream in the wheel and is fixed there: publishers run together, so four of
them refreshed the **same** single-use X refresh token simultaneously — one won, three were
told `invalid_grant`, and each of those three told its owner to reconnect an account that
was never disconnected. Separately, the refresh POST ran on httpx's bare 5-second default
against `api.x.com` — the very host this repo already gave a 10s/30s budget after watching
it time out on connect — and every failure of it, timeout or refusal alike, was reported as
an expired session.

What changes here is what the owner reads. A refresh that never completed now arrives as
`oauth_refresh_unavailable` and the Posts list labels it **"X didn't answer — retrying"**,
which is what the next tick actually does. It is not in `OAUTH_NEEDED_CODES`, so it never
raises the "Connect your X account" prompt, and the publisher holds on it rather than
pausing — a paused post waits for a human, and there is nothing here for a human to do.

The label was inert until the wheel bump; both land together in 0.35.0.

### Fixed — the Scheduler tab said "the token" and meant a different one

`scheduler_status` reports `renewsBeforeExpiryHours: 24` and `rerequestAfterHours: 1`, and
the Configuration card rendered the first as *"re-requests 24 h before the token expires"*.
Both numbers describe the **worker's own npub authorization** — the Device-Grant proof it
renews roughly monthly — and neither has anything to do with X OAuth2. Read one card away
from the X connection panel, with "the token" standing alone, they invite exactly the wrong
conclusion: that X access is lapsing on a scheduler's cadence.

Every row that describes the npub credential now says so, and the renewal row says outright
that it is not the X connection. Nothing on this page describes the X OAuth token.

### Fixed — a held post named a cause that wasn't the cause

Post `844c6b64` sat unpublished from 2026-07-27 to 2026-07-29. Every 30-minute tick held
it and stamped a reason: `oauth_not_yet_authorized`, `oauth_token_expired`, or
`insufficient_balance_resolve`. X was connected the whole time (`get_x_profile` returning
`@lonniev`) and the owner held 844 sats. Every reason was false, and each one sent the
owner to fix something that wasn't broken.

Most of that is a wheel bug (tollbooth-dpyc 0.75.0 teaches the vault read to say why it
couldn't answer). One half was ours: `_apply_billing` already distinguishes a patron who
is short of sats from a ledger it could not read — the second returns `vault_unavailable`,
charges nothing, and carries the comment *"never tell a funded patron 'insufficient
balance'"*. The publisher threw that away and hardcoded `insufficient_balance_resolve`,
undoing the distinction at the last step. It now propagates the real `error_code`, exactly
as it already did four lines earlier for a pricing denial, and carries which charge refused
as its own `stage` field rather than baking it into the reason string.

`attemptLabel` was missing the codes that actually occur — `oauth_not_yet_authorized` and
`insufficient_balance_resolve` both rendered raw. It now covers the real set, with the
wording checked against what it tells the human to *do*: a service still warming up must
not read as the owner's problem, and a database over quota must not read as something that
will clear if they wait.

### Changed — LLM calls route through a model router, and the wheel decides which

Both AI paths — composing a dynamic block and refining a flagged region — pinned
`https://api.anthropic.com/v1/messages` in their own module, alongside their own copy of
the web-tool declarations and a `clamp_timeout` byte-identical to optionality-mcp's. That
is a wheel concern, and it now lives in `tollbooth.llm_route` (SDK 0.74.0). What stays
here is what makes a *post* good: the prompt, the `<post>` tag extraction, the author's
web-lookup budget.

Composing draws the **writer** tier and refining the **reader** tier, since one writes
copy the owner publishes under their own name and the other suggests three short
rewrites. Changing either model is an environment variable and a restart, not a release.

The operator's key now names a *provider account*, which is why it is passed to every
call rather than read from module state: giving composition and refinement separate
accounts later is a second credential, not a redesign.

**The vaulted credential is renamed `anthropic_api_key` → `llm_api_key`, with no
compatibility shim.** The operator must redeliver it via Secure Courier — which was
already required to change providers, so the rename costs nothing extra. Until it is
delivered, dynamic blocks fall back to their fallback text and refine refunds its fare;
neither posts a gap.

### Fixed — an exhausted AI account was reported as a passing blip

Three separate places decided whether the AI provider had run out of money, and all three
matched only Anthropic's wording (`credit balance`, `purchase credits`, `plans &
billing`) because Anthropic reports an empty account as a **400**. A model router reports
it as a **402** reading *"Insufficient credits"*, which matches none of those.

An exhausted account therefore read as a generic transient failure: the operator's "feed
me" DM never fired, the scheduler kept retrying an endpoint that could not recover, and
patrons were told to try again later — indefinitely. `publisher.py`'s audit-ring reason
had the same blind spot from the other direction, holding only an exception string with
no status code at all.

All three now defer to the wheel's classifier, which reads both providers' wording, takes
a bare 402 from a metered LLM provider as unfunded, and classifies from a message alone
when no status survived. A model slug the provider no longer recognises is newly
distinguished as permanent rather than retryable — the signature of a marketplace
retiring a model under a running deployment.

`refine_post_region` had the defect in its plainest form: *every* upstream failure became
`llm_upstream_error` with "Try again shortly", so an empty account produced advice that
could never come true and no operator alert at all. It now curates the same way the
dynamic-block path does and wakes the operator when the cause is theirs to fix.

The operator's "feed me" DM was also telling them to add credit at `console.anthropic.com`
regardless of which provider the key belonged to, and always claimed dynamic blocks were
what broke — even when a refine had failed. It now names the capability the patron was
actually denied and points at the account behind `llm_api_key` without naming a vendor
console the operator may not have.

### Changed — the editor stopped naming a vendor it may not be calling

"Refine with Claude" was accurate when one lab was hardwired. With the model now a
configuration choice, the button, its hero card, the voice-profile hint, and `llms.txt`
would have been quietly false. The copy names the action instead: **Refine**.

### Added — a `none` chiclet on the Posts filters

`all` had been doing double duty: it selected every status, unless everything
was already selected, in which case it cleared them. So from a *partial*
selection there was no way to clear at all — clicking it selected everything
instead, the opposite of what you wanted.

`all` and `none` are now two actions, each idempotent and each doing exactly one
thing. The empty selection says so plainly ("No status selected — pick one
above, or choose all.") rather than claiming nothing matched.

### Changed — the scheduler badges speak the Posts vocabulary

A Post is only ever one of six things: Draft, Scheduled, Sending, Sent, Paused,
Archived. The health pill had been inventing its own words — "2 Held", then
"1 not posted", then "1 publishing" — each of which named something with no
filter to click and no chiclet to reconcile against.

Every badge is now a status that already exists, so each one maps to a filter
that is already there:

| Badge | Post status | Where |
|---|---|---|
| `1 Sending` | `sending` | a publisher is working it now |
| `⚠ 1 Scheduled` | `scheduled` | held last run, retries next — same ⚠ the post row shows |
| `⏸ 1 Paused` | `paused` | stopped until resumed — same ⏸ the post row shows |

The `working` scheduler state is gone with them. A publisher being mid-flight is
*post* state and belongs in a badge; the dot stays about the cron, so the two
never compete to describe the same thing in different words.

### Fixed — "Scheduler working" meant the wrong thing entirely

`working` was derived from the tick's own audit row still being open. That made
sense when a tick did the publishing inline and ran for minutes. Since the
scheduler became a dispatcher it closes that row in about two seconds, so the
state was both unobservable and — when it did appear — a statement about the
tick, not about any publishing.

It now means what a reader would assume: **a publisher is working right now**.
Derived honestly from a log that records only starts and finishes — a post
launched by a tick with no publication row since is still in flight, which is
exactly the post showing as `Sending` on the Posts tab. Shown as a
`N publishing` chip, so the pill and the status chiclet can be reconciled.

A stall still outranks it: publishers can be mid-flight while the cron behind
them is dead, and the dead cron is the thing worth saying.

### Fixed — "Held" was a status that doesn't exist, and the count was of the wrong thing

The health pill read `2 Held` while only one post was in flight, and the Posts
page has no Held tab to go looking in — because a held post isn't held, it's
still **Scheduled**. "Held" is the outcome of one publication attempt, not a
state a post occupies.

- The badge counted publication *rows*. One post failing on every tick writes a
  row each time, so a single struggling post read as two. It now counts distinct
  posts, newest outcome first, so a post that has since published stops counting.
- The badge says `N not posted` rather than inventing a seventh status, and its
  tooltip names each post and says where it actually lives — "still Scheduled —
  retries next run", or "now Paused".
- The Scheduler tab's publication rows never showed *which* post. They now carry
  the short id as a link straight to it.

### Fixed — the X write path had a 5-second budget and no second chance

`51110ca3` held three ticks running with `ConnectTimeout`, each time after
~6 minutes of dynamic-block resolution. The resolve was working; the *last*
step wasn't. `post_tweet` used a bare `httpx.AsyncClient()`, whose default
allows 5s for every phase — while `/users/me` on the same host answered fine,
so egress was healthy and the margin was simply too thin.

- `X_API_TIMEOUT` (connect 10s, read/write 30s) now covers the API calls, the
  way `IMAGE_DOWNLOAD_TIMEOUT_SECONDS` already covered the image paths.
- `post_tweet` retries a **connect-phase** failure up to three attempts. By the
  time a publication reaches this line it has spent minutes and real operator
  money resolving its content; discarding that because a socket didn't open is
  a bad trade.
- A `ReadTimeout` is deliberately **not** retried. The request reached X and we
  merely never saw the answer — the tweet may already be live, and a retry
  would post it twice. Pinned by a test.

### Fixed — a held post can no longer decline to say why

The live log showed a `held` publication whose reason rendered as `—`.
`dict.get(k, default)` returns the STORED value when the key exists, so an
upstream situation arriving as `{"error_code": None}` slipped past the default
and recorded a blank reason; `str(exc)` on an exception with no message did the
same. A post that quietly didn't publish is the exact failure this service keeps
relearning.

- The four call sites that could pass a blank now use `or` rather than a default
  argument, and a message-less exception is named by its type.
- `_stated()` is the backstop: any blank reaching it is recorded as
  `unreported` **and logged as a call-site bug**, so the row always names
  something and the defect is still visible as a defect.

### Added — the heartbeat forecasts instead of just reassuring

`alive · nothing due` said the cron was breathing and nothing else. It now says
what's coming: `alive · nothing due · next of 3 in 47 min`, or
`nothing scheduled ahead` when the queue has emptied — which is itself worth
seeing, since an empty queue and a broken one used to read the same.

Grouped by owner in the ring rather than totalled, because the log is
owner-scoped: a patron is told about their own queue and never the size or
timing of anyone else's. The tick's own totals span every owner and stay with
the operator. Best-effort — a forecast that can't be read never fails a tick.

### Added — the heartbeat says which build is beating

`scheduler … · alive · nothing due` is the line you see most and learn to skim
past. It now names the deployment that answered — `· v0.34.4 da69054` — in the
debug log and the Scheduler tab. Version *and* commit, because this service has
served cached bytes while reporting a fresh version, and the commit is the
honest half of that pair. It's the difference between a row that reassures and
one that can settle "did my deploy actually land?".

### Changed — the scheduler dispatches; a publisher publishes

Three clocks had been conflated into one: the cron's 30-minute periodicity, the
~128s lifetime of the HTTP request the Worker makes, and a dynamic block's own
runtime budget of up to 900s. The third was nested inside the second, because
`scheduler.py` awaited `resolve_block` **inline** — the one place in the service
that did long LLM work inside a request. The interactive path never did this: it
calls `runtime.start_async_job(...)` and hands back a claim check. Every symptom
of the last two days descends from that single inline `await`: the 524 stall, the
budget clamps invented to survive it, and a tweet published on fallback text.

The fix is to consume the capability that already existed rather than inline a
synchronous copy of it.

- **`scheduler.py` finds due posts and launches, and does nothing else.** Claim
  atomically, `start_async_job("publish_post", …)` per post, record what was
  dispatched, return. A tick is now seconds regardless of how slow publishing is.
  It has no billing surface and never loads the operator's Anthropic key — a test
  asserts both by giving it a runtime that lacks those attributes entirely.
- **`publisher.py` (new) owns one post's journey to X** — resolve, bill, post,
  write its own completion status. Registered as the `publish_post` job kind, so
  it runs on the wheel's queue. Nothing waits on it and nothing supervises it: a
  publisher that dies with its container leaves the post claimed, and the
  existing 20-minute claim lease hands it back to a later tick. That lease was
  always sized for this (*"must exceed the longest possible resolve, 900s"*) —
  the request ceiling is what had made it unreachable.
- **The author's `runtimeLimit` is honored again, up to 900s.** `TICK_BUDGET_S`,
  `RESOLVE_BUDGET_S` and `MIN_POST_BUDGET_S` are **deleted**, not retuned — they
  only ever existed to squeeze an LLM call into a request it didn't belong in.
- **A recurrence that fires faster than its content can be built** needs no
  special handling: a post still `sending` inside its lease isn't due, so it
  serializes instead of piling up.
- The audit ring now carries two row kinds — `tick` (dispatch) and `publication`
  (one post's outcome) — each owner-scoped, with the Scheduler tab, health pill
  and debug log reading both. The ring keeps 200 rows so publications can't crowd
  out the heartbeats.

### Reverted — an X 401 is transient after all, and must not pause

The previous entry's premise was wrong. A 401 on `post_tweet` is **not** a dead
authorization needing re-auth: the SDK refreshes only when its own `expires_at`
says the token is stale, so X rotating a refresh token out from under us yields a
rejected token while our bookkeeping still reads fresh. It self-heals on the next
refresh. Observed 2026-07-25: a post that 401'd at 23:00 published cleanly an
hour later with no human involved — pausing would have stranded it awaiting a
Resume it never needed.

- `_X_NON_TRANSIENT` is back to `{402}` alone. A lapsed X subscription still
  pauses; a rejected token holds and retries, as it did before.
- The post-card label change is reverted with it — it was built on the same wrong
  reading. A test now pins 401/403 as **holding**, with the reasoning, so the
  mistake isn't repeated.

### Fixed — the tick budget was sized against a guess, and it clipped real posts

`TICK_BUDGET_S` was set to 75s against an *assumed* ~100s edge timeout (the
proxy's documented default). The measured cut is **~128s** — two ticks died at
129.7s and 131.2s of Worker wall time, ~2s of which is connect + whoami. The
guess left ~50s of headroom unused and pushed a real dynamic block into its
fallback: a published tweet carried the author's fallback text instead of the
content it asked for.

- `TICK_BUDGET_S` 75 → **95**, `RESOLVE_BUDGET_S` 60 → **85**,
  `MIN_POST_BUDGET_S` 35 → **40**, keeping ~30s of margin under the measured
  ceiling for the X call and the writes that follow the last resolve. A single
  dynamic block now gets 85s instead of 60s. The comment records the measurement
  so the next person tunes against evidence rather than a default.

### Added — a post that goes out on fallback text says so

Substituting a block's fallback changes what the world reads, and it left no
trace but a log line: the run reported a clean `posted` while the tweet carried
different words than the author wrote. Neither the operator nor the owner could
tell it had happened, let alone why.

- Each fallback is recorded against the posted entry as
  `{block, reason, budget_s}`. The reason separates *we* cut it short
  (`resolve_timed_out_at_85s`) from *the provider* failed
  (`operator_llm_unfunded`, `upstream_rate_limited`, …) — the first is a tuning
  question answerable from the recorded budget, the second an outage.
- The Scheduler tab shows "⚠ N on fallback" beside the posted count, with the
  reasons in the tooltip. Recording it somewhere nobody looks would have repeated
  the original mistake.
- Publishing behavior is unchanged: the author wrote a fallback, so it's used.

### Fixed — a dead X authorization now says so, and stops retrying

The first unwedged tick (2026-07-25 23:00 UTC) surfaced a real post failing with
`x_api_error: X API 401: Unauthorized` — the owner's X authorization is dead. The
scheduler recorded it correctly, but everything downstream mishandled it.

- **It pauses instead of retrying forever.** Only a 402 was treated as
  non-transient; a 401/403 fell through to the "hold and retry" path, so the post
  sat `scheduled` and every tick re-billed and re-refunded the owner while the
  post looked like it was still trying. `_X_NON_TRANSIENT` now covers 401/402/403
  — a dead authorization is exactly as un-retryable as a lapsed subscription. A
  500 still holds and retries, which is what a blip deserves.
- **The post card names the right problem.** `attemptLabel` mapped a 401 to "X
  network error" — a label a human reasonably reads as "it'll clear on its own."
  It reads "X access expired" now.
- **The pause names the remedy.** A paused post's tooltip said "fix the cause at
  the provider", leaving the human to work out which provider and which cause.
  It now points at reconnecting X on the Profile tab, or renewing the X
  subscription for a 402.
- **Deferred posts are visible in the Scheduler tab.** They were counted in the
  health pill but missing from the traffic log. Shown as a neutral "N waiting"
  rather than folded into the error count — running out of tick budget is a
  hand-off, not a failure.

### Fixed — a scheduler tick can no longer stall the queue in silence

Diagnosed live on 2026-07-25: the cron kept firing, but every tick from ~19:00 UTC
died with `error code: 524` after ~130s — the edge in front of the MCP cuts a
request at roughly 100s, and `process_scheduled_posts` was running past it. The
throw escaped `ctx.waitUntil` unobserved, so nothing was logged, the proof state
was left untouched, and no run row was written: a wedged scheduler was
indistinguishable from a dead cron. The claimed post came back at the next cron
to overrun again, indefinitely.

- **The tick works to a deadline.** `TICK_BUDGET_S` (75s) bounds the whole run and
  `RESOLVE_BUDGET_S` (60s) caps a scheduler-fired dynamic resolve, so an author's
  budget — up to 900s on the interactive path — can no longer take a tick down
  with it. Posts past the deadline are reported as `deferred` and left
  **unclaimed** for the next tick; the head of the queue always gets its turn, so
  the budget can never starve it.
- **Every tick leaves a mark.** The audit row is opened (`status: started`) before
  any work and closed with the summary, so a tick cut off mid-flight is visible as
  exactly that. The health pill reads the new state: `working` while a run is
  genuinely in flight, `cut off` once an open row goes stale — a fresh heartbeat
  no longer reads as healthy on its own.
- **The Worker observes its own failures.** `scheduled()` now catches, so a tick
  that throws says so. An edge cut-off (`524`/`504`/timeout) is treated as work
  still in flight rather than a failed attempt: the Worker backs off for the
  20-minute claim lease (`heldOffUntil` on `/status`) instead of firing into work
  that may still be running. Worker 0.2.0 → **0.3.0**.

### Changed — track tollbooth-dpyc 0.69.1 (clear error for non-operator restricted calls)

- Bumped the pinned SDK to **0.69.1**: `restricted` (operator-only) tools now deny a non-operator with a clear `restricted` error instead of a misleading `proof_refresh_needed`. Complements the FE fix that already stops a patron from calling `scheduler_pending` — now if any non-operator does reach a restricted tool, the operator MCP returns the honest reason. `uv.lock` regenerated.

### Changed — the scheduler proof saga waits for human responsiveness

- Bumped `tollbooth-dpyc[nostr,prefect]` to **0.69.0**: the Secure Courier freshness window went 15 min → **1 hour**, so a proof challenge stays claimable long enough for a human to notice the DM and reply, and a 30-min tick reliably lands inside the window (15 min structurally missed it).
- New operator-only **"I've approved — check now"** button on the pending card: after replying in Studio, one click pokes the scheduler to claim the reply immediately instead of waiting for the next cron tick. Backed by a new operator-gated MCP tool `scheduler_check_now` → the Worker's new background `GET /tick` (returns immediately; the tick runs in `waitUntil`).

### Added — a Scheduler tab: the cron Worker made legible

- New **Scheduler** tab in the FE surfaces the scheduled-post Worker's configuration, status, pending approval, and per-tick traffic log — so it stops being a black box. It composes three already npub-scoped sources, so the page needs no gate of its own: each tool reveals only what the current proofed npub allows.
- New free MCP tool `scheduler_status` relays the Worker's public `GET /status` (cadence, version, renewal window, current authorization phase — never the challenge phrase or token) and adds the operator npub. The Worker gained a public `/status` route.
- The tab shows: authorization phase (active/pending/idle), last tick + health, the operator it acts for, cadence and renewal policy, the verify venue, the operator-only pending-approval card, and a traffic-log table (from `get_scheduler_log`, owner-scoped).

### Added — scheduler proof requests carry purpose + a Device-Grant second surface

- The scheduled-post cron Worker now sends a human-worded `reason` and a `verify_at` venue on its `request_npub_proof` call (it previously sent neither, so the ~monthly 3am renewal DM was contextless and pointed nowhere). Pricing Studio already renders both — the DM now says what is being asked and where to match the code.
- Owner-private `GET /pending` on the Worker returns the pending challenge phrase (never the active session token) only to a caller proving they are the operator npub. Fed from the Worker's own KV — a store an impostor can't write — so the phrase shown is the legit scheduler's.
- New operator-gated MCP tool `scheduler_pending`: the FE calls it with the operator-npub proof it already holds from an ordinary npub login, and the MCP reads the Worker's `/pending` **as the operator** (signing with the operator key it holds — no shared secret, no browser signing). This means the operator sees the pending phrase after a plain npub-DM login; no nsec ever touches the browser, and the FE↔MCP call is same-origin so there is no CORS or `verify_at` domain to reconcile.
- FE: a `SchedulerPendingCard` on the Posts page shows that phrase, its reason, and the match-gate, so the operator can confirm their own scheduler (not an impostor) before approving in Studio. Hidden unless pending and the viewer is the operator. `FE_URL` (the Worker's `verify_at` venue) points at the canonical FE domain.

## 0.34.4 — 2026-07-16


### Changed — track tollbooth-dpyc 0.63.3

- Bumped the pinned SDK to 0.63.3 (npub-proof challenge DM now stamps the request time). Also cuts a release for changes accumulated since the last tag.

## 0.34.3 — 2026-07-12


### Changed — SDK 0.62.4 (durable-jobs observability + missing-extra safety net)

- Pinned `tollbooth-dpyc[nostr,prefect]==0.62.4`. The SDK now degrades gracefully when the `[prefect]` extra is absent (loud warning + in-process fallback instead of crashing the first drill) and reports `detached_executor_resolved` / `detached_executor_error` in `service_status.durable_jobs`. eXcalibur already ships the `[prefect]` extra, so this is purely the new diagnostics for the sibling long-runner consumer. No excalibur code change.

## 0.34.2 — 2026-07-11


### Fixed — durable long-runner activates reliably on cold containers

- Pinned `tollbooth-dpyc[nostr,prefect]==0.62.3`. The SDK's `_ensure_async_executor` cached a *transient* creds-load failure (a cold vault on a container's first job), permanently pinning that container to in-process execution despite the long-runner creds being present — every dynamic-block resolve on it would then risk the in-process hard-cap. 0.62.3 retries the probe on a transient failure. No excalibur code change.

## 0.34.1 — 2026-07-11


### Changed — SDK 0.62.2 pin + forward-compatible shape callback signature

- Pinned `tollbooth-dpyc[nostr,prefect]==0.62.2`.
- `_resolve_shape_result` now accepts the second `params` argument the wheel threads through as of tollbooth-dpyc 0.62.2 (`shape_result(raw, params)`). Resolving a dynamic block is stateless, so `params` is ignored — but the signature must be in place before the SDK pin bumps, or the live detached (long-runner) path would break on the two-argument call. Defaulted (`params=None`), so the same code also ran unchanged on the prior 0.62.1 pin.

## 0.34.0 — 2026-07-10


### Added — published postings now link back to their recurring template

- A recurring post that carries a **dynamic block** fires as two rows: an immutable `sent` **snapshot** (the resolved static text that actually went to X) and the surviving `scheduled` **template** (which keeps its dynamic prompt and re-resolves on the next fire). This is correct and by design — nothing is lost — but the two rows shared a title and were indistinguishable, so a snapshot read as "the post lost its dynamic block." They're now visibly connected.
- Each sent occurrence stores a **`template_id`** back-link to the template it fired from (`create_sent_occurrence` threads it through; new `posts.template_id UUID` column, added idempotently). The scheduler sets it on every recurring fire.
- The **Posts list** gained two per-row chips and a link: **↻ recurring** (the live template reposts on its cadence), **⚡ dynamic** (carries a live prompt-driven block — distinguishes a template from a frozen snapshot), and **↗ from series** on a snapshot (opens the recurring template it fired from). `list_posts` now returns `is_recurring`, `has_dynamic`, and `template_id` per row, and accepts a `template_id` filter.
- The **editor** shows a banner in both directions: opening a published snapshot offers **"Edit the template →"** (so you don't edit a frozen record expecting future effect), and opening a live recurring template offers **"View published postings →"** (a `?template=<id>` filtered list of everything it has fired). `get_post` now returns `template_id`.
- **Caveat:** the back-link is forward-only. Occurrences fired before this release have no stored `template_id`, so they show no "from series" link; new postings do. The recurring/dynamic chips apply retroactively (derived from existing data).

## 0.33.0 — 2026-07-10


### Changed — Posts status filter is now a set of toggle chiclets

- The Posts page status filter changed from single-select tabs to a **select/reject chain of toggle chiclets**. Each status chiclet (Draft, Scheduled, Sending, Paused, Sent, Archived) toggles independently: **on** (filled) includes posts of that status, **off** (dashed, struck-through) excludes them. The **All** chiclet selects the whole set, or clears it when everything is already on. The default is all-selected — identical to the old unfiltered view.
- The selected set drives **server-side** filtering: the frontend sends the chosen statuses to `list_posts`, which matches them as set membership (`status = ANY(...)`) inside the same `WHERE` that feeds `COUNT`, `ORDER BY`, and the `LIMIT`/`OFFSET` page slice. So the total and every page reflect the filtered set — no client-side hiding of already-fetched rows. An empty selection short-circuits to the empty state without a round trip.
- The empty-state call-to-action now reads **"Compose a new post →"** (was "Compose your first post") in every no-results view, and shows "No posts match this filter." whenever a filter — including a partial chiclet selection — is active.

## 0.32.0 — 2026-07-10


### Changed — Posts table: a dedicated "Posted" column and icon actions

- The green "posted" indicator moved out of the Post cell into its own **Posted** column, alongside Scheduled and Edited. A sent post shows a green **peek** link (👁 + date, opens the tweet preview) when it has a tweet URL, or a **✓ date** otherwise; unsent rows show `—` like the other date columns.
- The row actions are now **Material Design icons** (inlined `currentColor` SVG paths, so the hover accent and light/dark themes flow through) instead of command words: Duplicate (`content_copy`), Resume (`play_arrow`), Return-to-Draft (`event_busy`), Repost (`repeat`), Archive (`archive`), Delete (`delete`). Each keeps its full tooltip and `aria-label`. Dropping the word labels frees the horizontal room the new Posted column needs; an in-flight action pulses its glyph rather than swapping to "…", so there's no layout shift.

## 0.31.1 — 2026-07-10


### Fixed — the expired-sign-in bounce now actually fires

- The proof-expiry re-auth gate added in 0.31.0 never triggered: the client compared the server's `error_code` against **uppercase** `PROOF_REFRESH_NEEDED` / `PROOF_REQUIRED`, but the wheel emits them **lowercase** (`proof_refresh_needed` / `proof_required`). The comparison never matched, so a lapsed proof on the Posts page (or anywhere) just dropped the raw *"cache entry is no longer valid"* text into an inline banner instead of re-presenting sign-in. The client now normalizes the code case-insensitively, so the bounce fires as intended.

### Changed — the frontend now carries the release version

- The Posts Manager footer showed a frozen `v0.1.0` (the never-bumped `frontend/package.json`) while the service reported the real release version, which was confusing as the UI evolved. The frontend version is now unified with the repo release version, so the footer reflects each shipped build.

## 0.31.0 — 2026-07-10


### Added — an expired sign-in re-presents the login screen instead of stranding you

- When your npub-proof cache lapses while you're working (routine — the cached DM proof only lives ~an hour), the next paid call on the Posts page (or the editor, or the wallet) used to drop the raw *"Your npub-proof cache entry is no longer valid"* text into a red banner and leave you on a page whose data silently wouldn't reload. Now that bounce **re-presents the sign-in screen** with a calm amber note — *"Your sign-in expired — that's routine. Sign in again to pick up where you left off."* — and your npub stays pre-filled, so re-signing is one DM (or an instant nsec/one-tap re-entry) away.
- The bounce is wired globally: the MCP client fires a proof-expiry signal that the app subscribes to, so it fires no matter which page the lapsed call came from. An in-browser nsec session re-signs each call inline and is left untouched — only a lapsed cached DM proof triggers the re-auth gate.
- The stale cached proof is also evicted from the "Recent identities" one-tap list on bounce, so the returning-user shortcut can't immediately replay the token the server just rejected.

## 0.30.1 — 2026-07-09


### Changed

- Bump `tollbooth-dpyc` to `==0.62.1` — the security-hardening batch (invoice-owner check on credit settlement, AES-256-GCM credential vault, encrypted self-provisioning ledger, no plaintext audit broadcast).

### Removed

- Deleted the unused `vault.py` (a dead PBKDF2 + Fernet credential vault that mirrored an old pattern). Credentials flow through the SDK's `NeonCredentialVault` / `VaultCipher`; the local reimplementation was never wired in.

## 0.30.0 — 2026-07-07


### Changed — editing a scheduled post no longer silently unschedules it

- **Save keeps a scheduled post scheduled.** Previously, editing a queued post and pressing "Save draft" wrote the edits to the same row but flipped its status back to `draft` — quietly dropping it out of the scheduler's due query, so it never posted. Now, saving an already-scheduled post preserves `status='scheduled'` and re-sends its publish time / recurrence / cease date, so both the edited content and the queue entry persist. On a scheduled post the button reads **"Save changes"** (with a tooltip saying it stays scheduled); on a plain draft it still reads "Save draft". Success reads *"Saved — still scheduled."*

### Added — an explicit way to cancel a scheduled posting

- The Schedule tab now shows an **"Unschedule (keep as draft)"** button for any scheduled post. It clears the schedule (publish time / recurrence / cease date) and returns the post to a plain draft **while preserving your current content**, so nothing is lost and the post reliably leaves the queue. Reschedule anytime from the same tab. When a post is already scheduled, the primary schedule button reads **"Update schedule"** so its effect is unambiguous.

## 0.29.2 — 2026-07-06


### Added — fast-fail + operator alert when the AI provider is unfunded

- Previewing or scheduling a post with a dynamic block no longer waits ~90 seconds to fall back when the operator's Anthropic account is out of credits. `resolve_dynamic_block` now runs a cheap synchronous probe first (a 1-token call — a 400 "credit balance too low" bills nothing) and, on a definitive provider-down result (unfunded or auth), returns "aborted — fee refunded" in ~1 second **with the reason**, instead of handing back a claim check that fails only on a later poll. Transient blips (429/5xx) still fall through to the real attempt.
- When that fast-fail trips, the operator gets a self-DM (operator npub → operator npub, surfaced in Pricing Studio): *"⚡ eXcalibur can't resolve dynamic post blocks — your Anthropic account is out of credits. Add credit at console.anthropic.com."* Best-effort and non-blocking (relay I/O runs off the response path).

## 0.29.1 — 2026-07-01


### Fixed — flagging a selection is no longer a one-shot

- The "Flag for AI" affordance used to vanish on the first stray tap or scroll (the chiclet was pinned to the live browser selection, and a scroll listener plus every empty tap cleared it). Now the selection is CAPTURED and PERSISTS: flag it via a stable bar fixed to the bottom of the screen (shows a preview of what you selected, with a Cancel ×). Scroll, miss a tap, or take your time — it stays until you flag it, dismiss it, make a new selection, or start editing a block.

## 0.29.0 — 2026-07-01


### Changed — a cross-block flag is ONE region / ONE LLM context

- Flagging a selection that spans multiple blocks now creates a single region (parts share a `regionId`) instead of independent per-block flags. Refine sends the joined span as one region with the WHOLE post as context (previously only the block's text), and returns one set of suggestions. Applying a suggestion replaces the entire span as one piece, collapsing the spanned blocks into the revised passage (start head + revision + end tail; middle blocks drop). Blocks are an editing convenience — the reader sees one post. The Flags tab shows one row per region ("spans N blocks"); each spanned block still highlights its part.
- Even single-block refines now use the whole composed post as context, not just the one block.

### Fixed — Flag chiclet no longer hides under Safari's selection popup

- The "Flag for AI" chiclet now appears BELOW the selection (Safari puts its own callout above), so the two no longer stack.

## 0.28.2 — 2026-07-01


### Fixed — flag a selection that spans multiple blocks

- Selecting text across 2+ blocks used to be rejected for flagging (the handler required the whole selection to sit inside one block). The selection is now mapped onto every block it covers — the start block's tail, any whole middle blocks, and the end block's head — and the "Flag for AI" chiclet creates a flag in each. Single-block selections are unchanged. Parts that overlap an existing flag are skipped.

## 0.28.1 — 2026-07-01


### Changed — bigger, always-visible block action bar (was tiny hover-only icons over the text)

- The per-block actions (Edit, Make Dynamic, Flag, Delete, move) were tiny (14px) icons in a hover-only overlay positioned ON the block text — hard to hit (especially on touch, where there is no hover) and they obscured the words. Replaced with an always-visible action bar BELOW each block: touch-sized labelled buttons that never cover the text. Dynamic-block cards get the same treatment (visible Run / Make static / Delete row). Cross-block text selection is unchanged.
- Added a per-block "Flag" button (flags the whole block for AI review) so flagging no longer requires a precise text selection — the floating select-to-flag pill still works for phrases.

## 0.28.0 — 2026-06-30


### Added — long dynamic-block posts defer to the scheduler; the runtime budget reaches the LLM

- **Post Now hands the editor back for long posts.** In `handlePostNow`, if any dynamic block's runtime budget exceeds ~30s, the post is saved **unresolved** as `scheduled` at `now+10s` instead of resolving synchronously in the browser — so the author gets control back immediately. The cron worker resolves the blocks server-side and posts. (Static / short-budget posts still post inline.)
- **The author's runtime budget now drives the LLM call.** `resolve_block`/`build_anthropic_request` gain `timeout_seconds`; the scheduler passes each block's `runtimeLimit`, and the claim-check runner + detached closure thread it too. Previously every resolve was capped at a fixed 210s regardless of the declared budget.
- **Scheduler tick frequency raised to every minute** (`*/10` → `* * * * *`) so a "now+10s" post fires promptly, and the worker's MCP-call timeout raised `60s → 300s` to cover a real resolve.

### Fixed — overlapping cron ticks can no longer double-post

- `process_due_posts` now **atomically claims** each due post (`scheduled → sending`) before doing any work, so two overlapping ticks (far more likely at `*/1`) can never fire the same post twice. A held post is released back to `scheduled`; a `sending` post orphaned by a crashed/timed-out tick is reclaimed after a 20-minute lease (which safely exceeds the longest possible resolve). New `claim_due_post`/`release_claim`; `list_due` includes stale `sending` for reclaim; `mark_attempt` reverts a claimed post. New transient **Sending** status badge in the Posts list.

### Note
This is the pragmatic half of an on-demand long-running-task design (HTTP/TCP wants seconds; these resolves want wall-time). Budgets beyond what the worker can wait on are covered by the planned durable-executor follow-up; until then such a post's tick may time out and reclaim/retry — never double-post.

## 0.27.2 — 2026-06-30


### Changed — the resolve poll loop now follows the backend's cadence (one algorithm)

- `resolveDynamicBlock` used its own client-side backoff (`4s → ×1.6 → 15s`) and **ignored** the `poll_after_seconds` the backend returns. The backend now has the better, budget-aware algorithm (a long first wait sized to the author's declared runtime, then tightening as the deadline nears), so the FE follows that value **verbatim** — seeded from `start.poll_after_seconds` and updated from each `fetch_dynamic_block`'s `poll_after_seconds`. One cadence, owned server-side; no duplicate client backoff to drift.
- Dropped `POLL_START_MS`/`POLL_CEILING_MS`/`POLL_FACTOR`; added a `DEFAULT_POLL_SECONDS = 5` fallback used only if an older server omits the field. The overall client deadline (sized to the budget) is unchanged.

## 0.27.1 — 2026-06-30


### Fixed — Post Now no longer silently drops the Sent record (frontend-only)

- `handlePostNow` recorded a post as Sent after a successful tweet via `create_post`/`update_post`, but a soft-fail there (the tool's `catch_errors` returns `{success:false,…}` rather than throwing) was swallowed: a new post got only a quiet hint, and an **existing** post's `updatePost` result was ignored outright. So the tweet went out while the row silently stayed a draft and the UI still said "Posted." (This is what made the recent scheduler/dpop_token breakage so hard to trace from the browser.)
- Now both branches check the result and, on failure, **surface the `error_code` to the editor's error banner and `debugPush` it** to the debug panel — while still showing the live tweet URL — so an after-send save failure can never again be invisible.

## 0.27.0 — 2026-06-30


### Added — author-declared time budget per dynamic block (ad-valorem ready)

- A dynamic block now carries an optional **time budget** (`runtimeLimit`, seconds, clamped 60–900, default 210). The editor exposes it as a numeric input beside the web-lookup budget on each dynamic-block card.
- `resolve_dynamic_block` gains a top-level `runtime_limit_seconds` parameter. It sets the async job's runtime ceiling **and** is passed as the wheel's new `expected_seconds`, so the claim-check poll cadence trusts it (first poll ≈75% of the budget, then tightens) instead of a steady tick. Because it's a named tool argument, an operator can price it **ad valorem** via a `price_type="percent"` entry keyed to `runtime_limit_seconds` in Pricing Studio — no further code needed.
- The browser resolve loop now scales its client-side timeout to the declared budget (was a flat 5 min), so a long block can finish in Preview/Run.

### Changed — bump `tollbooth-dpyc[nostr,prefect]==0.59.0`

- Picks up `start_async_job(expected_seconds=...)` and the budget-aware `poll_backoff_seconds`.

## 0.26.0 — 2026-06-29


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

## 0.25.1 — 2026-06-29


### Changed — editor surfaces the dynamic-block failure hint

- When a dynamic block can't resolve, the block already falls back to its
  fallback ("oops") text so the post stays publishable; now the editor's error
  line also appends the situation's `next_steps` (e.g. "Please try again later")
  and the `resolveDynamicBlock` wrapper passes the structured `error_code` /
  `transient` through, so future UX can branch on them. Frontend-only.

## 0.25.0 — 2026-06-29


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

## 0.24.2 — 2026-06-29


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

## 0.24.1 — 2026-06-29


### Fixed — dynamic-block resolution now actually runs on detached compute

- Bump `tollbooth-dpyc[nostr,prefect]==0.55.2`, which fixes `PrefectClosureExecutor`
  never authenticating to the operator's standalone Prefect account. Before this,
  `run_deployment` failed on the FastMCP/Horizon front (which sets its own
  `PREFECT_*` env) and the wheel silently fell back to the in-process runner — so
  resolve jobs ran on the recycling front after all (quick ones completed before a
  recycle and masked it). With 0.55.2 the dispatch reaches the detached pool.

## 0.24.0 — 2026-06-29


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

## 0.23.1 — 2026-06-27


### Fixed — Posts list shows a loading state on every filter change

- Switching status tabs (or filters) refetches with MCP cold-start lag, but the
  loading entertainment only showed on the *first* load (`loading && posts.length
  === 0`); a tab switch kept the stale table on screen, so it looked like nothing
  happened and the human click-spammed the tabs. Now the `QuoteScroller` shows on
  any in-flight query, the tabs/refresh are disabled while loading (the clicked
  tab still highlights so the action reads as registered), and the refresh icon
  spins.

## 0.23.0 — 2026-06-27


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

## 0.22.0 — 2026-06-27


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

## 0.21.0 — 2026-06-25


### Fixed — X API 402 now reads as "renew your subscription," and the scheduler stops looping on it

- **Symptom:** a scheduled post whose owner's X developer subscription had lapsed failed every tick with the opaque `x_api_error: X API 402: Unexpected response: 402`, re-firing every ~10 minutes forever (bill → X 402 → refund → leave `scheduled` → repeat). The human was never told what to do.
- **Cause:** `x_client` mapped any non-201/429/401/403 to a generic "Unexpected response," and the scheduler treated a 402 as a transient hold that the next tick would retry. A 402 from X is non-transient — it means the developer plan/tier behind the account's credentials no longer covers the write, and only a human renewing at developer.x.com can clear it.
- **Fix:**
  - `x_client.post_tweet` special-cases 402 with a clear detail instead of "Unexpected response: 402."
  - `_x_api_error_to_response` routes a 402 to the SDK's generic upstream-subscription situation (`tollbooth.upstream_payment.upstream_payment_situation`, `error_code` `upstream_subscription_required`) with renewal advice pointing at the X developer portal — `audience="patron"`, since each patron links their own X account.
  - The scheduler **pauses** a 402'd post (`posts.mark_paused` → `status='paused'`) so `list_due` stops returning it. The owner resumes by patching `status` back to `scheduled` after renewing. This ends the every-tick refire/refund loop.
- Requires `tollbooth-dpyc==0.53.0` (adds the generic upstream-402 handler). 401/403 behavior (re-authorize) is unchanged.

## 0.20.0 — 2026-06-22


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

## 0.19.0 — 2026-06-21


### Added — show the connected X @handle (personalization)

- New free, proof-gated `get_x_profile` tool calls X's `/users/me` with the
  patron's vaulted OAuth token and returns `{connected, username, name,
  profile_image_url}` (`x_client.get_me`).
- FE: the editor tweet-card preview now shows the author's real X **@handle**,
  display name, and avatar (cached per npub via `lib/xProfile.ts`, revalidated on
  open; falls back to the placeholder when X isn't connected). The Profile page's
  X panel shows "Connected · @handle".

## 0.18.0 — 2026-06-21


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

## 0.17.1 — 2026-06-21


### Security — no cross-patron leak in the scheduler log

One worker serves all patrons, so `scheduler_runs` records every patron's
outcomes together. `get_scheduler_log` already owner-scoped the per-post entries,
but it still passed the **global `processed` count** through to every patron — a
cross-patron aggregate. `scheduler_runs.scope_runs` now recomputes `processed` to
the reader's own entry count; a patron's heartbeat is conveyed by `run_at` alone.
The operator still sees every tick in full.

## 0.17.0 — 2026-06-21


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

## 0.16.0 — 2026-06-21


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

## 0.15.0 — 2026-06-21


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

## 0.14.1 — 2026-06-21


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

## 0.14.0 — 2026-06-21


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

## 0.13.0 — 2026-06-20


### Added — every send stamps last_sent_at + stores the tweet URL

- **`last_sent_at` is now stamped on every send.** Transitioning a post to
  `sent` (the FE's Post It, via create or update) stamps `last_sent_at = NOW()`
  server-side; the scheduler already did. So manual and scheduled posts both
  record their fire time.
- **The posted tweet's URL is stored on the post.** New `tweet_url` column
  (idempotent `ADD COLUMN IF NOT EXISTS` for existing tables); `create_post`
  and `update_post` accept it, `mark_sent` persists it (COALESCE-guarded for
  recurrence), and it's returned by `get_post` and `list_posts`.

## 0.12.1 — 2026-06-20


### Fixed — posts can be marked "sent" (Post It now flips the row)

- `create_post` / `update_post` rejected `status="sent"` (`tool_input_invalid`),
  so a successful **Post It** posted to X but the draft never moved to **Sent**.
  `sent` is a valid terminal status (it's in the table contract and the
  scheduler sets it) — added it to the create and patch allow-lists.

## 0.12.0 — 2026-06-20


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

## 0.11.0 — 2026-06-20


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

## 0.10.1 — 2026-06-19


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

## 0.10.0 — 2026-06-19


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

## 0.9.1 — 2026-06-11

- chore: track tollbooth-dpyc through 0.44.15 — SDK audit hardening (correctness fixes for credit-tranche expiration in 0.44.9 and proof-reply handling in 0.44.10; blocking mypy + coverage gates). No wire-API changes.

## 0.9.0 — 2026-05-19


### Changed — sync with tollbooth-dpyc 0.25.0

Picks up the wheel's runtime-name + DRY pass:

- **Identity proofs sign the runtime tool name** (`<slug>_<capability>` —
  e.g. `<slug>_check_balance`). The bare capability seed never crosses the
  server boundary. (wheel 0.24.0)
- **Oracle delegations mount under `<slug>_oracle_*`** — every wire-exposed
  tool on this operator now shares the same slug prefix. (wheel 0.24.1)
- **`register_standard_tools` returns the `@tool` decorator** — the slug
  literal now appears exactly once in this server's bootstrap. (wheel 0.25.0)

## 0.8.0 — 2026-04-13


- security: add proof parameter to all tools with npub
- update debit_or_deny call for Either return type
- chore: pin tollbooth-dpyc>=0.5.0

## 0.7.0 — 2026-04-12


- remove Horizon OAuth — sessions keyed by npub, no fallback code

## 0.6.36 — 2026-04-11


- chore: pin tollbooth-dpyc>=0.4.9 — credential validator fix

## 0.6.35 — 2026-04-11


- chore: pin tollbooth-dpyc>=0.4.8 — ncred fix, courier diagnostics

## 0.6.34 — 2026-04-11


- chore: pin tollbooth-dpyc>=0.4.6
- Add credential_validator: validates btcpay + client_id + client_secret

## 0.6.33 — 2026-04-11


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

## 0.6.31 — 2026-03-29


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

## 0.6.30 — 2026-03-22


- chore: bump version to 0.6.30 for release
- chore: bump tollbooth-dpyc to >=0.1.100 (notarization catalog + remove get_tax_rate)

## 0.6.29 — 2026-03-22


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

## 0.6.28 — 2026-03-14


- chore: bump tollbooth-dpyc to >=0.1.91
- feat: gate set_pricing_model to operator-only (Step 0C)
- feat: wire pricing CRUD tools for operator self-service (#56)
- chore: bump tollbooth-dpyc to >=0.1.83 (#55)

## 0.6.27 — 2026-03-09


- chore: bump tollbooth-dpyc to >=0.1.82, version 0.6.27 (#54)
- chore: bump tollbooth-dpyc to >=0.1.81, version 0.6.26 (#53)

## 0.6.25 — 2026-03-08


- chore: bump version to 0.6.25
- Merge pull request #52 from lonniev/refactor/lookup-cache-path
- refactor: remove redundant dpyc_registry_url config

## 0.6.24 — 2026-03-07


- chore: bump version to 0.6.24
- docs: add instructions block + clarify patron npub in tool docstrings (#51)

## 0.6.23 — 2026-03-07


- Merge pull request #50 from lonniev/feat/invoice-dm-delivery
- feat: wire invoice DM delivery via Secure Courier
- chore: bump version to 0.6.22 (#49)

## 0.6.22 — 2026-03-07


- feat: add EXPIRES column to account statement infographic (#48)

## 0.6.21 — 2026-03-07


- fix: remove legacy royalty payout config and params (#47)
- chore: bump to v0.6.20 for clean deploy (native Twitter media for banners)
- fix: upload banner PNG as native Twitter media instead of PostImg
- fix: use correct PostImg upload endpoint with token
- fix: follow redirects on PostImg upload (301 fix)
- fix: switch PostImg to official API endpoint
- fix: replace svglib+reportlab with PyMuPDF for banner SVG→PNG
- fix: pin svglib<1.6.0 to avoid pycairo C dep on FastMCP Cloud
- chore: force redeploy for v0.6.14 (svglib+reportlab)

## 0.6.14 — 2026-03-06


- Merge pull request #46 from lonniev/fix/svglib-renderer
- fix: replace Playwright with svglib+reportlab for banner SVG→PNG

## 0.6.13 — 2026-03-06


- Merge pull request #45 from lonniev/fix/playwright-renderer
- fix: replace cairosvg with Playwright for banner rendering

## 0.6.12 — 2026-03-06


- Merge pull request #44 from lonniev/fix/banner-svg-only
- fix: simplify banner to SVG-only, make cairosvg a required dep

## 0.6.11 — 2026-03-06


- Merge pull request #43 from lonniev/feat/banner-postimg
- chore: bump version to 0.6.11
- feat: add banner_svg_or_png to post_tweet via PostImages upload

## 0.6.10 — 2026-03-06


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

## 0.6.9 — 2026-03-04


- Merge pull request #37 from lonniev/fix/post-tweet-cost
- fix: set post_tweet cost to 5 api_sats, post_tweet_image to 10
- Merge pull request #36 from lonniev/chore/pin-073
- chore: trigger FastMCP Cloud redeploy for tollbooth-dpyc 0.1.73
- Merge pull request #35 from lonniev/feat/pin-trademark
- chore: pin tollbooth-dpyc>=0.1.72 + trademark notices
- chore: trigger FastMCP Cloud redeploy for tollbooth-dpyc 0.1.70
- feat: auto-restore DPYC identity from vault on cold start (#34)
- chore: trigger FastMCP Cloud redeploy for tollbooth-dpyc 0.1.66

## 0.6.8 — 2026-03-03


- Merge pull request #33 from lonniev/feat/auto-certify-purchase
- feat: auto-certify purchase_credits via server-to-server OAuth

## 0.6.7 — 2026-03-03


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

## 0.6.5 — 2026-03-01


- chore: force redeploy after NSEC-only identity migration
- Merge pull request #26 from lonniev/feat/nsec-only-registry-resolution
- NSEC-only registry resolution: derive authority npub at runtime (v0.6.5)

## 0.6.4 — 2026-03-01


- Merge pull request #25 from lonniev/feat/courier-greeting
- Resolve merge conflict, bump to v0.6.4
- Pass operator greeting to Secure Courier open_channel
- Bump tollbooth-dpyc minimum to >=0.1.49 (scan-all-DMs fix) (#24)
- Bump tollbooth-dpyc minimum to >=0.1.49 (scan-all-DMs fix)

## 0.6.3 — 2026-02-28


- Bump tollbooth-dpyc to >=0.1.48 (NIP-44v2 cipher fix) (#23)

## 0.6.2 — 2026-02-28


- Merge pull request #22 from lonniev/refactor/dry-version
- DRY version: read from importlib.metadata, bump to 0.6.2

## 0.6.1 — 2026-02-28


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

## 0.6.0 — 2026-02-27


- Add service_status tool + bump tollbooth-dpyc to >=0.1.41 (#15)

## 0.5.0 — 2026-02-27


- Release 0.5.0

## Appendix — raw commit log, 0.6.1 → 0.6.27 (2026-02-28 → 2026-03-09)

Kept verbatim, and deliberately last. It was previously headed `## [0.4.2] — 2026-03-09`,
which is neither its version nor a position any reader could follow. Most of it is also
covered by the per-version sections above, but it is the only surviving record of
0.6.15–0.6.20 and 0.6.26, so it is not safe to drop.

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
