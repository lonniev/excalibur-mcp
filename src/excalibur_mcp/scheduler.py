"""Scheduled-post firing.

Walks the due ``scheduled`` posts and publishes each on behalf of its owner:
resolve the owner's vaulted X bearer, bill the owner for ``post_tweet`` (keeping
the tranche-expiry / demurrage guard intact), post, then stamp ``last_sent_at``
and either reschedule from ``recurrence`` or mark the post ``sent`` once past
``cease_at``.

No per-fire npub proof: a scheduled post is the owner's standing consent, and the
entrypoint tool (``process_scheduled_posts``) is operator-gated. Insufficient
balance / unavailable OAuth are **situations, not failures** — the post is left
``scheduled`` and reported, never dropped.

The owner billing reuses the wheel's own pricing + billing path
(``runtime._resolve_pricing`` → ``runtime._apply_billing``), so the scheduler
charges exactly what an interactive ``post_tweet`` would, demurrage and all.
"""

from __future__ import annotations

import asyncio
import calendar
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from excalibur_mcp.db import posts as posts_db
from excalibur_mcp.db import scheduler_runs
from excalibur_mcp.formatter import markdown_to_unicode

logger = logging.getLogger(__name__)


# -- tick budget -------------------------------------------------------------
#
# A tick is one HTTP request, and the edge in front of this origin cuts it — far
# below the 900s a dynamic block is allowed to ask for. An overrunning tick
# doesn't just lose its posts: the connection dies, the server task goes with it,
# nothing is recorded, and every post it had claimed comes back at the next cron
# to overrun again. So the tick works to a wall-clock deadline inside that window
# and hands the remainder to the next tick — 30 minutes away, and strictly better
# than a retry that was always going to be cut off.
#
# The cut is MEASURED, not assumed: two ticks died at 129.7s and 131.2s of Worker
# wall time on 2026-07-25, of which ~2s is connect + whoami, putting the edge's
# ceiling on the POST itself at ~128s. (An earlier revision of this file guessed
# 100s from the proxy's documented default and left ~50s of headroom unused,
# which clipped real dynamic blocks into their fallbacks for no reason.) The
# budget below keeps ~30s of margin under the measured ceiling for the X call,
# the DB writes, and the audit close that follow the last resolve.
TICK_BUDGET_S = 95.0

# Ceiling for a single scheduler-fired dynamic resolve — most of a tick, so one
# block can use nearly the whole budget. An author may still ask for more and get
# it on the interactive path (bounded there at 240s); from the scheduler, a
# budget that can't fit inside a tick is a budget that can't post.
RESOLVE_BUDGET_S = 85.0

# Don't open a post we can't plausibly finish — resolve clamps its own floor at
# 30s, so starting one with less than this left just overruns the deadline.
MIN_POST_BUDGET_S = 40.0

# A 402 is the owner's own X developer subscription lapsing — a billing matter
# at X that no retry can fix, so it pauses.
#
# A 401 does NOT belong here, though it looks like it should. The SDK refreshes
# only when its own `expires_at` says the token is stale, so X rotating a refresh
# token out from under us yields a 401 while our bookkeeping still reads fresh —
# transient, and self-healing on the next refresh. Observed 2026-07-25: a post
# that 401'd at 23:00 posted cleanly an hour later with no human involved.
# Pausing on 401 would have stranded it awaiting a Resume it never needed.
_X_NON_TRANSIENT = frozenset({402})


# -- time / recurrence helpers ----------------------------------------------

def _parse_iso(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _as_dict(value: Any) -> dict[str, Any] | None:
    """Neon may hand JSONB back as a parsed object or a raw string — normalize."""
    if value is None:
        return None
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            return None
    return None


def _add_months(dt: datetime, months: int) -> datetime:
    m = dt.month - 1 + months
    year = dt.year + m // 12
    month = m % 12 + 1
    day = min(dt.day, calendar.monthrange(year, month)[1])
    return dt.replace(year=year, month=month, day=day)


def _add_business_days(dt: datetime, n: int) -> datetime:
    """Advance ``n`` business days (Mon-Fri), skipping Sat/Sun, preserving the
    time of day. Stepping forward from a Friday (or a weekend) lands on the
    next Monday, so a daily-on-weekdays cadence never fires on a weekend."""
    r = dt
    added = 0
    while added < n:
        r = r + timedelta(days=1)
        if r.weekday() < 5:  # Mon=0 .. Fri=4
            added += 1
    return r


def _advance(sent_at: datetime, recurrence: dict[str, Any]) -> datetime | None:
    freq = recurrence.get("freq")
    interval = recurrence.get("interval", 1)
    interval = interval if isinstance(interval, int) and interval >= 1 else 1
    if freq == "daily":
        return sent_at + timedelta(days=interval)
    if freq == "weekdays":
        return _add_business_days(sent_at, interval)
    if freq == "weekly":
        return sent_at + timedelta(weeks=interval)
    if freq == "monthly":
        return _add_months(sent_at, interval)
    return None


def _next_state(
    sent_at: datetime, recurrence: dict[str, Any] | None, cease_at: Any,
) -> tuple[str, datetime | None]:
    """Return ``(next_status, next_publish_at)`` after a successful fire."""
    if not recurrence:
        return "sent", None
    nxt = _advance(sent_at, recurrence)
    if nxt is None:
        return "sent", None
    cease = _parse_iso(cease_at)
    if cease is not None and nxt > cease:
        return "sent", None
    return "scheduled", nxt


# -- dynamic-block resolution ------------------------------------------------

def _dynamic_blocks(doc: dict[str, Any] | None) -> list[dict[str, Any]]:
    """The dynamic blocks in a post's doc (empty for legacy/static posts)."""
    if not isinstance(doc, dict):
        return []
    blocks = doc.get("blocks")
    if not isinstance(blocks, list):
        return []
    return [b for b in blocks if isinstance(b, dict) and b.get("dynamic")]


async def _owner_voice(owner: str) -> tuple[str, list[str]]:
    """The owner's saved Voice (profile + active ban texts) for tone-matching.

    Best-effort: a missing/unreadable Voice just means no voice constraints.
    """
    try:
        from excalibur_mcp.tools import voices as voices_tools

        v = await voices_tools.get(owner)
        voice_obj = (v or {}).get("voice") or {}
        profile = str(voice_obj.get("profile") or "")
        bans = [
            str(b.get("text"))
            for b in (voice_obj.get("bans") or [])
            if isinstance(b, dict) and b.get("on") and b.get("text")
        ]
        return profile, bans
    except Exception:  # noqa: BLE001 — voice is an enhancement, never a blocker
        logger.exception("scheduler: failed to load voice for %s", owner)
        return "", []


def _fallback_reason(exc: Exception, budget_s: float) -> str:
    """Why a dynamic block fell back, in a form worth reading in the audit ring.

    The distinction that matters is whether WE cut it short (our budget) or the
    provider failed — the first is a tuning question we can answer by looking at
    the recorded budget, the second is an outage. Both used to read as an
    identical silence."""
    name = type(exc).__name__
    if "Timeout" in name or isinstance(exc, TimeoutError):
        return f"resolve_timed_out_at_{int(budget_s)}s"
    text = str(exc).lower()
    if "credit balance" in text or "quota" in text:
        return "operator_llm_unfunded"
    if "401" in text or "authentication" in text:
        return "operator_llm_auth"
    if "429" in text or "rate" in text:
        return "upstream_rate_limited"
    return f"resolve_failed:{name}"


def _resolve_timeout(requested: Any, budget_s: float) -> float:
    """The budget a scheduler-fired resolve actually gets.

    The author's ``runtimeLimit`` is a ceiling for the interactive path; here it
    competes with what's left of the tick. Whichever is smallest wins, so a
    900s block can't take the whole tick down with it.
    """
    try:
        want = float(requested) if requested else RESOLVE_BUDGET_S
    except (TypeError, ValueError):
        want = RESOLVE_BUDGET_S
    return max(1.0, min(want, RESOLVE_BUDGET_S, budget_s))


async def _resolve_post_text(
    owner: str,
    blocks: list[dict[str, Any]],
    voice: str,
    bans: list[str],
    api_key: str | None,
    budget_s: float = RESOLVE_BUDGET_S,
) -> tuple[str | None, list[dict[str, Any]] | None, str | None, list[dict[str, Any]]]:
    """Compose the final tweet text by resolving each dynamic block at fire time.

    Returns ``(text, rendered_blocks, None)`` on success, where ``rendered_blocks``
    is a static snapshot (dynamic blocks replaced by their resolved text) for the
    Sent occurrence. Returns ``(None, None, reason)`` when a dynamic block failed
    AND carried no fallback — the caller holds the post and never posts a gap.
    ``api_key`` is None when the operator has no Anthropic key, so every dynamic
    block falls back.
    """
    from excalibur_mcp.resolve import INSERT_MARKER, clamp_fetches, resolve_block

    def _domains(b: dict[str, Any]) -> list[str]:
        raw = b.get("domains")
        if isinstance(raw, list):
            return [str(x).strip() for x in raw if str(x).strip()]
        if isinstance(raw, str):
            return [x.strip() for x in raw.replace(",", "\n").split("\n") if x.strip()]
        return []

    # Static texts known up front; dynamic slots fill in after resolution.
    rendered: list[str] = [
        "" if (isinstance(b, dict) and b.get("dynamic")) else str((b or {}).get("text", ""))
        for b in blocks
    ]

    # Context for a dynamic block: static siblings verbatim + OTHER dynamics as
    # their fallback. Blocks resolve in PARALLEL, so none can see another's
    # resolved value — independence is the trade for not posting at the sum of the
    # per-block times.
    def _context_for(i: int) -> str:
        parts: list[str] = []
        for j, bj in enumerate(blocks):
            if j == i:
                parts.append(INSERT_MARKER)
            elif isinstance(bj, dict) and bj.get("dynamic"):
                parts.append(str(bj.get("fallback", "")).strip())
            else:
                parts.append(rendered[j])
        return "\n\n".join(p for p in parts if p).strip()

    async def _resolve_one(i: int) -> tuple[str | None, dict[str, Any] | None]:
        """``(text, fallback_note)`` for dynamic block i.

        ``text`` is the resolved text, or the block's fallback when the resolve
        didn't produce anything, or None when it failed AND has no fallback (the
        caller then holds the post rather than posting a gap).

        ``fallback_note`` is non-None exactly when the author's prompt did NOT
        make it into the tweet. Substituting fallback text is a real degradation
        of what the author asked for, and it used to leave no trace anywhere but
        a log line — the post was reported as cleanly `posted` while carrying
        different words than intended. The note is what makes that visible."""
        b = blocks[i]
        prompt = str(b.get("text", "")).strip()
        fallback = str(b.get("fallback", "")).strip()
        budget = _resolve_timeout(b.get("runtimeLimit"), budget_s)
        resolved, why = "", None
        if not prompt:
            return (fallback or None), None  # nothing was asked for; not a degradation
        if not api_key:
            why = "no_operator_llm_key"
        else:
            try:
                resolved = await resolve_block(
                    api_key=api_key, prompt=prompt, context=_context_for(i),
                    voice=voice, bans=bans, allowed_domains=_domains(b),
                    max_fetches=clamp_fetches(b.get("maxFetches", 5)),
                    # Author's budget, clamped to what's left of the tick.
                    timeout_seconds=budget,
                )
                if not resolved:
                    why = "empty_resolution"
            except Exception as exc:  # noqa: BLE001 — fall back, report the reason
                logger.warning("scheduler: dynamic resolve failed for %s: %s", owner, exc)
                why = _fallback_reason(exc, budget)
        if resolved:
            return resolved, None
        return (fallback or None), {"block": i, "reason": why, "budget_s": round(budget, 1)}

    dynamic_idx = [
        i for i, b in enumerate(blocks) if isinstance(b, dict) and b.get("dynamic")
    ]
    results = await asyncio.gather(*(_resolve_one(i) for i in dynamic_idx))
    fallbacks: list[dict[str, Any]] = []
    for i, (val, note) in zip(dynamic_idx, results):
        if val is None:
            return None, None, "dynamic_resolve_failed", fallbacks
        if note is not None:
            fallbacks.append(note)
        rendered[i] = val

    text = "\n\n".join(p for p in rendered if p).strip()
    if not text:
        return None, None, "empty_after_resolve", fallbacks

    # Static snapshot: dynamic blocks become plain text of what actually went out.
    rendered_blocks: list[dict[str, Any]] = []
    for i, b in enumerate(blocks):
        if isinstance(b, dict) and b.get("dynamic"):
            rendered_blocks.append({"text": rendered[i], "flags": []})
        elif isinstance(b, dict):
            rendered_blocks.append(b)
        else:
            rendered_blocks.append({"text": str(b), "flags": []})
    return text, rendered_blocks, None, fallbacks


# -- main loop ---------------------------------------------------------------

async def process_due_posts(runtime: Any) -> dict[str, Any]:
    """Fire every due scheduled post; return a per-post outcome summary."""
    from tollbooth.tool_identity import capability_uuid

    from excalibur_mcp.server import _resolve_x_client
    from excalibur_mcp.x_client import XAPIError

    post_tweet_id = capability_uuid("post_tweet")
    resolve_id = capability_uuid("resolve_dynamic_block")
    # Open the audit row FIRST: if the edge cuts this request mid-flight, the row
    # stays ``status: started`` and the log shows a tick that was cut off rather
    # than no tick at all.
    run_id = await scheduler_runs.begin_run()
    deadline = time.monotonic() + TICK_BUDGET_S
    now = datetime.now(timezone.utc)
    due = await posts_db.list_due(now.isoformat())

    posted: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []

    async def _hold(bucket: list[dict[str, Any]], pid: str, owner: str, reason: str, **extra: Any) -> None:
        """Record an attempt the scheduler held back: report it in the summary AND
        stamp the post (when/why) so it visibly shows it was tried — never silently
        sitting ``scheduled``. ``owner`` is carried so the log can be owner-scoped.
        Stamping is best-effort; it can't abort the run."""
        bucket.append({"post_id": pid, "owner": owner, "reason": reason, **extra})
        try:
            await posts_db.mark_attempt(pid, datetime.now(timezone.utc).isoformat(), reason)
        except Exception:  # noqa: BLE001 — stamping is non-critical
            logger.exception("scheduler: failed to stamp attempt on %s", pid)

    async def _pause(bucket: list[dict[str, Any]], pid: str, owner: str, reason: str, **extra: Any) -> None:
        """Like ``_hold``, but for a NON-transient situation the next tick can't
        resolve (e.g. the owner's upstream subscription lapsed). Pauses the post
        so it stops being re-fired every tick; the owner resumes it after fixing
        the upstream cause. Best-effort stamping, same as ``_hold``."""
        bucket.append({"post_id": pid, "owner": owner, "reason": reason, "paused": True, **extra})
        try:
            await posts_db.mark_paused(pid, datetime.now(timezone.utc).isoformat(), reason)
        except Exception:  # noqa: BLE001 — stamping is non-critical
            logger.exception("scheduler: failed to stamp attempt on %s", pid)

    for idx, row in enumerate(due):
        pid = row["post_id"]
        # Out of tick budget: hand the remainder to the next cron UNCLAIMED, so
        # they stay plainly ``scheduled`` instead of being claimed by a tick that
        # is about to be cut off. The first post always gets its turn (the budget
        # starts well above the minimum), so this can never starve the queue.
        left = deadline - time.monotonic()
        if idx and left < MIN_POST_BUDGET_S:
            deferred.extend(
                {"post_id": r["post_id"], "owner": r["npub"], "reason": "tick_budget_exhausted"}
                for r in due[idx:]
            )
            logger.info("scheduler: deferring %d post(s) to the next tick", len(due) - idx)
            break
        # Atomically claim the post (scheduled → sending) before any work, so
        # overlapping cron ticks can never fire the same post twice. The claim is
        # the exclusivity gate; the candidate row from list_due carries the same
        # doc/owner. If another tick already owns it, skip — it'll handle it.
        if await posts_db.claim_due_post(pid) is None:
            continue
        owner = row["npub"]
        doc = _as_dict(row.get("doc"))
        dynamic = _dynamic_blocks(doc)
        text = (row.get("text_cache") or "").strip()
        # The doc snapshotted into a recurring occurrence — replaced below with the
        # rendered (static) doc when the post carried dynamic blocks.
        occurrence_doc: dict[str, Any] = doc or {}

        if not dynamic and not text:  # content reason
            await _hold(skipped, pid, owner, "empty_text_cache")
            continue

        # 1. Resolve the owner's X bearer (no billing yet). — access reason
        client, situation = await _resolve_x_client(owner)
        if client is None:
            code = (situation or {}).get("error_code", "oauth_unavailable")
            await _hold(skipped, pid, owner, code)
            continue

        # 1b. Dynamic blocks: bill the owner once for resolution, run each prompt,
        #     and compose the final text. A failed block falls back to its author
        #     text; a failed block with no fallback holds the post (refunding the
        #     resolve fare) — we never post a gap. The resolve fare is also
        #     refunded if anything downstream holds the post (see refunds below).
        resolve_charged = False
        fallbacks: list[dict[str, Any]] = []
        if dynamic:
            rcost, rdenial = await runtime._resolve_pricing(
                resolve_id, "resolve_dynamic_block", "heavy", {},
            )
            if rdenial is not None:
                await _hold(errors, pid, owner, rdenial.get("error_code", "pricing_unavailable"))
                continue
            rbilling = await runtime._apply_billing(owner, "resolve_dynamic_block", rcost, [])
            if isinstance(rbilling, dict):  # finance reason
                await _hold(skipped, pid, owner, "insufficient_balance_resolve", cost_sats=rcost)
                continue
            resolve_charged = True

            try:
                creds = await runtime.load_credentials(["anthropic_api_key"])
                key = creds.get("anthropic_api_key")
            except Exception:  # noqa: BLE001 — no key → blocks fall back
                key = None
            voice, bans = await _owner_voice(owner)
            rendered, rendered_blocks, reason, fallbacks = await _resolve_post_text(
                owner, list(doc.get("blocks") or []) if doc else [], voice, bans, key,
                budget_s=deadline - time.monotonic(),
            )
            if rendered is None:
                await runtime.rollback_debit(resolve_id, owner)
                await _hold(errors, pid, owner, reason or "dynamic_resolve_failed")
                continue
            text = rendered
            occurrence_doc = {"blocks": rendered_blocks or []}

        # 2. Price + bill the owner for post_tweet (tranche-expiry guard inside).
        cost, denial = await runtime._resolve_pricing(post_tweet_id, "post_tweet", "write", {})
        if denial is not None:
            if resolve_charged:
                await runtime.rollback_debit(resolve_id, owner)
            await _hold(errors, pid, owner, denial.get("error_code", "pricing_unavailable"))
            continue
        billing = await runtime._apply_billing(owner, "post_tweet", cost, [])
        if isinstance(billing, dict):
            # Insufficient / expired balance — leave it scheduled, report it. — finance reason
            if resolve_charged:
                await runtime.rollback_debit(resolve_id, owner)
            await _hold(skipped, pid, owner, "insufficient_balance", cost_sats=cost)
            continue

        # 3. Post. On failure, refund the owner and leave the post scheduled. — network reason
        try:
            result = await client.post_tweet(markdown_to_unicode(text))
        except XAPIError as exc:
            await runtime.rollback_debit(post_tweet_id, owner)
            if resolve_charged:
                await runtime.rollback_debit(resolve_id, owner)
            reason = f"x_api_error: {exc}"
            if getattr(exc, "status_code", None) in _X_NON_TRANSIENT:
                # Non-transient: the owner's X subscription/tier lapsed. Pause so
                # we stop re-firing (and re-billing+refunding) every tick; the FE
                # surfaces the situation and the owner resumes after renewing. —
                # subscription reason
                await _pause(errors, pid, owner, reason)
            else:
                await _hold(errors, pid, owner, reason)
            continue
        except Exception as exc:  # noqa: BLE001 — money path, refund then report
            await runtime.rollback_debit(post_tweet_id, owner)
            if resolve_charged:
                await runtime.rollback_debit(resolve_id, owner)
            await _hold(errors, pid, owner, str(exc))
            continue

        # 4. Stamp the fire and reschedule (or retire past cease_at).
        sent_at = datetime.now(timezone.utc)
        next_status, next_publish = _next_state(
            sent_at, _as_dict(row.get("recurrence")), row.get("cease_at"),
        )
        tweet_url = (result or {}).get("tweet_url") if isinstance(result, dict) else None

        if next_status == "scheduled":
            # Recurring: snapshot THIS occurrence as its own Sent post (with the X
            # URL), then advance the recurring template — so every posting stays
            # visible instead of collapsing into a row that silently reschedules.
            # For a dynamic post the snapshot carries the RESOLVED text + a static
            # rendered doc, so history shows exactly what went out, not the prompt.
            await posts_db.create_sent_occurrence(
                npub=owner, doc=occurrence_doc, text_cache=text,
                tweet_url=tweet_url, sent_at=sent_at.isoformat(), template_id=pid,
                publish_at=str(row.get("publish_at")) if row.get("publish_at") else None,
            )
            await posts_db.mark_sent(
                pid, sent_at.isoformat(), "scheduled",
                next_publish.isoformat() if next_publish else None,
                None,  # the occurrence carries the URL; the template just advances
            )
        else:
            # One-shot: the row itself becomes the Sent record.
            await posts_db.mark_sent(pid, sent_at.isoformat(), "sent", None, tweet_url)

        # `fallbacks` rides along on a SUCCESSFUL post on purpose: the tweet went
        # out, but not with the words the author asked for. Without it the run
        # reads as a clean success and the degradation is invisible.
        posted.append({"post_id": pid, "owner": owner, "next_status": next_status,
                       "tweet_id": (result or {}).get("tweet_id") if isinstance(result, dict) else None,
                       "tweet_url": tweet_url,
                       **({"fallbacks": fallbacks} if fallbacks else {})})

    summary = {"processed": len(due), "posted": posted,
               "skipped": skipped, "errors": errors, "deferred": deferred}
    logger.info(
        "scheduler: processed=%d posted=%d skipped=%d errors=%d deferred=%d",
        len(due), len(posted), len(skipped), len(errors), len(deferred),
    )
    # Close the run row opened at the top. Best-effort: an audit-write failure
    # must never undo the posting work we just did.
    try:
        await scheduler_runs.complete_run(run_id, summary)
    except Exception:  # noqa: BLE001 — audit is non-critical
        logger.exception("scheduler: failed to record run summary")
    return summary
