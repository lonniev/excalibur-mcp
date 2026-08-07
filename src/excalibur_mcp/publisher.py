"""Posting one finished body — the fast half.

A *publisher* takes a body that is ALREADY resolved and carries it to X: bill the
owner, post, record what happened, advance any recurrence, publish the companion
Nostr notes. It never calls an LLM and never branches on whether the post was
dynamic, because by the time it runs that distinction has been erased by
``resolver.py``.

That is what makes it fast. A post is one HTTPS call and two row writes — tens of
milliseconds — where resolution can take minutes. Carrying both under one claim
forced a 45-minute lease over work that is mostly instantaneous, and let a
container recycle kill a publication mid-flight.

It is deliberately ignorant of scheduling. It doesn't know what "due" means, it
never looks for work, and nothing waits on it. The scheduler launches it and
forgets it; the publisher records its own completion on the post row. If it dies
mid-flight the post is simply left claimed, and the claim lease hands it back to
a later tick — no supervisor required.

Money rules are unchanged and stay here, where the work is: charge before the
upstream call, refund whenever the post doesn't go out. Insufficient balance and
unavailable OAuth are **situations, not failures** — the post is left
``scheduled`` and reported, never dropped.
"""

from __future__ import annotations

import calendar
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from tollbooth.llm_route import classify_llm_failure

from excalibur_mcp.db import posts as posts_db
from excalibur_mcp.db import scheduler_runs
from excalibur_mcp.formatter import markdown_to_unicode

logger = logging.getLogger(__name__)

# A 402 is the owner's own X developer subscription lapsing — a billing matter at
# X that no retry can fix, so it pauses.
#
# A 401 does NOT belong here, though it looks like it should. The SDK refreshes
# only when its own `expires_at` says the token is stale, so X rotating a refresh
# token out from under us yields a 401 while our bookkeeping still reads fresh —
# transient, and self-healing on the next refresh. Observed 2026-07-25: a post
# that 401'd at 23:00 posted cleanly an hour later with no human involved.
# Pausing on 401 would have stranded it awaiting a Resume it never needed.
_X_NON_TRANSIENT = frozenset({402})

# Failures where the request was already on the wire, so X may have made the
# tweet even though we never read the reply. A ConnectTimeout/ConnectError is
# deliberately NOT here: nothing was sent, `_post_retrying_connect` already
# retried the one phase that is safe to retry, and a post that never left is
# free to try again on the next tick.
_X_MAYBE_DELIVERED = (
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.RemoteProtocolError,
    httpx.ReadError,
)


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
    slot: datetime | None,
    recurrence: dict[str, Any] | None,
    cease_at: Any,
    *,
    now: datetime | None = None,
) -> tuple[str, datetime | None]:
    """Return ``(next_status, next_publish_at)`` after a successful fire.

    Advances from the SLOT the post was scheduled for, never from the moment it
    happened to succeed. Those differ by however long the tick, the model and X
    took, and using the second compounds that delay into every future occurrence:
    a weekly Sunday-morning post drifts a few minutes each week until it is
    posting Wednesday evening. Observed live on post ``0314fe59``.

    Then it walks the pattern forward until it lands **after now**. A slot missed
    while the post was failing is simply skipped — the next occurrence is the next
    real one, not a backlog of dates already in the past. That also means a post
    recovering from a multi-day outage rejoins its own rhythm instead of firing
    repeatedly to catch up.

    ``slot`` may be ``None`` for a legacy row with no ``publish_at``; the caller
    passes the send time in that case, which is the best anchor available.
    """
    if not recurrence:
        return "sent", None
    if slot is None:
        return "sent", None

    ref = now or datetime.now(timezone.utc)
    cease = _parse_iso(cease_at)

    nxt = _advance(slot, recurrence)
    if nxt is None:
        return "sent", None

    # Skip whole missed occurrences rather than scheduling into the past. Bounded
    # so a malformed recurrence can never spin: a year of daily slots is far more
    # than any real outage, and anything beyond it is a broken pattern, not a gap.
    for _ in range(400):
        if nxt is None or nxt > ref:
            break
        nxt = _advance(nxt, recurrence)
    if nxt is None or nxt <= ref:
        return "sent", None

    if cease is not None and nxt > cease:
        return "sent", None
    return "scheduled", nxt


# -- companion notes ------------------------------------------------

def _fallback_blocks(rendered: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Blocks in THIS firing's render that carry the author's fallback text.

    ``fellBack`` is stamped on the block by ``resolver`` when a dynamic block's
    resolution bought nothing and the authored fallback was substituted. Reading
    it off the render — rather than off the resolve log row — is what makes the
    degradation survive a dead worker, a resumed render, and the gap between the
    resolve tick and the posting tick.
    """
    if not isinstance(rendered, dict):
        return []
    blocks = rendered.get("blocks")
    if not isinstance(blocks, list):
        return []
    return [
        {"block": i, **b["fellBack"]}
        for i, b in enumerate(blocks)
        if isinstance(b, dict) and isinstance(b.get("fellBack"), dict)
    ]


def _nostr_blocks(doc: dict[str, Any] | None) -> list[dict[str, Any]]:
    """The Nostr companion-note blocks in a post's doc (empty for posts without).

    A Nostr block is static copy that never enters the tweet; it is published
    instead as a companion Nostr note carrying the live X URL. Read exactly the
    flagged with ``b.get("nostr")``.
    """
    if not isinstance(doc, dict):
        return []
    blocks = doc.get("blocks")
    if not isinstance(blocks, list):
        return []
    return [b for b in blocks if isinstance(b, dict) and b.get("nostr")]


async def _publish_notes(
    runtime: Any, owner: str, messages: list[str],
) -> dict[str, Any]:
    """Publish each Nostr companion note, billed per note, and report the result.

    Called AFTER the tweet is recorded sent, so a slow relay never delays the sent
    record. There is no proven session at 3am, so this cannot make a tool call: it
    bills explicitly and calls ``publish_note`` directly — the same pattern
    ``publish_one`` uses for ``resolve_dynamic_block`` and ``post_tweet``.

    Money rules mirror the ``post_nostr_message`` tool: charge, publish, and refund
    the fare only when **no** relay accepted the note (a partial publish is a
    success). A pricing denial or insufficient balance SKIPS that note and is
    reported — it never holds or pauses a post whose tweet is already live.
    Returns ``{"published": n, "failed": [{"note": i, "reason": ...}, ...]}``.
    """
    import asyncio

    from tollbooth.tool_identity import capability_uuid

    from excalibur_mcp.nostr_note import publish_note

    nostr_id = capability_uuid("post_nostr_message")
    published = 0
    failed: list[dict[str, Any]] = []
    for i, message in enumerate(messages):
        cost, denial = await runtime._resolve_pricing(
            nostr_id, "post_nostr_message", "write", {},
        )
        if denial is not None:
            failed.append({"note": i, "reason": denial.get("error_code") or "pricing_unavailable"})
            continue
        billing = await runtime._apply_billing(owner, "post_nostr_message", cost, [])
        if isinstance(billing, dict):  # insufficient / expired balance
            failed.append({"note": i, "reason": billing.get("error_code") or "insufficient_balance"})
            continue
        try:
            # Relay I/O is blocking websockets — run it off the event loop the same
            # way server.py calls it.
            result = await asyncio.to_thread(publish_note, message, owner)
        except Exception as exc:  # noqa: BLE001 — money path, refund then report
            await runtime.rollback_debit(nostr_id, owner)
            failed.append({"note": i, "reason": str(exc) or type(exc).__name__})
            continue
        if isinstance(result, dict) and result.get("success"):
            published += 1
        else:
            # No relay accepted (or setup failed) — no reach delivered, refund.
            await runtime.rollback_debit(nostr_id, owner)
            reason = (result or {}).get("error") if isinstance(result, dict) else None
            failed.append({"note": i, "reason": reason or "no_relay_accepted"})
    return {"published": published, "failed": failed}


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
        logger.exception("publisher: failed to load voice for %s", owner)
        return "", []


def _fallback_reason(exc: Exception, budget_s: float) -> str:
    """Why a dynamic block fell back, in a form worth reading in the audit ring.

    The distinction that matters is whether the block ran out of ITS OWN time or
    the provider failed — the first is a budget the author can raise, the second
    is an outage. Both used to read as an identical silence."""
    name = type(exc).__name__
    if "Timeout" in name or isinstance(exc, TimeoutError):
        return f"resolve_timed_out_at_{int(budget_s)}s"
    # Hand the classifier the STATUS whenever the exception carries one. It is
    # the premise of the wheel's bare-402 rule ("a metered LLM provider means
    # exactly one thing: the account is empty"), and that rule was unreachable
    # from here: httpx renders an HTTPStatusError as only the generic
    # "Client error '402 Payment Required' for url …", which holds none of the
    # provider's own wording that _UNFUNDED_NEEDLES matches on. So the message
    # alone matched nothing, and an empty OpenRouter account fell out as the
    # shrug `resolve_failed:HTTPStatusError` — the one cause a fallback most
    # needs to name, because unlike a small runtimeLimit no edit to the post can
    # fix it. Read the status off the response rather than regexing it back out
    # of the rendered string: the structured value is right here.
    # Observed 2026-08-07, after an OpenRouter balance ran dry.
    status = getattr(getattr(exc, "response", None), "status_code", None)
    return (
        classify_llm_failure(status=status, message=str(exc))
        or f"resolve_failed:{name}"
    )


# -- one publication ---------------------------------------------------------

async def publish_one(runtime: Any, post_id: str) -> dict[str, Any]:
    """Carry one claimed post to X and record what happened.

    Returns the outcome dict that is also written to the audit ring, so a
    publication is legible whether you read the job result or the log.
    """
    from tollbooth.tool_identity import capability_uuid

    from excalibur_mcp.server import _resolve_x_client
    from excalibur_mcp.x_client import XAPIError

    post_tweet_id = capability_uuid("post_tweet")

    row = await posts_db.get_claimed(post_id)
    if row is None:
        return await _record({"post_id": post_id, "outcome": "gone"})
    owner = row["npub"]
    # The fencing token for every write we make about this post. `claim_for_post`
    # stamps `last_attempt_at = NOW()` on each claim, so it identifies OUR claim
    # specifically: if a later tick decides we died and re-claims, the stamp moves
    # and our writes stop matching. Captured once, here, rather than re-read later
    # — a value re-read after the theft would be the thief's, not ours.
    claim_stamp = str(row.get("last_attempt_at")) if row.get("last_attempt_at") else None

    def _billing_reason(billing: dict[str, Any], fallback: str) -> str:
        """The reason a billing call refused, as IT stated it.

        ``_apply_billing`` distinguishes a patron who is genuinely short of sats
        from a ledger it could not read — the second returns ``vault_unavailable``
        and charges nothing, and its own comment explains why: *never tell a
        funded patron "insufficient balance"*. Flattening both to
        ``insufficient_balance`` here undid that at the last step, and sent an
        owner with 844 sats to top up their account.
        """
        return str(billing.get("error_code") or fallback)

    async def _hold(reason: str, *, detail: str = "", **extra: Any) -> dict[str, Any]:
        """Leave the post ``scheduled`` for a later tick and say why — the
        situation is stamped on the post so it never sits silently.

        ``reason`` is the machine code a surface switches on; ``detail`` is the
        sentence a human needs. Recording only the first is how five unrelated
        OAuth failures all reached the owner as "X access expired", every one of
        them answered with a reconnect that did nothing."""
        try:
            reason = _stated(reason, post_id)
            await posts_db.mark_attempt(
                post_id, _now().isoformat(), reason, detail or None,
                claim_stamp=claim_stamp,
            )
            # Retry the half that failed. A post-phase hold says nothing about
            # the body — it is finished and already paid for — so the row goes
            # back to the POSTER's queue. `mark_attempt`'s blanket
            # sending → scheduled sent it to the resolver instead, and each
            # re-claim there burned one of five lifetime firing attempts.
            await posts_db.release_to_resolved(post_id, claim_stamp)
        except Exception:  # noqa: BLE001 — stamping is non-critical
            logger.exception("publisher: failed to stamp attempt on %s", post_id)
        return await _record({"post_id": post_id, "owner": owner, "outcome": "held",
                              "reason": _stated(reason, post_id),
                              **({"detail": detail} if detail else {}), **extra})

    async def _pause(reason: str, *, detail: str = "", **extra: Any) -> dict[str, Any]:
        """Like ``_hold``, but for a situation no later tick can resolve. The
        owner fixes the upstream cause and resumes the post themselves."""
        try:
            await posts_db.mark_paused(
                post_id, _now().isoformat(), _stated(reason, post_id), detail or None,
                claim_stamp=claim_stamp,
            )
        except Exception:  # noqa: BLE001 — stamping is non-critical
            logger.exception("publisher: failed to stamp attempt on %s", post_id)
        return await _record({"post_id": post_id, "owner": owner, "outcome": "paused",
                              "reason": _stated(reason, post_id),
                              **({"detail": detail} if detail else {}), **extra})

    # What went out is `render` — this firing's resolved blocks. `doc` is the
    # author's template and is never read for content here (nor written: the
    # publishing path holds no write handle on it at all). Legacy rows resolved
    # before `render` existed carry their rendered text in `doc`, so they fall
    # back to it; nothing else may.
    doc = _as_dict(row.get("doc"))
    rendered = _as_dict(row.get("render")) or doc or {}
    nostr = _nostr_blocks(rendered)
    text = (row.get("text_cache") or "").strip()
    # The doc snapshotted into a recurring occurrence: the rendered blocks, so
    # history shows what was published rather than the prompt behind it.
    occurrence_doc: dict[str, Any] = rendered

    if not text:  # content reason — a body that resolved to nothing
        return await _hold("empty_text_cache")

    # 1. Resolve the owner's X bearer (no billing yet). — access reason
    #
    # The situation arrives carrying its evidence: which of the several very
    # different OAuth failures this was, what the provider actually answered,
    # and — for a grant killed by a renewal whose answer was lost — the moment
    # that happened. Keeping only the code is what made "reconnect X" the
    # standing advice for problems reconnecting could not touch.
    client, situation = await _resolve_x_client(owner)
    if client is None:
        return await _hold(
            (situation or {}).get("error_code") or "oauth_unavailable",
            detail=_situation_detail(situation),
        )

    # The body arrived FINISHED. Resolution is a separate phase now
    # (``resolver.py``): it runs under its own claim, bills per block, persists
    # each block as it completes, and only then marks the row ``resolved``. So
    # this function never calls an LLM, never branches on static-vs-dynamic, and
    # takes milliseconds — which is why it no longer needs to be a long-runner
    # able to outlive its container.
    # Which blocks are about to go out as the author's consolation rather than as
    # the post they asked for. The resolver stamps `fellBack` on the block itself,
    # so this survives a dead worker, a resumed render and the gap between the
    # resolve tick and the posting tick — none of which the resolve log row does.
    #
    # This list was declared here and never filled, so `fallbacks` on a publication
    # could not fire and every degraded send read as a clean one. Four flattened
    # templates posted their fallback line on schedule for days and nothing in the
    # log or the FE could distinguish them from real posts.
    fallbacks: list[dict[str, Any]] = _fallback_blocks(rendered)
    if not text:
        return await _hold("empty_after_resolve")

    # 2. Price + bill the owner for post_tweet (tranche-expiry guard inside).
    cost, denial = await runtime._resolve_pricing(post_tweet_id, "post_tweet", "write", {})
    if denial is not None:
        return await _hold(
            denial.get("error_code") or "pricing_unavailable",
            detail=_situation_detail(denial),
        )
    billing = await runtime._apply_billing(owner, "post_tweet", cost, [])
    if isinstance(billing, dict):
        # Short balance, expired tranche, or an unreadable ledger — leave it
        # scheduled and report which. — finance reason
        return await _hold(
            _billing_reason(billing, "insufficient_balance"),
            detail=_situation_detail(billing),
            stage="post", cost_sats=cost,
        )

    # 4. Take permission to call X, and only then call it.
    #
    # This is the last instruction before the irreversible one, and its answer is
    # the authorization — not a log line. `mark_x_call_started` is a fenced
    # compare-and-set: it writes the evidence recovery will read, and it succeeds
    # only if we still own the claim. So a publisher that stalled in OAuth or
    # billing while a sweep reassigned its row finds zero rows matched and stands
    # down here, rather than posting a second copy of something already sent.
    #
    # An exception is treated exactly like a refusal. If the write's outcome is
    # unknown and we posted anyway, the row would still read `x_call_at IS NULL`
    # and recovery would conclude nothing was sent — which is the 2026-07-30
    # double-post rebuilt out of new parts.
    try:
        cleared = await posts_db.mark_x_call_started(post_id, claim_stamp)
    except Exception as exc:  # noqa: BLE001 — unknown write outcome, never post
        await runtime.rollback_debit(post_tweet_id, owner)
        logger.warning("publisher: could not record the send mark for %s: %s", post_id, exc)
        return await _hold("x_call_mark_unavailable", detail=str(exc) or type(exc).__name__)
    if not cleared:
        # The row is not ours any more. Say so and touch nothing: stamping an
        # attempt here would overwrite the state of whoever owns it now.
        await runtime.rollback_debit(post_tweet_id, owner)
        logger.warning(
            "publisher: claim on %s was taken before the send; standing down", post_id,
        )
        return await _record({
            "post_id": post_id, "owner": owner,
            "outcome": "claim_lost_before_post", "reason": "claim_reassigned_before_send",
        })

    # 5. Post. On failure, refund the owner and leave the post retryable. — network reason
    try:
        result = await client.post_tweet(markdown_to_unicode(text))
    except XAPIError as exc:
        await runtime.rollback_debit(post_tweet_id, owner)
        # `reason` stays a stable, switchable code; X's own words go in `detail`.
        # They used to be concatenated into one string, so a surface could only
        # pattern-match prose — and when x_client substituted a canned sentence
        # for the body, the prose it matched was ours, not X's. An operator
        # asking "what is wrong with this post?" got a sentence written months
        # before their post existed.
        status = getattr(exc, "status_code", None)
        reason = f"x_api_error: {status}" if status else "x_api_error"
        detail = str(getattr(exc, "detail", "") or exc)
        if status in _X_NON_TRANSIENT:
            return await _pause(reason, detail=detail)
        return await _hold(reason, detail=detail)
    except _X_MAYBE_DELIVERED as exc:
        # The request REACHED X and we never saw the answer. `x_client` already
        # refuses to retry these at the HTTP layer — "the tweet may already be
        # live" — but that discipline was undone one level up: holding the post
        # hands it to the next tick, which posts it again.
        #
        # It did exactly that on 2026-07-30. X created tweet …0735014637900 at
        # 20:06:16; the read timed out; the 20:30 tick posted the same thing
        # again as …7064064160148. eXcalibur only ever recorded the second, so
        # the first is live on X with no row anywhere.
        #
        # A hold is the one thing this must never be, because a hold means "safe
        # to try again" and that is precisely what is not known. Pausing costs a
        # delayed post; guessing costs a duplicate public one, and only the human
        # can look at the timeline and say which happened.
        await runtime.rollback_debit(post_tweet_id, owner)
        logger.warning(
            "publisher: post_tweet for %s reached X but never answered (%s); "
            "pausing — a tweet may already be live.",
            post_id, type(exc).__name__,
        )
        return await _pause("x_post_outcome_unknown")
    except Exception as exc:  # noqa: BLE001 — money path, refund then report
        await runtime.rollback_debit(post_tweet_id, owner)
        # An exception can carry an empty message; its type still names it.
        return await _hold(str(exc) or type(exc).__name__)

    # 6. Stamp the fire and reschedule (or retire past cease_at).
    sent_at = _now()
    # Anchored on the SCHEDULED slot, not on `sent_at`. See _next_state: using
    # the success moment compounds every delay into the next occurrence.
    slot = _parse_iso(row.get("publish_at")) or sent_at
    next_status, next_publish = _next_state(
        slot, _as_dict(row.get("recurrence")), row.get("cease_at"), now=sent_at,
    )
    tweet_url = (result or {}).get("tweet_url") if isinstance(result, dict) else None

    # Substitute the live X URL into each Nostr companion note and patch those
    # blocks in the occurrence snapshot — so a recurring firing's history shows the
    # note that actually went out, the same intent as rendered_blocks for dynamic
    # blocks. Every {{tweet_url}} is replaced; a note without the token publishes
    # verbatim. Guarded on tweet_url: a note is never published for an absent URL.
    note_messages: list[str] = []
    if nostr and tweet_url:
        snap_blocks = list(occurrence_doc.get("blocks") or [])
        for i, b in enumerate(snap_blocks):
            if isinstance(b, dict) and b.get("nostr"):
                message = str(b.get("text", "")).replace("{{tweet_url}}", tweet_url)
                note_messages.append(message)
                snap_blocks[i] = {**b, "text": message}
        occurrence_doc = {**occurrence_doc, "blocks": snap_blocks}

    if next_status == "scheduled":
        # Recurring: snapshot THIS occurrence as its own Sent post (with the X
        # URL) AND advance the recurring template — one statement, so every
        # posting stays visible instead of collapsing into a row that silently
        # reschedules, and so the two can never come apart. For a dynamic post the
        # snapshot carries the RESOLVED text + a static rendered doc, so history
        # shows exactly what went out, not the prompt.
        held = await posts_db.record_occurrence_and_advance(
            template_id=post_id, npub=owner, doc=occurrence_doc, text_cache=text,
            tweet_url=tweet_url, sent_at=sent_at.isoformat(),
            occurrence_publish_at=str(row.get("publish_at")) if row.get("publish_at") else None,
            next_publish_at=next_publish.isoformat() if next_publish else None,
            claim_stamp=claim_stamp,
        )
    else:
        # One-shot: the row itself becomes the Sent record.
        held = await posts_db.mark_sent(
            post_id, sent_at.isoformat(), "sent", None, tweet_url,
            claim_stamp=claim_stamp,
        )

    if not held:
        # The tweet is live and we are not the owner of record — another tick
        # re-claimed this post while we worked. Nothing here can un-send a tweet,
        # so the only honest move is to refuse to write over the new owner's state
        # and say plainly that a duplicate is likely already out. Silence here is
        # how the 2026-07-30 double-post went unnoticed for an afternoon.
        logger.error(
            "publisher: posted %s (%s) but the claim had been taken — a duplicate "
            "tweet is likely. Expected claim stamp %s.",
            post_id, tweet_url or "no url", claim_stamp,
        )
        return await _record({
            "post_id": post_id, "owner": owner, "outcome": "posted_claim_lost",
            "tweet_url": tweet_url, "reason": "claim_reassigned_mid_publish",
        })

    # Schedule decaying-cadence metrics harvests. Best-effort and after the row
    # is durable: a harvest miss is recoverable on the next operator sweep, a
    # lost send is not. X drops non_public/organic metrics after 30 days.
    try:
        from excalibur_mcp.metrics_harvest import schedule_after_send

        await schedule_after_send(
            post_id=post_id,
            tweet_id=(result or {}).get("tweet_id") if isinstance(result, dict) else None,
            tweet_url=tweet_url,
            npub=owner,
            sent_at=sent_at,
            doc=occurrence_doc,
            text=text,
            voice_id=owner,
        )
    except Exception:  # noqa: BLE001 — never fail a publication over harvest setup
        logger.exception("publisher: metrics schedule failed for %s", post_id)

    # Publish the Nostr companion notes LAST — the send is already recorded, so a
    # slow relay never delays it and a relay miss never un-sends the live tweet.
    nostr_result = await _publish_notes(runtime, owner, note_messages) if note_messages else None

    # `fallbacks` rides along on a SUCCESSFUL publication on purpose: the tweet
    # went out, but not with the words the author asked for. Without it the run
    # reads as a clean success and the degradation is invisible. `nostr` rides
    # along the same way — a companion note that missed its relays is reported,
    # never a reason to un-send the post.
    return await _record({
        "post_id": post_id, "owner": owner, "outcome": "posted",
        "next_status": next_status,
        "tweet_id": (result or {}).get("tweet_id") if isinstance(result, dict) else None,
        "tweet_url": tweet_url,
        **({"fallbacks": fallbacks} if fallbacks else {}),
        **({"nostr": nostr_result} if nostr_result is not None else {}),
    })


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _situation_detail(situation: dict[str, Any] | None) -> str:
    """The most informative sentence a situation dict carries, or "".

    Prefers ``detail`` — the provider's own words, redacted, set by the wheel
    for the failures that have any — and falls back to ``error``, the recipe's
    prose. Both are safe to store and show; neither ever holds a credential.
    """
    if not isinstance(situation, dict):
        return ""
    return str(situation.get("detail") or situation.get("error") or "").strip()


def _stated(reason: Any, post_id: str) -> str:
    """A held post must always say why. This is the backstop that guarantees it.

    Upstream situations reach us as ``{"error_code": None}`` as readily as with
    the key absent, and ``str(SomeError())`` is legitimately empty — either way a
    caller can hand over a blank reason and the log then shows a post that
    quietly didn't publish, which is the exact failure this service keeps
    relearning. A blank arriving here is a bug at the call site, so it's logged
    as one rather than silently papered over.
    """
    text = str(reason or "").strip()
    if text:
        return text
    logger.warning("publisher: a hold on %s carried no reason — call site bug", post_id)
    return "unreported"


async def _record(outcome: dict[str, Any]) -> dict[str, Any]:
    """Append this publication to the audit ring and hand the outcome back.

    Every exit from ``publish_one`` goes through here, so a publication cannot
    finish without leaving a trace — provided the write lands. On 2026-07-31
    three ticks launched a publisher for the same post and the log showed only
    the launches: the posts were correctly released, but their publication rows
    never appeared, and a tick that dispatched work it never heard back from
    reads exactly like a publisher that died. A single Neon hiccup on this
    INSERT was enough to erase the evidence.

    So the write is retried once, and a loss that survives the retry is logged
    at ERROR rather than swallowed at exception level. The post row's
    ``last_attempt_reason`` / ``last_attempt_detail`` remain the durable record
    either way — they are written before this, by ``_hold``/``_pause``.
    """
    row = {"kind": "publication", **outcome}
    for attempt in (1, 2):
        try:
            await scheduler_runs.record_run(row)
            return outcome
        except Exception:  # noqa: BLE001 — audit must never fail the publication
            if attempt == 1:
                logger.warning(
                    "publisher: audit write for %s failed; retrying once",
                    outcome.get("post_id"),
                )
                continue
            logger.error(  # noqa: TRY400 — the traceback is in the warning above
                "publisher: LOST the audit row for %s (outcome=%s, reason=%s). "
                "The post row still carries the reason; the traffic log will "
                "show a launch with no publication.",
                outcome.get("post_id"), outcome.get("outcome"),
                outcome.get("reason"), exc_info=True,
            )
    return outcome
