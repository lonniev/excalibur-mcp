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
from datetime import datetime, timedelta, timezone
from typing import Any

from excalibur_mcp.db import posts as posts_db
from excalibur_mcp.db import scheduler_runs
from excalibur_mcp.formatter import markdown_to_unicode

logger = logging.getLogger(__name__)


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


def _advance(sent_at: datetime, recurrence: dict[str, Any]) -> datetime | None:
    freq = recurrence.get("freq")
    interval = recurrence.get("interval", 1)
    interval = interval if isinstance(interval, int) and interval >= 1 else 1
    if freq == "daily":
        return sent_at + timedelta(days=interval)
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


async def _resolve_post_text(
    owner: str,
    blocks: list[dict[str, Any]],
    voice: str,
    bans: list[str],
    api_key: str | None,
) -> tuple[str | None, list[dict[str, Any]] | None, str | None]:
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

    async def _resolve_one(i: int) -> str | None:
        """Resolved text for dynamic block i; its fallback on failure; None when
        it failed AND has no fallback (caller then holds the post)."""
        b = blocks[i]
        prompt = str(b.get("text", "")).strip()
        fallback = str(b.get("fallback", "")).strip()
        resolved = ""
        if api_key and prompt:
            try:
                resolved = await resolve_block(
                    api_key=api_key, prompt=prompt, context=_context_for(i),
                    voice=voice, bans=bans, allowed_domains=_domains(b),
                    max_fetches=clamp_fetches(b.get("maxFetches", 5)),
                )
            except Exception as exc:  # noqa: BLE001 — fall back, report via reason
                logger.warning("scheduler: dynamic resolve failed for %s: %s", owner, exc)
                resolved = ""
        if not resolved:
            return fallback or None
        return resolved

    dynamic_idx = [
        i for i, b in enumerate(blocks) if isinstance(b, dict) and b.get("dynamic")
    ]
    results = await asyncio.gather(*(_resolve_one(i) for i in dynamic_idx))
    for i, val in zip(dynamic_idx, results):
        if val is None:
            return None, None, "dynamic_resolve_failed"
        rendered[i] = val

    text = "\n\n".join(p for p in rendered if p).strip()
    if not text:
        return None, None, "empty_after_resolve"

    # Static snapshot: dynamic blocks become plain text of what actually went out.
    rendered_blocks: list[dict[str, Any]] = []
    for i, b in enumerate(blocks):
        if isinstance(b, dict) and b.get("dynamic"):
            rendered_blocks.append({"text": rendered[i], "flags": []})
        elif isinstance(b, dict):
            rendered_blocks.append(b)
        else:
            rendered_blocks.append({"text": str(b), "flags": []})
    return text, rendered_blocks, None


# -- main loop ---------------------------------------------------------------

async def process_due_posts(runtime: Any) -> dict[str, Any]:
    """Fire every due scheduled post; return a per-post outcome summary."""
    from tollbooth.tool_identity import capability_uuid

    from excalibur_mcp.server import _resolve_x_client
    from excalibur_mcp.x_client import XAPIError

    post_tweet_id = capability_uuid("post_tweet")
    resolve_id = capability_uuid("resolve_dynamic_block")
    now = datetime.now(timezone.utc)
    due = await posts_db.list_due(now.isoformat())

    posted: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

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

    for row in due:
        pid = row["post_id"]
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
            rendered, rendered_blocks, reason = await _resolve_post_text(
                owner, list(doc.get("blocks") or []) if doc else [], voice, bans, key,
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
            if getattr(exc, "status_code", None) == 402:
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
                tweet_url=tweet_url, sent_at=sent_at.isoformat(),
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

        posted.append({"post_id": pid, "owner": owner, "next_status": next_status,
                       "tweet_id": (result or {}).get("tweet_id") if isinstance(result, dict) else None,
                       "tweet_url": tweet_url})

    summary = {"processed": len(due), "posted": posted,
               "skipped": skipped, "errors": errors}
    logger.info(
        "scheduler: processed=%d posted=%d skipped=%d errors=%d",
        len(due), len(posted), len(skipped), len(errors),
    )
    # Record the tick for FE visibility. Best-effort: an audit-write failure must
    # never undo the posting work we just did.
    try:
        await scheduler_runs.record_run(summary)
    except Exception:  # noqa: BLE001 — audit is non-critical
        logger.exception("scheduler: failed to record run summary")
    return summary
