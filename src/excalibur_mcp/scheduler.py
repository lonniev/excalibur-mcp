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

import calendar
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from excalibur_mcp.db import posts as posts_db
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


# -- main loop ---------------------------------------------------------------

async def process_due_posts(runtime: Any) -> dict[str, Any]:
    """Fire every due scheduled post; return a per-post outcome summary."""
    from tollbooth.tool_identity import capability_uuid

    from excalibur_mcp.server import _resolve_x_client
    from excalibur_mcp.x_client import XAPIError

    post_tweet_id = capability_uuid("post_tweet")
    now = datetime.now(timezone.utc)
    due = await posts_db.list_due(now.isoformat())

    posted: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    for row in due:
        pid = row["post_id"]
        owner = row["npub"]
        text = (row.get("text_cache") or "").strip()

        if not text:
            skipped.append({"post_id": pid, "reason": "empty_text_cache"})
            continue

        # 1. Resolve the owner's X bearer (no billing yet).
        client, situation = await _resolve_x_client(owner)
        if client is None:
            code = (situation or {}).get("error_code", "oauth_unavailable")
            skipped.append({"post_id": pid, "reason": code})
            continue

        # 2. Price + bill the owner for post_tweet (tranche-expiry guard inside).
        cost, denial = await runtime._resolve_pricing(post_tweet_id, "post_tweet", "write", {})
        if denial is not None:
            errors.append({"post_id": pid, "reason": denial.get("error_code", "pricing_unavailable")})
            continue
        billing = await runtime._apply_billing(owner, "post_tweet", cost, [])
        if isinstance(billing, dict):
            # Insufficient / expired balance — leave it scheduled, report it.
            skipped.append({"post_id": pid, "reason": "insufficient_balance",
                            "cost_sats": cost})
            continue

        # 3. Post. On failure, refund the owner and leave the post scheduled.
        try:
            result = await client.post_tweet(markdown_to_unicode(text))
        except XAPIError as exc:
            await runtime.rollback_debit(post_tweet_id, owner)
            errors.append({"post_id": pid, "reason": f"x_api_error: {exc}"})
            continue
        except Exception as exc:  # noqa: BLE001 — money path, refund then report
            await runtime.rollback_debit(post_tweet_id, owner)
            errors.append({"post_id": pid, "reason": str(exc)})
            continue

        # 4. Stamp the fire and reschedule (or retire past cease_at).
        sent_at = datetime.now(timezone.utc)
        next_status, next_publish = _next_state(
            sent_at, _as_dict(row.get("recurrence")), row.get("cease_at"),
        )
        tweet_url = (result or {}).get("tweet_url") if isinstance(result, dict) else None
        await posts_db.mark_sent(
            pid, sent_at.isoformat(), next_status,
            next_publish.isoformat() if next_publish else None,
            tweet_url,
        )
        posted.append({"post_id": pid, "next_status": next_status,
                       "tweet_id": (result or {}).get("id") if isinstance(result, dict) else None})

    summary = {"processed": len(due), "posted": posted,
               "skipped": skipped, "errors": errors}
    logger.info(
        "scheduler: processed=%d posted=%d skipped=%d errors=%d",
        len(due), len(posted), len(skipped), len(errors),
    )
    return summary
