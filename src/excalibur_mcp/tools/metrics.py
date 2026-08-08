"""Post-metrics tool handlers — harvest, raw series, derived performance."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from excalibur_mcp.db import metrics as metrics_db
from excalibur_mcp.metrics_harvest import (
    compute_post_performance,
    process_due_harvests,
    render_performance_infographic,
    schedule_after_send,
    tweet_id_from_url,
)

logger = logging.getLogger(__name__)


def _require_uuid(value: str, name: str = "post_id") -> str:
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, AttributeError, TypeError):
        raise ValueError(f"{name} must be a valid UUID")


async def harvest(
    runtime: Any,
    tool_id: str,
    *,
    npub: str,
    requeue_dead_id: str = "",
) -> dict[str, Any]:
    """Operator-only cadence-aware metrics sweep (+ optional dead-letter requeue)."""
    operator = runtime.operator_npub()
    if not npub or npub != operator:
        await runtime.rollback_debit(tool_id, npub)
        return {
            "success": False,
            "error_code": "operator_only",
            "error": "excalibur_harvest_metrics is restricted to the operator npub.",
        }

    requeued = False
    if requeue_dead_id:
        jid = _require_uuid(requeue_dead_id, "requeue_dead_id")
        requeued = await metrics_db.requeue_dead(jid)

    summary = await process_due_harvests(runtime)
    pending = await metrics_db.count_pending()
    dead = await metrics_db.list_dead_jobs(limit=20)
    return {
        "success": True,
        **summary,
        "pending_jobs": pending,
        "dead_letter": dead,
        **({"requeued": requeued, "requeue_dead_id": requeue_dead_id} if requeue_dead_id else {}),
    }


async def get_post_metrics(
    runtime: Any,
    tool_id: str,
    *,
    post_id: str,
    npub: str,
) -> dict[str, Any]:
    """Patron: raw snapshot series for one owned post."""
    pid = _require_uuid(post_id)
    rows = await metrics_db.list_snapshots(npub, pid)
    if not rows:
        # Distinguish "no post" from "no harvest yet" via a posts lookup.
        from excalibur_mcp.db import posts as posts_db

        post = await posts_db.get_post(npub, pid)
        if not post:
            await runtime.rollback_debit(tool_id, npub)
            return {
                "success": False,
                "error_code": "post_not_found",
                "error": f"No post {pid} owned by this npub.",
            }
        return {
            "success": True,
            "post_id": pid,
            "snapshots": [],
            "tweet_url": post.get("tweet_url"),
            "note": "No metrics snapshots yet — harvest runs on a decaying cadence after send.",
        }

    snapshots = [
        {
            "snapshot_id": r.get("snapshot_id"),
            "captured_at": str(r.get("captured_at") or ""),
            "t_offset": r.get("t_offset"),
            "cadence_key": r.get("cadence_key"),
            "impressions": r.get("impressions"),
            "likes": r.get("likes"),
            "replies": r.get("replies"),
            "reposts": r.get("reposts"),
            "quotes": r.get("quotes"),
            "bookmarks": r.get("bookmarks"),
            "url_link_clicks": r.get("url_link_clicks"),
            "user_profile_clicks": r.get("user_profile_clicks"),
            "link_placement": r.get("link_placement"),
            "snippet_ids": r.get("snippet_ids") or [],
            "voice_id": r.get("voice_id"),
            "tweet_id": r.get("tweet_id"),
        }
        for r in rows
    ]
    return {"success": True, "post_id": pid, "snapshots": snapshots}


async def post_performance(
    runtime: Any,
    tool_id: str,
    *,
    npub: str,
) -> dict[str, Any]:
    """Patron: derived reach scores across the harvested corpus."""
    follower_count: int | None = None
    # Best-effort followers for the corpus display card only — breakout ratio
    # is personal-median based (#359) and does not need this. Never fail the
    # tool on an OAuth miss.
    try:
        from excalibur_mcp.server import _resolve_x_client

        client, situation = await _resolve_x_client(npub)
        if client is not None:
            me = await client.get_me_with_metrics()
            fc = me.get("followers_count")
            if fc is not None:
                follower_count = int(fc)
        else:
            logger.info(
                "post_performance: no X client for %s (%s)",
                npub[:16],
                (situation or {}).get("error_code"),
            )
    except Exception:  # noqa: BLE001
        logger.exception("post_performance: follower lookup failed")

    data = await compute_post_performance(npub, follower_count=follower_count)
    return {"success": True, **data}


async def post_performance_infographic(
    runtime: Any,
    tool_id: str,
    *,
    npub: str,
) -> dict[str, Any]:
    """Patron: SVG infographic of derived post performance."""
    perf = await post_performance(runtime, tool_id, npub=npub)
    if not perf.get("success", True) and perf.get("error_code"):
        return perf
    svg = render_performance_infographic(perf)
    return {
        "success": True,
        "svg": svg,
        "corpus": perf.get("corpus"),
        "post_count": (perf.get("corpus") or {}).get("post_count", 0),
    }


async def backfill_schedule_for_sent(
    runtime: Any,
    *,
    npub: str,
    post_id: str,
) -> dict[str, Any]:
    """Schedule harvest jobs for an already-sent post (operator/manual recovery)."""
    from excalibur_mcp.db import posts as posts_db

    pid = _require_uuid(post_id)
    post = await posts_db.get_post(npub, pid)
    if not post:
        return {"success": False, "error_code": "post_not_found"}
    url = post.get("tweet_url")
    tid = tweet_id_from_url(url)
    if not tid:
        return {"success": False, "error_code": "no_tweet_url", "error": "Post has no tweet_url."}
    n = await schedule_after_send(
        post_id=pid,
        tweet_id=tid,
        tweet_url=url,
        npub=npub,
        doc=post.get("doc"),
        text=post.get("text_cache"),
        voice_id=npub,
    )
    return {"success": True, "scheduled": n, "tweet_id": tid}
