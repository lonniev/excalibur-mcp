"""Post-metrics snapshot + harvest-job persistence.

Append-only ``post_metrics_snapshot`` rows are the durable time-series of X
``non_public_metrics`` / ``organic_metrics`` captured inside the 30-day window.
``metrics_harvest_job`` is the decaying-cadence work queue the scheduler drains
with dead-letter retry — a missed cadence is permanent data loss, so attempts
are tracked and exhausted jobs land in ``dead`` rather than disappearing.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from excalibur_mcp.db.neon import execute, fetch, fetchrow

logger = logging.getLogger(__name__)

_SNAPSHOT_COLS = (
    "id::text AS snapshot_id, post_id::text AS post_id, tweet_id, npub, "
    "captured_at, t_offset, impressions, likes, replies, reposts, quotes, "
    "bookmarks, url_link_clicks, user_profile_clicks, link_placement, "
    "snippet_ids, voice_id, cadence_key"
)


async def insert_snapshot(
    *,
    post_id: str,
    tweet_id: str,
    npub: str,
    t_offset: int,
    impressions: int | None,
    likes: int | None,
    replies: int | None,
    reposts: int | None,
    quotes: int | None,
    bookmarks: int | None,
    url_link_clicks: int | None,
    user_profile_clicks: int | None,
    link_placement: str | None,
    snippet_ids: list[str] | None,
    voice_id: str | None,
    cadence_key: str | None,
    raw: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Append one metrics snapshot. Never upserts — history is the asset."""
    row = await fetchrow(
        """
        INSERT INTO post_metrics_snapshot
            (post_id, tweet_id, npub, t_offset, impressions, likes, replies,
             reposts, quotes, bookmarks, url_link_clicks, user_profile_clicks,
             link_placement, snippet_ids, voice_id, cadence_key, raw)
        VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                $14::jsonb, $15, $16, $17::jsonb)
        RETURNING id::text AS snapshot_id, captured_at
        """,
        post_id,
        tweet_id,
        npub,
        t_offset,
        impressions,
        likes,
        replies,
        reposts,
        quotes,
        bookmarks,
        url_link_clicks,
        user_profile_clicks,
        link_placement,
        json.dumps(snippet_ids or []),
        voice_id,
        cadence_key,
        json.dumps(raw) if raw is not None else None,
    )
    if not row:
        raise RuntimeError("insert_snapshot: INSERT … RETURNING returned no row")
    return row


async def list_snapshots(npub: str, post_id: str) -> list[dict[str, Any]]:
    """Raw snapshot series for one post, owner-scoped, oldest first."""
    return await fetch(
        f"""
        SELECT {_SNAPSHOT_COLS}
        FROM post_metrics_snapshot
        WHERE npub = $1 AND post_id = $2::uuid
        ORDER BY captured_at ASC, t_offset ASC
        """,
        npub,
        post_id,
    )


async def list_latest_by_post(
    npub: str, *, limit: int = 100
) -> list[dict[str, Any]]:
    """Latest snapshot per post for a patron (corpus performance view)."""
    lim = max(1, min(500, limit))
    return await fetch(
        f"""
        SELECT DISTINCT ON (post_id) {_SNAPSHOT_COLS}
        FROM post_metrics_snapshot
        WHERE npub = $1
        ORDER BY post_id, captured_at DESC
        LIMIT $2
        """,
        npub,
        lim,
    )


async def list_all_for_npub(npub: str) -> list[dict[str, Any]]:
    """Every snapshot for a patron — used for derived cohort stats."""
    return await fetch(
        f"""
        SELECT {_SNAPSHOT_COLS}
        FROM post_metrics_snapshot
        WHERE npub = $1
        ORDER BY captured_at ASC
        """,
        npub,
    )


async def list_t15_impressions(npub: str, *, exclude_post_id: str | None = None) -> list[int]:
    """t+15m impression counts for the patron's corpus (escape-velocity median)."""
    if exclude_post_id:
        rows = await fetch(
            """
            SELECT impressions FROM post_metrics_snapshot
            WHERE npub = $1 AND cadence_key = '15m' AND impressions IS NOT NULL
              AND post_id <> $2::uuid
            ORDER BY captured_at DESC
            LIMIT 50
            """,
            npub,
            exclude_post_id,
        )
    else:
        rows = await fetch(
            """
            SELECT impressions FROM post_metrics_snapshot
            WHERE npub = $1 AND cadence_key = '15m' AND impressions IS NOT NULL
            ORDER BY captured_at DESC
            LIMIT 50
            """,
            npub,
        )
    out: list[int] = []
    for r in rows:
        try:
            out.append(int(r["impressions"]))
        except (TypeError, ValueError, KeyError):
            continue
    return out


async def schedule_jobs(jobs: list[dict[str, Any]]) -> int:
    """Insert harvest jobs for a newly-sent post. Returns rows inserted."""
    if not jobs:
        return 0
    n = 0
    for j in jobs:
        try:
            await execute(
                """
                INSERT INTO metrics_harvest_job
                    (post_id, tweet_id, npub, cadence_key, due_at, sent_at,
                     link_placement, snippet_ids, voice_id, status)
                VALUES ($1::uuid, $2, $3, $4, $5::timestamptz, $6::timestamptz,
                        $7, $8::jsonb, $9, 'pending')
                ON CONFLICT (post_id, cadence_key) DO NOTHING
                """,
                j["post_id"],
                j["tweet_id"],
                j["npub"],
                j["cadence_key"],
                j["due_at"].isoformat() if hasattr(j["due_at"], "isoformat") else j["due_at"],
                j["sent_at"].isoformat() if hasattr(j["sent_at"], "isoformat") else j["sent_at"],
                j.get("link_placement"),
                json.dumps(j.get("snippet_ids") or []),
                j.get("voice_id"),
            )
            n += 1
        except Exception:  # noqa: BLE001 — one bad job must not block the rest
            logger.exception("schedule_jobs: failed for cadence %s", j.get("cadence_key"))
    return n


async def claim_due_jobs(now_iso: str, limit: int = 50) -> list[dict[str, Any]]:
    """Atomically claim due pending (or lease-expired harvesting) jobs.

    Lists candidates, then claims each with a status fence (same pattern as
    ``claim_for_post``) so overlapping ticks cannot double-harvest. A job whose
    harvest claim is older than 15 minutes is presumed orphaned and reclaimable.
    """
    lim = max(1, min(200, limit))
    candidates = await fetch(
        """
        SELECT id::text AS job_id FROM metrics_harvest_job
        WHERE due_at <= $1::timestamptz
          AND (
            status = 'pending'
            OR (status = 'harvesting'
                AND last_attempt_at < NOW() - interval '15 minutes')
          )
          AND attempts < 5
        ORDER BY due_at ASC
        LIMIT $2
        """,
        now_iso,
        lim,
    )
    claimed: list[dict[str, Any]] = []
    for c in candidates:
        jid = c.get("job_id")
        if not jid:
            continue
        row = await fetchrow(
            """
            UPDATE metrics_harvest_job
            SET status = 'harvesting',
                attempts = attempts + 1,
                last_attempt_at = NOW(),
                updated_at = NOW()
            WHERE id = $1::uuid
              AND (
                status = 'pending'
                OR (status = 'harvesting'
                    AND last_attempt_at < NOW() - interval '15 minutes')
              )
              AND attempts < 5
            RETURNING id::text AS job_id, post_id::text AS post_id, tweet_id, npub,
                      cadence_key, due_at, sent_at, link_placement, snippet_ids,
                      voice_id, attempts, status
            """,
            jid,
        )
        if row:
            claimed.append(row)
    return claimed


async def mark_job_done(job_id: str) -> None:
    await execute(
        """
        UPDATE metrics_harvest_job
        SET status = 'done', last_error = NULL, updated_at = NOW()
        WHERE id = $1::uuid
        """,
        job_id,
    )


async def mark_job_failed(
    job_id: str, error: str, *, dead: bool = False
) -> None:
    """Record a failed attempt; ``dead=True`` parks it past the retry budget."""
    status = "dead" if dead else "pending"
    await execute(
        """
        UPDATE metrics_harvest_job
        SET status = $2,
            last_error = $3,
            updated_at = NOW()
        WHERE id = $1::uuid
        """,
        job_id,
        status,
        (error or "")[:500],
    )


async def list_dead_jobs(limit: int = 50) -> list[dict[str, Any]]:
    lim = max(1, min(200, limit))
    return await fetch(
        """
        SELECT id::text AS job_id, post_id::text AS post_id, tweet_id, npub,
               cadence_key, due_at, attempts, last_error, updated_at
        FROM metrics_harvest_job
        WHERE status = 'dead'
        ORDER BY updated_at DESC
        LIMIT $1
        """,
        lim,
    )


async def requeue_dead(job_id: str) -> bool:
    """Operator dead-letter retry: dead → pending with attempts reset."""
    row = await fetchrow(
        """
        UPDATE metrics_harvest_job
        SET status = 'pending', attempts = 0, last_error = NULL, updated_at = NOW()
        WHERE id = $1::uuid AND status = 'dead'
        RETURNING id
        """,
        job_id,
    )
    return row is not None


async def count_pending() -> int:
    row = await fetchrow(
        "SELECT COUNT(*) AS n FROM metrics_harvest_job WHERE status IN ('pending', 'harvesting')"
    )
    return int(row["n"]) if row and row.get("n") is not None else 0
