"""Stored-post persistence — CRUD + scheduler queries.

Low-level, npub-scoped CRUD over the ``posts`` table. Every statement carries
``npub = $1`` so a patron can only ever touch their own posts — there is no
cross-npub read or write at this layer. Business rules (idempotency, billing,
recurrence math) live in the tool/scheduler layers; these functions are
deliberately thin SQL.

``doc`` and ``recurrence`` are JSONB; timestamps are ISO-8601 strings cast to
``timestamptz`` (``None`` → SQL NULL). The Neon HTTP SQL API returns ``rowCount``
(capital C), not ``rowcount``.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from excalibur_mcp.db.neon import execute, fetch, fetchrow

logger = logging.getLogger(__name__)

# Columns returned for a full single-post read.
_FULL_COLS = (
    "id::text AS post_id, npub, status, doc, text_cache, "
    "publish_at, recurrence, cease_at, last_sent_at, tweet_url, "
    "last_attempt_at, last_attempt_reason, "
    "created_at, updated_at"
)

# Whitelisted sort keys → column expressions. Caller input only selects a key,
# so an unknown value falls back to a safe default rather than reaching the
# query as raw SQL (same safety posture as optionality-mcp's journal list).
_SORT_MAP: dict[str, str] = {
    "created": "created_at",
    "updated": "updated_at",
    "status": "status",
    "scheduled": "publish_at",
}

# Patch keys a caller may set on update, mapped to their column cast. Caller
# input only selects a key; the column expression never comes from the caller,
# so an unknown patch key can't reach the query as raw SQL.
_PATCHABLE: dict[str, str] = {
    "doc": "::jsonb",
    "publish_at": "::timestamptz",
    "recurrence": "::jsonb",
    "cease_at": "::timestamptz",
    "status": "",
    "tweet_url": "",
}
_JSON_KEYS = {"doc", "recurrence"}


async def create_post(
    npub: str,
    doc: dict[str, Any],
    text_cache: str | None,
    publish_at: str | None,
    recurrence: dict[str, Any] | None,
    cease_at: str | None,
    status: str,
    client_req_id: str | None,
    tweet_url: str | None = None,
) -> dict[str, Any]:
    """Insert a post; return ``{post_id, status, created_at}``.

    A post created already ``sent`` (the FE's Post It on a brand-new draft)
    stamps ``last_sent_at`` server-side, so every send records its time.
    """
    row = await fetchrow(
        """
        INSERT INTO posts
            (npub, status, doc, text_cache, publish_at, recurrence, cease_at,
             client_req_id, tweet_url, last_sent_at)
        VALUES ($1, $2, $3::jsonb, $4, $5::timestamptz, $6::jsonb, $7::timestamptz,
                $8, $9, CASE WHEN $2 = 'sent' THEN NOW() ELSE NULL END)
        RETURNING id::text AS post_id, status, created_at
        """,
        npub,
        status,
        json.dumps(doc),
        text_cache,
        publish_at,
        json.dumps(recurrence) if recurrence is not None else None,
        cease_at,
        client_req_id or None,
        tweet_url or None,
    )
    if not row:
        raise RuntimeError("create_post: INSERT … RETURNING returned no row")
    return row


async def find_by_req_id(npub: str, client_req_id: str) -> dict[str, Any] | None:
    """Find a live post previously created with this client_req_id (create dedup)."""
    if not client_req_id:
        return None
    return await fetchrow(
        """
        SELECT id::text AS post_id, status, created_at
        FROM posts
        WHERE npub = $1 AND client_req_id = $2 AND status <> 'archived'
        ORDER BY created_at ASC
        LIMIT 1
        """,
        npub,
        client_req_id,
    )


async def get_post(npub: str, post_id: str) -> dict[str, Any] | None:
    """Full post row, scoped to the owner."""
    return await fetchrow(
        f"SELECT {_FULL_COLS} FROM posts WHERE id = $2::uuid AND npub = $1",
        npub,
        post_id,
    )


async def current_req_id(npub: str, post_id: str) -> str | None:
    """The last-applied client_req_id for a post (update idempotency)."""
    row = await fetchrow(
        "SELECT client_req_id FROM posts WHERE id = $2::uuid AND npub = $1",
        npub,
        post_id,
    )
    return (row or {}).get("client_req_id")


async def list_posts(
    npub: str,
    status: str | None = None,
    sort_col: str = "created",
    sort_dir: str = "desc",
    page: int = 0,
    page_size: int = 25,
) -> dict[str, Any]:
    """Server-side sorted, offset-paginated list for the owner.

    Sorting runs in SQL so each page is a slice of the fully-ordered dataset.
    ORDER BY comes from the fixed ``_SORT_MAP`` whitelist; ``created_at DESC``
    is a stable tiebreak. Returns ``{posts:[{post_id,status,excerpt,publish_at,
    updated_at,tweet_url}], total, page, page_size}``.
    """
    psize = max(1, min(100, page_size))
    pg = max(0, page)
    offset = pg * psize

    sort_expr = _SORT_MAP.get(sort_col, "created_at")
    row_dir = "DESC" if str(sort_dir).lower() == "desc" else "ASC"

    params: list[Any] = [npub]
    where = "npub = $1"
    if status:
        params.append(status)
        where += f" AND status = ${len(params)}"

    total_row = await fetchrow(
        f"SELECT COUNT(*) AS n FROM posts WHERE {where}", *params
    )
    total = int(total_row["n"]) if total_row and total_row.get("n") is not None else 0

    params.append(psize)
    limit_idx = len(params)
    params.append(offset)
    offset_idx = len(params)

    rows = await fetch(
        f"""
        SELECT id::text AS post_id, status, left(text_cache, 120) AS excerpt,
               publish_at, updated_at, created_at, tweet_url, last_sent_at,
               last_attempt_at, last_attempt_reason
        FROM posts
        WHERE {where}
        ORDER BY {sort_expr} {row_dir}, created_at DESC
        LIMIT ${limit_idx} OFFSET ${offset_idx}
        """,
        *params,
    )

    posts = [
        {
            "post_id": r["post_id"],
            "status": r["status"],
            "excerpt": r.get("excerpt") or "",
            "publish_at": str(r["publish_at"]) if r.get("publish_at") else None,
            "updated_at": str(r.get("updated_at") or ""),
            "tweet_url": r.get("tweet_url") or None,
            "last_sent_at": str(r["last_sent_at"]) if r.get("last_sent_at") else None,
            "last_attempt_at": str(r["last_attempt_at"]) if r.get("last_attempt_at") else None,
            "last_attempt_reason": r.get("last_attempt_reason") or None,
        }
        for r in rows
    ]
    return {"posts": posts, "total": total, "page": pg, "page_size": psize}


async def update_post(
    npub: str,
    post_id: str,
    patch: dict[str, Any],
    text_cache: Any = None,
    client_req_id: str | None = None,
) -> dict[str, Any] | None:
    """Patch whitelisted fields; return ``{post_id, status, updated_at}``.

    ``text_cache`` is updated only when explicitly provided (``not None``) —
    the FE supplies it alongside a ``doc`` change. ``client_req_id`` is recorded
    as the last-applied request id (update idempotency lives in the tool layer).
    """
    set_parts: list[str] = []
    params: list[Any] = [npub, post_id]

    for key, cast in _PATCHABLE.items():
        if key not in patch:
            continue
        value = patch[key]
        if key in _JSON_KEYS:
            value = json.dumps(value) if value is not None else None
        params.append(value)
        set_parts.append(f"{key} = ${len(params)}{cast}")

    if text_cache is not None:
        params.append(text_cache)
        set_parts.append(f"text_cache = ${len(params)}")

    # Transitioning to "sent" (the FE's Post It) stamps the fire time server-side,
    # so every send records last_sent_at without the caller having to.
    if patch.get("status") == "sent":
        set_parts.append("last_sent_at = NOW()")

    params.append(client_req_id or None)
    set_parts.append(f"client_req_id = ${len(params)}")
    set_parts.append("updated_at = NOW()")

    row = await fetchrow(
        f"""
        UPDATE posts SET {', '.join(set_parts)}
        WHERE id = $2::uuid AND npub = $1
        RETURNING id::text AS post_id, status, updated_at
        """,
        *params,
    )
    return row


async def soft_delete(npub: str, post_id: str) -> dict[str, Any] | None:
    """Archive a post (soft delete); return ``{post_id, status}``."""
    return await fetchrow(
        """
        UPDATE posts SET status = 'archived', updated_at = NOW()
        WHERE id = $2::uuid AND npub = $1
        RETURNING id::text AS post_id, status
        """,
        npub,
        post_id,
    )


async def hard_delete(npub: str, post_id: str) -> bool:
    """Permanently delete a post; return ``True`` if a row was removed."""
    result = await execute(
        "DELETE FROM posts WHERE id = $2::uuid AND npub = $1",
        npub,
        post_id,
    )
    return (result.get("rowCount") or 0) > 0


# -- Scheduler queries (operator-side; not npub-scoped) ----------------------


async def list_due(now_iso: str, limit: int = 100) -> list[dict[str, Any]]:
    """Scheduled posts whose publish_at has arrived, oldest first."""
    lim = max(1, min(500, limit))
    return await fetch(
        f"""
        SELECT {_FULL_COLS} FROM posts
        WHERE status = 'scheduled' AND publish_at IS NOT NULL
          AND publish_at <= $1::timestamptz
        ORDER BY publish_at ASC
        LIMIT $2
        """,
        now_iso,
        lim,
    )


async def mark_sent(
    post_id: str,
    last_sent_at: str,
    next_status: str,
    next_publish_at: str | None,
    tweet_url: str | None = None,
) -> None:
    """Record a fire: stamp last_sent_at, set the next status/publish_at, and
    store the posted tweet's URL (COALESCE keeps a prior URL on recurrence).
    A successful fire clears any prior ``last_attempt_reason`` (the hold is over)."""
    await execute(
        """
        UPDATE posts
        SET last_sent_at         = $2::timestamptz,
            status               = $3,
            publish_at           = $4::timestamptz,
            tweet_url            = COALESCE($5, tweet_url),
            last_attempt_at      = $2::timestamptz,
            last_attempt_reason  = NULL,
            updated_at           = NOW()
        WHERE id = $1::uuid
        """,
        post_id,
        last_sent_at,
        next_status,
        next_publish_at,
        tweet_url or None,
    )


async def mark_attempt(post_id: str, at_iso: str, reason: str) -> None:
    """Stamp a scheduled post the scheduler TRIED to fire but held back.

    Records when and why (the skip/error reason — access/finance/network/content)
    so the post visibly shows it was attempted, and the FE can surface the hold
    instead of the post silently sitting ``scheduled``. The post keeps its
    ``scheduled`` status so the next due tick retries it."""
    await execute(
        """
        UPDATE posts
        SET last_attempt_at     = $2::timestamptz,
            last_attempt_reason = $3,
            updated_at          = NOW()
        WHERE id = $1::uuid
        """,
        post_id,
        at_iso,
        reason,
    )
