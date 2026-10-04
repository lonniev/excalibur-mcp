"""Conversation-lead persistence — npub-scoped SQL over ``conversation_queries``
and ``conversations``.

Every statement carries the owner's npub, so a patron only ever reaches their
own saved queries and leads. Business rules (validation, scoring, X paging)
live in the tool layer and ``conversation_scoring``; these are thin SQL.

Two shapes worth knowing. The upsert addresses the row by ``(npub,
conversation_id)`` and *never* writes ``status``: a re-run refreshes what X
knows about the thread, but what the patron decided about it is theirs. And the
insert aliases its table (``INSERT INTO conversations AS c``) because
``neon._qualify`` rewrites a bare table name only when whitespace follows it —
``conversations.score`` inside ``ON CONFLICT`` would reach Postgres unprefixed.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from excalibur_mcp.db.neon import execute, fetch, fetchrow

logger = logging.getLogger(__name__)

STATUSES: tuple[str, ...] = ("new", "seen", "engaged", "dismissed")
QUERY_LIMIT_PER_NPUB = 50

_QUERY_COLS = (
    "id::text AS id, name, query, weights, safe_defaults, since_id, last_run_at, "
    "last_run_posts_read, created_at, updated_at"
)
_LEAD_COLS = (
    "id::text AS id, query_id::text AS query_id, query_text, conversation_id, tweet_id, "
    "author_id, author_username, author_followers, author_location, text, posted_at, "
    "reply_count, like_count, is_reply, has_media, score, signals, status, found_at, "
    "last_seen_at, status_at, reply_tweet_id, replied_at"
)

# Whitelisted sort keys → column expressions (caller input selects a key only).
_SORT_MAP: dict[str, str] = {
    "score": "score",
    "found": "found_at",
    "seen": "last_seen_at",
    "posted": "posted_at",
    "replies": "reply_count",
    "followers": "author_followers",
}
_DATE_FIELDS: dict[str, str] = {
    "found": "found_at",
    "posted": "posted_at",
}


def _is_instant_bound(value: str) -> bool:
    s = (value or "").strip()
    return "T" in s or " " in s


# ---------------------------------------------------------------------------
# Saved queries
# ---------------------------------------------------------------------------


async def list_queries(npub: str) -> list[dict[str, Any]]:
    return await fetch(
        f"SELECT {_QUERY_COLS} FROM conversation_queries WHERE npub = $1 "
        f"ORDER BY updated_at DESC LIMIT {QUERY_LIMIT_PER_NPUB}",
        npub,
    )


async def count_queries(npub: str) -> int:
    row = await fetchrow(
        "SELECT COUNT(*) AS n FROM conversation_queries WHERE npub = $1", npub,
    )
    return int(row["n"]) if row and row.get("n") is not None else 0


async def get_query(npub: str, query_id: str) -> dict[str, Any] | None:
    return await fetchrow(
        f"SELECT {_QUERY_COLS} FROM conversation_queries "
        f"WHERE npub = $1 AND id = $2::uuid",
        npub, query_id,
    )


async def find_query_by_name(npub: str, name: str) -> dict[str, Any] | None:
    return await fetchrow(
        f"SELECT {_QUERY_COLS} FROM conversation_queries "
        f"WHERE npub = $1 AND lower(name) = lower($2)",
        npub, name,
    )


async def create_query(
    npub: str, *, name: str, query: str, weights: dict[str, int], safe_defaults: bool,
) -> dict[str, Any]:
    row = await fetchrow(
        f"INSERT INTO conversation_queries (npub, name, query, weights, safe_defaults) "
        f"VALUES ($1, $2, $3, $4::jsonb, $5) RETURNING {_QUERY_COLS}",
        npub, name, query, json.dumps(weights), safe_defaults,
    )
    assert row is not None
    return row


async def update_query(
    npub: str,
    query_id: str,
    *,
    name: str | None = None,
    query: str | None = None,
    weights: dict[str, int] | None = None,
    safe_defaults: bool | None = None,
) -> dict[str, Any] | None:
    """Patch the provided fields; a changed query text resets ``since_id``
    (the old watermark belongs to a different question)."""
    sets: list[str] = []
    args: list[Any] = [npub, query_id]
    if name is not None:
        args.append(name)
        sets.append(f"name = ${len(args)}")
    if query is not None:
        args.append(query)
        sets.append(f"query = ${len(args)}")
        sets.append("since_id = NULL")
    if weights is not None:
        args.append(json.dumps(weights))
        sets.append(f"weights = ${len(args)}::jsonb")
    if safe_defaults is not None:
        args.append(safe_defaults)
        sets.append(f"safe_defaults = ${len(args)}")
    if not sets:
        return await get_query(npub, query_id)
    set_clause = ", ".join(sets) + ", updated_at = NOW()"
    return await fetchrow(
        f"UPDATE conversation_queries SET {set_clause} "
        f"WHERE npub = $1 AND id = $2::uuid RETURNING {_QUERY_COLS}",
        *args,
    )


async def mark_query_run(
    npub: str, query_id: str, *, since_id: str | None, posts_read: int,
) -> None:
    await execute(
        "UPDATE conversation_queries SET since_id = COALESCE($3, since_id), "
        "last_run_at = NOW(), last_run_posts_read = $4, updated_at = NOW() "
        "WHERE npub = $1 AND id = $2::uuid",
        npub, query_id, since_id, int(posts_read),
    )


async def delete_query(npub: str, query_id: str) -> bool:
    """Remove a saved query. Its leads stay, detached — a worked list is the
    patron's record, not the query's."""
    await execute(
        "UPDATE conversations SET query_id = NULL WHERE npub = $1 AND query_id = $2::uuid",
        npub, query_id,
    )
    res = await execute(
        "DELETE FROM conversation_queries WHERE npub = $1 AND id = $2::uuid",
        npub, query_id,
    )
    return (res.get("rowCount") or 0) > 0


# ---------------------------------------------------------------------------
# Leads
# ---------------------------------------------------------------------------


async def list_conversations(
    npub: str,
    *,
    query_id: str | None = None,
    adhoc_only: bool = False,
    statuses: list[str] | None = None,
    min_score: int = 0,
    sort_col: str = "score",
    sort_dir: str = "desc",
    page: int = 0,
    page_size: int = 25,
    search: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    date_field: str = "found",
) -> dict[str, Any]:
    """Server-side sorted, offset-paginated, filtered lead list (the
    ``list_snippets`` shape). Returns ``{conversations, total, page, page_size}``."""
    psize = max(1, min(100, page_size))
    pg = max(0, page)
    offset = pg * psize

    sort_expr = _SORT_MAP.get(sort_col, "score")
    row_dir = "DESC" if str(sort_dir).lower() == "desc" else "ASC"
    date_col = _DATE_FIELDS.get(date_field, "found_at")

    params: list[Any] = [npub]
    where = "npub = $1"
    if query_id:
        params.append(query_id)
        where += f" AND query_id = ${len(params)}::uuid"
    elif adhoc_only:
        where += " AND query_id IS NULL"
    if statuses:
        params.append(list(statuses))
        where += f" AND status = ANY(${len(params)}::text[])"
    if min_score > 0:
        params.append(int(min_score))
        where += f" AND score >= ${len(params)}"
    if search:
        params.append(search)
        where += f" AND (text ~* ${len(params)} OR author_username ~* ${len(params)})"
    if date_from:
        params.append(date_from)
        cast = "::timestamptz" if _is_instant_bound(date_from) else "::date"
        where += f" AND {date_col} >= ${len(params)}{cast}"
    if date_to:
        params.append(date_to)
        if _is_instant_bound(date_to):
            where += f" AND {date_col} < ${len(params)}::timestamptz"
        else:
            where += f" AND {date_col} < (${len(params)}::date + interval '1 day')"

    total_row = await fetchrow(
        f"SELECT COUNT(*) AS n FROM conversations WHERE {where}", *params,
    )
    total = int(total_row["n"]) if total_row and total_row.get("n") is not None else 0

    params.append(psize)
    limit_idx = len(params)
    params.append(offset)
    offset_idx = len(params)
    rows = await fetch(
        f"SELECT {_LEAD_COLS} FROM conversations WHERE {where} "
        f"ORDER BY {sort_expr} {row_dir}, found_at DESC "
        f"LIMIT ${limit_idx} OFFSET ${offset_idx}",
        *params,
    )
    return {"conversations": rows, "total": total, "page": pg, "page_size": psize}


async def get_conversation(npub: str, row_id: str) -> dict[str, Any] | None:
    return await fetchrow(
        f"SELECT {_LEAD_COLS} FROM conversations WHERE npub = $1 AND id = $2::uuid",
        npub, row_id,
    )


async def upsert_conversations(
    npub: str, rows: list[dict[str, Any]],
) -> tuple[int, int]:
    """Insert or refresh one row per X conversation. Returns ``(new, refreshed)``.

    Counts and ``last_seen_at`` always refresh. The post itself (text, ids,
    author, score, signals) is replaced only when the new sighting scores
    higher — a better ask in the same thread wins the row. ``status`` and
    ``status_at`` are not in the SET list and never will be.
    """
    inserted = 0
    refreshed = 0
    for r in rows:
        out = await fetchrow(
            "INSERT INTO conversations AS c (npub, query_id, query_text, conversation_id, "
            "tweet_id, author_id, author_username, author_followers, author_location, "
            "text, posted_at, reply_count, like_count, is_reply, has_media, score, signals) "
            "VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11::timestamptz, "
            "$12, $13, $14, $15, $16, $17::jsonb) "
            "ON CONFLICT (npub, conversation_id) DO UPDATE SET "
            "reply_count = EXCLUDED.reply_count, "
            "like_count = EXCLUDED.like_count, "
            "author_followers = EXCLUDED.author_followers, "
            "last_seen_at = NOW(), "
            "query_id = COALESCE(c.query_id, EXCLUDED.query_id), "
            "tweet_id = CASE WHEN EXCLUDED.score > c.score THEN EXCLUDED.tweet_id ELSE c.tweet_id END, "
            "author_id = CASE WHEN EXCLUDED.score > c.score THEN EXCLUDED.author_id ELSE c.author_id END, "
            "author_username = CASE WHEN EXCLUDED.score > c.score THEN EXCLUDED.author_username ELSE c.author_username END, "
            "author_location = CASE WHEN EXCLUDED.score > c.score THEN EXCLUDED.author_location ELSE c.author_location END, "
            "text = CASE WHEN EXCLUDED.score > c.score THEN EXCLUDED.text ELSE c.text END, "
            "posted_at = CASE WHEN EXCLUDED.score > c.score THEN EXCLUDED.posted_at ELSE c.posted_at END, "
            "is_reply = CASE WHEN EXCLUDED.score > c.score THEN EXCLUDED.is_reply ELSE c.is_reply END, "
            "has_media = CASE WHEN EXCLUDED.score > c.score THEN EXCLUDED.has_media ELSE c.has_media END, "
            "signals = CASE WHEN EXCLUDED.score > c.score THEN EXCLUDED.signals ELSE c.signals END, "
            "score = GREATEST(c.score, EXCLUDED.score) "
            "RETURNING (xmax = 0) AS inserted",
            npub, r.get("query_id"), r["query_text"], r["conversation_id"], r["tweet_id"],
            r["author_id"], r["author_username"], r.get("author_followers"),
            r.get("author_location"), r["text"], r.get("posted_at"),
            int(r.get("reply_count") or 0), int(r.get("like_count") or 0),
            bool(r.get("is_reply")), bool(r.get("has_media")), int(r.get("score") or 0),
            json.dumps(list(r.get("signals") or [])),
        )
        if out and out.get("inserted"):
            inserted += 1
        else:
            refreshed += 1
    return inserted, refreshed


async def set_status(npub: str, row_id: str, status: str) -> dict[str, Any] | None:
    return await fetchrow(
        f"UPDATE conversations SET status = $3, status_at = NOW() "
        f"WHERE npub = $1 AND id = $2::uuid RETURNING {_LEAD_COLS}",
        npub, row_id, status,
    )


async def record_reply(npub: str, row_id: str, reply_tweet_id: str) -> dict[str, Any] | None:
    """The patron replied through eXcalibur: remember X's id for the reply and
    mark the lead engaged in the same statement."""
    return await fetchrow(
        f"UPDATE conversations SET reply_tweet_id = $3, replied_at = NOW(), "
        f"status = 'engaged', status_at = NOW() "
        f"WHERE npub = $1 AND id = $2::uuid RETURNING {_LEAD_COLS}",
        npub, row_id, reply_tweet_id,
    )


async def purge_stale(
    npub: str, *, days: int = 30, keep: tuple[str, ...] = ("engaged",),
) -> int:
    """Drop this patron's leads not seen for ``days``, except the statuses in
    ``keep`` — a conversation the patron joined is theirs to close."""
    res = await execute(
        "DELETE FROM conversations WHERE npub = $1 "
        "AND last_seen_at < NOW() - ($2::int * interval '1 day') "
        "AND NOT (status = ANY($3::text[]))",
        npub, int(days), list(keep),
    )
    return int(res.get("rowCount") or 0)
