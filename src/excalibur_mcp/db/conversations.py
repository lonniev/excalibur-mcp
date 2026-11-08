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
    "id::text AS id, query_text, conversation_id, tweet_id, "
    "author_id, author_username, author_followers, author_location, text, posted_at, "
    "reply_count, like_count, is_reply, has_media, score, signals, status, found_at, "
    "last_seen_at, status_at, reply_tweet_id, replied_at"
)
# The saved queries whose runs found a lead (ad hoc runs carry none). Aliased
# ``c`` so it reads from the outer row.
_LEAD_QUERY_IDS = (
    "ARRAY(SELECT DISTINCT r.query_id::text FROM conversation_hits h "
    "JOIN conversation_runs r ON r.id = h.run_id "
    "WHERE h.lead_id = c.id AND r.query_id IS NOT NULL) AS query_ids"
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
    patron's record, not the query's. Its runs become ad hoc runs, which
    ``purge_stale`` retires on their own clock."""
    await execute(
        "UPDATE conversation_runs SET query_id = NULL WHERE npub = $1 AND query_id = $2::uuid",
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
    run_id: str | None = None,
    mark_run_id: str | None = None,
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
    ``list_snippets`` shape). Returns ``{conversations, total, page, page_size}``.

    ``query_id`` narrows to leads any run of that saved query found;
    ``run_id`` to the leads one run found. ``mark_run_id`` adds ``in_run`` to
    each row: whether that run found it."""
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
        where += (
            " AND EXISTS (SELECT 1 FROM conversation_hits h JOIN conversation_runs r "
            f"ON r.id = h.run_id WHERE h.lead_id = c.id AND r.query_id = ${len(params)}::uuid)"
        )
    if run_id:
        params.append(run_id)
        where += (
            " AND EXISTS (SELECT 1 FROM conversation_hits h "
            f"WHERE h.lead_id = c.id AND h.run_id = ${len(params)}::uuid)"
        )
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
        f"SELECT COUNT(*) AS n FROM conversations c WHERE {where}", *params,
    )
    total = int(total_row["n"]) if total_row and total_row.get("n") is not None else 0

    in_run = "FALSE"
    if mark_run_id:
        params.append(mark_run_id)
        in_run = (
            "EXISTS (SELECT 1 FROM conversation_hits h "
            f"WHERE h.lead_id = c.id AND h.run_id = ${len(params)}::uuid)"
        )
    params.append(psize)
    limit_idx = len(params)
    params.append(offset)
    offset_idx = len(params)
    rows = await fetch(
        f"SELECT {_LEAD_COLS}, {_LEAD_QUERY_IDS}, {in_run} AS in_run "
        f"FROM conversations c WHERE {where} "
        f"ORDER BY {sort_expr} {row_dir}, found_at DESC "
        f"LIMIT ${limit_idx} OFFSET ${offset_idx}",
        *params,
    )
    return {"conversations": rows, "total": total, "page": pg, "page_size": psize}


async def get_conversation(npub: str, row_id: str) -> dict[str, Any] | None:
    return await fetchrow(
        f"SELECT {_LEAD_COLS}, {_LEAD_QUERY_IDS} FROM conversations c "
        f"WHERE npub = $1 AND id = $2::uuid",
        npub, row_id,
    )


async def upsert_conversations(
    npub: str, rows: list[dict[str, Any]],
) -> tuple[list[str], int, int]:
    """Insert or refresh one row per X conversation. Returns
    ``(lead_ids, new, refreshed)``; ``lead_ids`` is every row touched.

    Counts and ``last_seen_at`` always refresh. The post itself (text, ids,
    author, score, signals) is replaced only when the new sighting scores
    higher — a better ask in the same thread wins the row. ``status`` and
    ``status_at`` are not in the SET list and never will be.
    """
    lead_ids: list[str] = []
    inserted = 0
    refreshed = 0
    for r in rows:
        out = await fetchrow(
            "INSERT INTO conversations AS c (npub, query_text, conversation_id, "
            "tweet_id, author_id, author_username, author_followers, author_location, "
            "text, posted_at, reply_count, like_count, is_reply, has_media, score, signals) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::timestamptz, "
            "$11, $12, $13, $14, $15, $16::jsonb) "
            "ON CONFLICT (npub, conversation_id) DO UPDATE SET "
            "reply_count = EXCLUDED.reply_count, "
            "like_count = EXCLUDED.like_count, "
            "author_followers = EXCLUDED.author_followers, "
            "last_seen_at = NOW(), "
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
            "RETURNING id::text AS id, (xmax = 0) AS inserted",
            npub, r["query_text"], r["conversation_id"], r["tweet_id"],
            r["author_id"], r["author_username"], r.get("author_followers"),
            r.get("author_location"), r["text"], r.get("posted_at"),
            int(r.get("reply_count") or 0), int(r.get("like_count") or 0),
            bool(r.get("is_reply")), bool(r.get("has_media")), int(r.get("score") or 0),
            json.dumps(list(r.get("signals") or [])),
        )
        if out and out.get("id"):
            lead_ids.append(str(out["id"]))
        if out and out.get("inserted"):
            inserted += 1
        else:
            refreshed += 1
    return lead_ids, inserted, refreshed


async def record_run(
    npub: str, *, query_id: str | None, query_text: str, posts_read: int,
    new_count: int, lead_ids: list[str],
) -> str:
    """Store one search and the leads it found. Returns the run id."""
    run = await fetchrow(
        "INSERT INTO conversation_runs (npub, query_id, query_text, posts_read, new_count) "
        "VALUES ($1, $2::uuid, $3, $4, $5) RETURNING id::text AS id",
        npub, query_id, query_text, int(posts_read), int(new_count),
    )
    assert run is not None
    run_id = str(run["id"])
    if lead_ids:
        # Owner-scoped: only this patron's leads can be attached to the run.
        await execute(
            "INSERT INTO conversation_hits (run_id, lead_id) "
            "SELECT $2::uuid, c.id FROM conversations c "
            "WHERE c.npub = $1 AND c.id = ANY($3::uuid[]) ON CONFLICT DO NOTHING",
            npub, run_id, lead_ids,
        )
    return run_id


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
    # Ad hoc runs are one-off questions; their leads stay while still seen.
    await execute(
        "DELETE FROM conversation_runs WHERE npub = $1 AND query_id IS NULL "
        "AND ran_at < NOW() - ($2::int * interval '1 day')",
        npub, int(days),
    )
    return int(res.get("rowCount") or 0)


async def purge_query(
    npub: str, query_id: str, *, days: int = 7, keep: tuple[str, ...] = ("engaged",),
) -> int:
    """Forget this saved query's leads not seen for ``days`` (X's search
    window), except the statuses in ``keep``. A lead another search also found
    stays for that search. Returns how many leads were deleted outright."""
    gone = await fetch(
        "DELETE FROM conversation_hits h USING conversation_runs r, conversations c "
        "WHERE h.run_id = r.id AND h.lead_id = c.id "
        "AND r.npub = $1 AND r.query_id = $2::uuid AND c.npub = $1 "
        "AND c.last_seen_at < NOW() - ($3::int * interval '1 day') "
        "AND NOT (c.status = ANY($4::text[])) "
        "RETURNING h.lead_id::text AS lead_id",
        npub, query_id, int(days), list(keep),
    )
    lead_ids = sorted({str(r["lead_id"]) for r in gone})
    if not lead_ids:
        return 0
    res = await execute(
        "DELETE FROM conversations c WHERE c.npub = $1 AND c.id = ANY($2::uuid[]) "
        "AND NOT EXISTS (SELECT 1 FROM conversation_hits h WHERE h.lead_id = c.id)",
        npub, lead_ids,
    )
    return int(res.get("rowCount") or 0)
