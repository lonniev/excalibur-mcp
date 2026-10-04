"""Conversation-lead SQL — npub-scoping on every statement, sort whitelist,
filter parameterisation, and the upsert's two invariants: it never writes
``status`` and it aliases its table (``neon._qualify`` would leave a bare
``conversations.score`` unprefixed)."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from excalibur_mcp.db import conversations as db

NPUB = "npub1l94pd4qu4eszrl6ek032ftcnsu3tt9a7xvq2zp7eaxeklp6mrpzssmq8pf"
QID = "11111111-1111-1111-1111-111111111111"
RID = "22222222-2222-2222-2222-222222222222"


class Capture:
    def __init__(self, rows=None, row=None, result=None):
        self.calls: list[tuple[str, tuple]] = []
        self._rows, self._row, self._result = rows or [], row, result or {"rowCount": 1}

    async def fetch(self, q, *a):
        self.calls.append((q, a))
        return self._rows

    async def fetchrow(self, q, *a):
        self.calls.append((q, a))
        return self._row

    async def execute(self, q, *a):
        self.calls.append((q, a))
        return self._result


def _patched(cap: Capture):
    return (
        patch.object(db, "fetch", cap.fetch),
        patch.object(db, "fetchrow", cap.fetchrow),
        patch.object(db, "execute", cap.execute),
    )


@pytest.mark.asyncio
async def test_list_conversations_scopes_sorts_and_pages():
    cap = Capture(row={"n": 7})
    p1, p2, p3 = _patched(cap)
    with p1, p2, p3:
        out = await db.list_conversations(
            NPUB, sort_col="replies", sort_dir="asc", page=2, page_size=10,
        )
    count_q, count_args = cap.calls[0]
    page_q, page_args = cap.calls[1]
    assert "WHERE npub = $1" in count_q and "WHERE npub = $1" in page_q
    assert "ORDER BY reply_count ASC, found_at DESC" in page_q
    assert "LIMIT $2 OFFSET $3" in page_q
    assert page_args == (NPUB, 10, 20)
    assert out == {"conversations": [], "total": 7, "page": 2, "page_size": 10}


@pytest.mark.asyncio
async def test_list_conversations_unknown_sort_falls_back_to_score():
    cap = Capture(row={"n": 0})
    p1, p2, p3 = _patched(cap)
    with p1, p2, p3:
        await db.list_conversations(NPUB, sort_col="npub; DROP TABLE", sort_dir="weird")
    assert "ORDER BY score ASC" in cap.calls[1][0]


@pytest.mark.asyncio
async def test_list_conversations_filters_are_parameterised():
    cap = Capture(row={"n": 0})
    p1, p2, p3 = _patched(cap)
    with p1, p2, p3:
        await db.list_conversations(
            NPUB, query_id=QID, statuses=["new", "seen"], min_score=50,
            search="mcp", date_from="2026-10-01", date_to="2026-10-04T00:00:00Z",
            date_field="posted",
        )
    q, args = cap.calls[1]
    assert "query_id = $2::uuid" in q
    assert "status = ANY($3::text[])" in q
    assert "score >= $4" in q
    assert "(text ~* $5 OR author_username ~* $5)" in q
    assert "posted_at >= $6::date" in q
    assert "posted_at < $7::timestamptz" in q
    assert args[:7] == (NPUB, QID, ["new", "seen"], 50, "mcp", "2026-10-01", "2026-10-04T00:00:00Z")


@pytest.mark.asyncio
async def test_list_conversations_adhoc_only_is_null_query():
    cap = Capture(row={"n": 0})
    p1, p2, p3 = _patched(cap)
    with p1, p2, p3:
        await db.list_conversations(NPUB, adhoc_only=True)
    assert "query_id IS NULL" in cap.calls[1][0]


@pytest.mark.asyncio
async def test_upsert_aliases_table_never_sets_status_and_counts():
    cap = Capture(row={"inserted": True})
    p1, p2, p3 = _patched(cap)
    row = {
        "query_id": QID, "query_text": "mcp", "conversation_id": "c1", "tweet_id": "t1",
        "author_id": "a1", "author_username": "ann", "author_followers": 5,
        "author_location": "Somewhere", "text": "how do I", "posted_at": "2026-10-04T00:00:00Z",
        "reply_count": 2, "like_count": 1, "is_reply": False, "has_media": True,
        "score": 55, "signals": ["need"],
    }
    with p1, p2, p3:
        new, refreshed = await db.upsert_conversations(NPUB, [row, row])
    assert (new, refreshed) == (2, 0)
    q, args = cap.calls[0]
    assert q.startswith("INSERT INTO conversations AS c ")
    assert "conversations." not in q
    assert "ON CONFLICT (npub, conversation_id) DO UPDATE SET" in q
    set_clause = q.split("DO UPDATE SET", 1)[1]
    assert "status" not in set_clause
    assert "GREATEST(c.score, EXCLUDED.score)" in set_clause
    assert "RETURNING (xmax = 0) AS inserted" in q
    assert args[0] == NPUB and args[1] == QID and args[3] == "c1"
    assert args[-1] == json.dumps(["need"])


@pytest.mark.asyncio
async def test_upsert_counts_refreshed_rows():
    cap = Capture(row={"inserted": False})
    p1, p2, p3 = _patched(cap)
    row = {"query_text": "q", "conversation_id": "c", "tweet_id": "t", "author_id": "a",
           "author_username": "u", "text": "x"}
    with p1, p2, p3:
        assert await db.upsert_conversations(NPUB, [row]) == (0, 1)


@pytest.mark.asyncio
async def test_set_status_and_get_are_owner_scoped():
    cap = Capture(row={"id": RID, "status": "seen"})
    p1, p2, p3 = _patched(cap)
    with p1, p2, p3:
        await db.set_status(NPUB, RID, "seen")
        await db.get_conversation(NPUB, RID)
    for q, args in cap.calls:
        assert "npub = $1" in q and args[0] == NPUB
    assert "status_at = NOW()" in cap.calls[0][0]


@pytest.mark.asyncio
async def test_purge_stale_scoped_and_keeps_engaged():
    cap = Capture(result={"rowCount": 4})
    p1, p2, p3 = _patched(cap)
    with p1, p2, p3:
        n = await db.purge_stale(NPUB)
    q, args = cap.calls[0]
    assert n == 4
    assert q.startswith("DELETE FROM conversations WHERE npub = $1")
    assert "NOT (status = ANY($3::text[]))" in q
    assert args == (NPUB, 30, ["engaged"])


@pytest.mark.asyncio
async def test_query_crud_scoped_and_query_change_resets_since_id():
    cap = Capture(row={"id": QID}, rows=[])
    p1, p2, p3 = _patched(cap)
    with p1, p2, p3:
        await db.list_queries(NPUB)
        await db.get_query(NPUB, QID)
        await db.find_query_by_name(NPUB, "Mine")
        await db.create_query(NPUB, name="n", query="q", weights={"need": 1}, safe_defaults=True)
        await db.update_query(NPUB, QID, query="new q")
        await db.update_query(NPUB, QID, weights={})
        await db.mark_query_run(NPUB, QID, since_id="99", posts_read=12)
        await db.delete_query(NPUB, QID)
    for q, args in cap.calls:
        assert "npub = $1" in q or q.startswith("INSERT INTO conversation_queries (npub,"), q
        assert args[0] == NPUB
    create_q, create_args = cap.calls[3]
    assert "$4::jsonb" in create_q and create_args[3] == json.dumps({"need": 1})
    update_q = cap.calls[4][0]
    assert "query = $3" in update_q and "since_id = NULL" in update_q
    assert "since_id = NULL" not in cap.calls[5][0]
    assert "COALESCE($3, since_id)" in cap.calls[6][0]
    detach_q, delete_q = cap.calls[7][0], cap.calls[8][0]
    assert detach_q.startswith("UPDATE conversations SET query_id = NULL")
    assert delete_q.startswith("DELETE FROM conversation_queries")
