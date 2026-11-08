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
RUN = "33333333-3333-3333-3333-333333333333"


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
    assert "FROM conversations c WHERE npub = $1" in count_q
    assert "FROM conversations c WHERE npub = $1" in page_q
    assert "AS query_ids" in page_q and "FALSE AS in_run" in page_q
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
    assert "r.query_id = $2::uuid" in q and "h.lead_id = c.id" in q
    assert "status = ANY($3::text[])" in q
    assert "score >= $4" in q
    assert "(text ~* $5 OR author_username ~* $5)" in q
    assert "posted_at >= $6::date" in q
    assert "posted_at < $7::timestamptz" in q
    assert args[:7] == (NPUB, QID, ["new", "seen"], 50, "mcp", "2026-10-01", "2026-10-04T00:00:00Z")


@pytest.mark.asyncio
async def test_list_conversations_by_run_and_marked_run():
    cap = Capture(row={"n": 0})
    p1, p2, p3 = _patched(cap)
    with p1, p2, p3:
        await db.list_conversations(NPUB, run_id=RUN, mark_run_id=RUN, page_size=5)
    count_q, count_args = cap.calls[0]
    page_q, page_args = cap.calls[1]
    assert "h.run_id = $2::uuid" in count_q and count_args == (NPUB, RUN)
    assert "h.run_id = $3::uuid) AS in_run" in page_q
    assert page_args == (NPUB, RUN, RUN, 5, 0)


@pytest.mark.asyncio
async def test_upsert_aliases_table_never_sets_status_and_counts():
    cap = Capture(row={"id": RID, "inserted": True})
    p1, p2, p3 = _patched(cap)
    row = {
        "query_text": "mcp", "conversation_id": "c1", "tweet_id": "t1",
        "author_id": "a1", "author_username": "ann", "author_followers": 5,
        "author_location": "Somewhere", "text": "how do I", "posted_at": "2026-10-04T00:00:00Z",
        "reply_count": 2, "like_count": 1, "is_reply": False, "has_media": True,
        "score": 55, "signals": ["need"],
    }
    with p1, p2, p3:
        ids, new, refreshed = await db.upsert_conversations(NPUB, [row, row])
    assert (ids, new, refreshed) == ([RID, RID], 2, 0)
    q, args = cap.calls[0]
    assert q.startswith("INSERT INTO conversations AS c ")
    assert "conversations." not in q
    assert "ON CONFLICT (npub, conversation_id) DO UPDATE SET" in q
    set_clause = q.split("DO UPDATE SET", 1)[1]
    assert "status" not in set_clause
    assert "GREATEST(c.score, EXCLUDED.score)" in set_clause
    assert "query_id" not in q
    assert "RETURNING id::text AS id, (xmax = 0) AS inserted" in q
    assert args[0] == NPUB and args[1] == "mcp" and args[2] == "c1"
    assert args[-1] == json.dumps(["need"])


@pytest.mark.asyncio
async def test_upsert_counts_refreshed_rows():
    cap = Capture(row={"inserted": False})
    p1, p2, p3 = _patched(cap)
    row = {"query_text": "q", "conversation_id": "c", "tweet_id": "t", "author_id": "a",
           "author_username": "u", "text": "x"}
    with p1, p2, p3:
        assert await db.upsert_conversations(NPUB, [row]) == ([], 0, 1)


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
    runs_q, runs_args = cap.calls[1]
    assert runs_q.startswith("DELETE FROM conversation_runs WHERE npub = $1 AND query_id IS NULL")
    assert runs_args == (NPUB, 30)


@pytest.mark.asyncio
async def test_record_run_scopes_hits_to_the_owner():
    cap = Capture(row={"id": RUN})
    p1, p2, p3 = _patched(cap)
    with p1, p2, p3:
        run_id = await db.record_run(
            NPUB, query_id=None, query_text="mcp", posts_read=40, new_count=2, lead_ids=[RID],
        )
    assert run_id == RUN
    run_q, run_args = cap.calls[0]
    assert run_q.startswith("INSERT INTO conversation_runs (npub, query_id,")
    assert run_args == (NPUB, None, "mcp", 40, 2)
    hits_q, hits_args = cap.calls[1]
    assert "WHERE c.npub = $1 AND c.id = ANY($3::uuid[])" in hits_q
    assert hits_args == (NPUB, RUN, [RID])


@pytest.mark.asyncio
async def test_record_run_with_no_leads_writes_no_hits():
    cap = Capture(row={"id": RUN})
    p1, p2, p3 = _patched(cap)
    with p1, p2, p3:
        await db.record_run(NPUB, query_id=QID, query_text="q", posts_read=0, new_count=0, lead_ids=[])
    assert len(cap.calls) == 1


@pytest.mark.asyncio
async def test_purge_query_detaches_then_deletes_only_orphans():
    cap = Capture(rows=[{"lead_id": RID}, {"lead_id": RID}], result={"rowCount": 1})
    p1, p2, p3 = _patched(cap)
    with p1, p2, p3:
        n = await db.purge_query(NPUB, QID)
    assert n == 1
    hits_q, hits_args = cap.calls[0]
    assert hits_q.startswith("DELETE FROM conversation_hits h USING")
    assert "r.npub = $1 AND r.query_id = $2::uuid AND c.npub = $1" in hits_q
    assert hits_args == (NPUB, QID, 7, ["engaged"])
    lead_q, lead_args = cap.calls[1]
    assert "NOT EXISTS (SELECT 1 FROM conversation_hits h WHERE h.lead_id = c.id)" in lead_q
    assert lead_args == (NPUB, [RID])


@pytest.mark.asyncio
async def test_purge_query_with_nothing_stale_deletes_nothing():
    cap = Capture(rows=[])
    p1, p2, p3 = _patched(cap)
    with p1, p2, p3:
        assert await db.purge_query(NPUB, QID) == 0
    assert len(cap.calls) == 1


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
    assert detach_q.startswith("UPDATE conversation_runs SET query_id = NULL")
    assert delete_q.startswith("DELETE FROM conversation_queries")


@pytest.mark.asyncio
async def test_record_reply_sets_engaged_and_reply_in_one_statement():
    cap = Capture(row={"id": RID, "status": "engaged"})
    p1, p2, p3 = _patched(cap)
    with p1, p2, p3:
        await db.record_reply(NPUB, RID, "999")
    q, args = cap.calls[0]
    assert q.startswith("UPDATE conversations SET reply_tweet_id = $3, replied_at = NOW(), status = 'engaged'")
    assert "WHERE npub = $1 AND id = $2::uuid" in q
    assert args == (NPUB, RID, "999")
