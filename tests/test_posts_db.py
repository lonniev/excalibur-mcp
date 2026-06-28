"""Low-level posts SQL tests — cursor codec, npub-scoping, dynamic update.

The Neon layer (``execute``/``fetch``/``fetchrow``) is faked so we can assert on
the SQL and params the CRUD functions build — every statement must be
npub-scoped, and ``update_post`` must only touch the patched columns.
"""

import json
from unittest.mock import AsyncMock, patch

import pytest

from excalibur_mcp.db import posts as posts_db

NPUB = "npub1l94pd4qu4eszrl6ek032ftcnsu3tt9a7xvq2zp7eaxeklp6mrpzssmq8pf"
PID = "11111111-1111-1111-1111-111111111111"


@pytest.mark.asyncio
async def test_create_post_serializes_json_and_scopes_npub():
    captured = {}

    async def fake_fetchrow(query, *args):
        captured["query"] = query
        captured["args"] = args
        return {"post_id": PID, "status": "draft", "created_at": "2026-06-19T00:00:00+00:00"}

    with patch.object(posts_db, "fetchrow", fake_fetchrow):
        await posts_db.create_post(
            npub=NPUB, doc={"blocks": [1]}, text_cache="hi", publish_at=None,
            recurrence=None, cease_at=None, status="draft", client_req_id=None,
        )
    assert "INSERT INTO posts" in captured["query"]
    # Column order: npub, status, title, doc, text_cache, publish_at, recurrence, …
    # doc is json-encoded; recurrence None stays None (not the string "null")
    assert captured["args"][0] == NPUB
    assert captured["args"][2] is None  # title omitted → NULL
    assert json.loads(captured["args"][3]) == {"blocks": [1]}
    assert captured["args"][6] is None  # recurrence


@pytest.mark.asyncio
async def test_update_post_sets_only_patched_columns():
    captured = {}

    async def fake_fetchrow(query, *args):
        captured["query"] = query
        captured["args"] = args
        return {"post_id": PID, "status": "scheduled", "updated_at": "2026-06-19T01:00:00+00:00"}

    with patch.object(posts_db, "fetchrow", fake_fetchrow):
        await posts_db.update_post(
            NPUB, PID, {"status": "scheduled"}, text_cache="composed", client_req_id="r1",
        )
    q = captured["query"]
    assert "status = $3" in q
    assert "doc" not in q  # not patched → not in SET
    assert "text_cache = $4" in q
    assert "client_req_id = $5" in q
    assert "updated_at = NOW()" in q
    assert "WHERE id = $2::uuid AND npub = $1" in q
    assert "last_sent_at" not in q  # not sent → no fire stamp


@pytest.mark.asyncio
async def test_update_post_to_sent_stamps_last_sent_at_and_stores_tweet_url():
    captured = {}

    async def fake_fetchrow(query, *args):
        captured["query"] = query
        captured["args"] = args
        return {"post_id": PID, "status": "sent", "updated_at": "2026-06-21T03:20:00+00:00"}

    with patch.object(posts_db, "fetchrow", fake_fetchrow):
        await posts_db.update_post(
            NPUB, PID, {"status": "sent", "tweet_url": "https://x.com/i/status/123"},
            text_cache="composed", client_req_id="r2",
        )
    q = captured["query"]
    assert "last_sent_at = NOW()" in q  # transitioning to sent stamps the fire
    assert "tweet_url = $" in q  # url persisted as a patched column
    assert "https://x.com/i/status/123" in captured["args"]


@pytest.mark.asyncio
async def test_mark_sent_persists_tweet_url():
    captured = {}

    async def fake_execute(query, *args):
        captured["query"] = query
        captured["args"] = args
        return {"rowCount": 1}

    with patch.object(posts_db, "execute", fake_execute):
        await posts_db.mark_sent(
            PID, "2026-06-21T03:20:00+00:00", "sent", None,
            "https://x.com/i/status/456",
        )
    assert "tweet_url            = COALESCE($5, tweet_url)" in captured["query"]
    assert "https://x.com/i/status/456" in captured["args"]
    # a successful fire clears any prior held-attempt reason
    assert "last_attempt_reason  = NULL" in captured["query"]


@pytest.mark.asyncio
async def test_mark_attempt_stamps_reason_and_time():
    captured = {}

    async def fake_execute(query, *args):
        captured["query"] = query
        captured["args"] = args
        return {"rowCount": 1}

    with patch.object(posts_db, "execute", fake_execute):
        await posts_db.mark_attempt(PID, "2026-06-21T20:00:00+00:00", "insufficient_balance")
    q = captured["query"]
    assert "last_attempt_at     = $2::timestamptz" in q
    assert "last_attempt_reason = $3" in q
    assert "WHERE id = $1::uuid" in q
    assert captured["args"] == (PID, "2026-06-21T20:00:00+00:00", "insufficient_balance")


@pytest.mark.asyncio
async def test_list_posts_offset_sort_and_total():
    captured = {}

    async def fake_fetchrow(query, *args):  # COUNT(*)
        captured["count_query"] = query
        captured["count_args"] = args
        return {"n": 7}

    async def fake_fetch(query, *args):  # paged rows
        captured["query"] = query
        captured["args"] = args
        return [
            {"post_id": "id0", "status": "scheduled", "excerpt": "e0",
             "publish_at": None, "updated_at": "t", "created_at": "c", "tweet_url": None,
             "last_sent_at": "2026-06-21T14:39:00+00:00",
             "last_attempt_at": "2026-06-21T20:00:00+00:00",
             "last_attempt_reason": "insufficient_balance"},
        ]

    with patch.object(posts_db, "fetchrow", fake_fetchrow), \
         patch.object(posts_db, "fetch", fake_fetch):
        out = await posts_db.list_posts(
            NPUB, status="draft", sort_col="updated", sort_dir="asc",
            page=2, page_size=5,
        )
    q = captured["query"]
    assert "ORDER BY updated_at ASC, created_at DESC" in q
    assert "LIMIT $3 OFFSET $4" in q
    assert captured["args"][0] == NPUB
    assert captured["args"][1] == "draft"
    assert captured["args"][2] == 5  # page_size
    assert captured["args"][3] == 10  # page 2 * size 5
    assert "last_sent_at" in q
    assert "last_attempt_at, last_attempt_reason" in q
    assert out["total"] == 7
    assert out["page"] == 2 and out["page_size"] == 5
    assert out["posts"][0]["excerpt"] == "e0"
    assert out["posts"][0]["last_sent_at"] == "2026-06-21T14:39:00+00:00"
    assert out["posts"][0]["last_attempt_reason"] == "insufficient_balance"
    assert out["posts"][0]["last_attempt_at"] == "2026-06-21T20:00:00+00:00"


@pytest.mark.asyncio
async def test_list_posts_search_and_date_filter_build_where():
    captured = {}

    async def fake_fetchrow(query, *args):  # COUNT(*)
        captured["count_query"] = query
        captured["count_args"] = args
        return {"n": 3}

    async def fake_fetch(query, *args):
        captured["query"] = query
        captured["args"] = args
        return []

    with patch.object(posts_db, "fetchrow", fake_fetchrow), \
         patch.object(posts_db, "fetch", fake_fetch):
        await posts_db.list_posts(
            NPUB, search="hel+o", date_from="2026-06-01", date_to="2026-06-30",
            date_field="scheduled", page=0, page_size=10,
        )
    q = captured["query"]
    assert "text_cache ~* $2" in q  # regex content match
    assert "publish_at >= $3::date" in q  # date_field=scheduled → publish_at
    assert "publish_at < ($4::date + interval '1 day')" in q  # end-inclusive
    # COUNT shares the same filter params (npub, search, from, to)
    assert captured["count_args"] == (NPUB, "hel+o", "2026-06-01", "2026-06-30")
    # page params come after the filter params
    assert captured["args"][:5] == (NPUB, "hel+o", "2026-06-01", "2026-06-30", 10)


@pytest.mark.asyncio
async def test_list_posts_unknown_date_field_falls_back_to_created():
    with patch.object(posts_db, "fetchrow", AsyncMock(return_value={"n": 0})), \
         patch.object(posts_db, "fetch", AsyncMock(return_value=[])) as f:
        await posts_db.list_posts(NPUB, date_from="2026-01-01", date_field="; DROP")
    q = f.await_args.args[0]
    assert "created_at >= $2::date" in q  # unknown field → created_at, no raw SQL
    assert "DROP" not in q


@pytest.mark.asyncio
async def test_list_posts_unknown_sort_falls_back_to_created():
    async def fake_fetchrow(query, *args):
        return {"n": 0}

    captured = {}

    async def fake_fetch(query, *args):
        captured["query"] = query
        return []

    with patch.object(posts_db, "fetchrow", fake_fetchrow), \
         patch.object(posts_db, "fetch", fake_fetch):
        await posts_db.list_posts(NPUB, sort_col="; DROP TABLE posts; --")
    # Unknown key never reaches the query as raw SQL — falls back to created_at.
    assert "ORDER BY created_at DESC, created_at DESC" in captured["query"]
    assert "DROP TABLE" not in captured["query"]


@pytest.mark.asyncio
async def test_hard_delete_uses_rowcount_camelcase():
    with patch.object(posts_db, "execute", AsyncMock(return_value={"rowCount": 1})):
        assert await posts_db.hard_delete(NPUB, PID) is True
    with patch.object(posts_db, "execute", AsyncMock(return_value={"rowCount": 0})):
        assert await posts_db.hard_delete(NPUB, PID) is False
