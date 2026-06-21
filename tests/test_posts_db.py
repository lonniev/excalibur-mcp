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


def test_cursor_round_trip():
    cur = posts_db._encode_cursor("2026-06-19T00:00:00+00:00", PID)
    assert posts_db._decode_cursor(cur) == ("2026-06-19T00:00:00+00:00", PID)


def test_cursor_decode_garbage_is_none():
    assert posts_db._decode_cursor("@@not-base64@@") is None


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
    # doc is json-encoded; recurrence None stays None (not the string "null")
    assert captured["args"][0] == NPUB
    assert json.loads(captured["args"][2]) == {"blocks": [1]}
    assert captured["args"][5] is None  # recurrence


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
    assert "tweet_url    = COALESCE($5, tweet_url)" in captured["query"]
    assert "https://x.com/i/status/456" in captured["args"]


@pytest.mark.asyncio
async def test_list_posts_pagination_emits_next_cursor():
    rows = [
        {"post_id": f"id{i}", "status": "draft", "excerpt": f"e{i}",
         "publish_at": None, "updated_at": "t", "created_at": f"2026-06-1{i}T00:00:00+00:00"}
        for i in range(3)
    ]
    with patch.object(posts_db, "fetch", AsyncMock(return_value=rows)):
        out = await posts_db.list_posts(NPUB, limit=2)
    assert len(out["posts"]) == 2  # extra row trimmed
    assert out["next_cursor"] is not None
    assert out["posts"][0]["excerpt"] == "e0"


@pytest.mark.asyncio
async def test_hard_delete_uses_rowcount_camelcase():
    with patch.object(posts_db, "execute", AsyncMock(return_value={"rowCount": 1})):
        assert await posts_db.hard_delete(NPUB, PID) is True
    with patch.object(posts_db, "execute", AsyncMock(return_value={"rowCount": 0})):
        assert await posts_db.hard_delete(NPUB, PID) is False
