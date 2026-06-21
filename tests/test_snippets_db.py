"""Low-level snippets SQL tests — npub-scoping, sort whitelist, doc encoding.

The Neon layer (``execute``/``fetch``/``fetchrow``) is faked so we can assert on
the SQL and params the CRUD functions build — every statement must be
npub-scoped, the sort key must come from the whitelist, and ``doc`` must be
json-encoded.
"""

import json
from unittest.mock import patch

import pytest

from excalibur_mcp.db import snippets as snippets_db

NPUB = "npub1l94pd4qu4eszrl6ek032ftcnsu3tt9a7xvq2zp7eaxeklp6mrpzssmq8pf"
SID = "11111111-1111-1111-1111-111111111111"


@pytest.mark.asyncio
async def test_list_snippets_offset_sort_and_total():
    captured = {}

    async def fake_fetchrow(query, *args):  # COUNT(*)
        return {"n": 3}

    async def fake_fetch(query, *args):
        captured["query"] = query
        captured["args"] = args
        return []

    with patch.object(snippets_db, "fetchrow", fake_fetchrow), \
         patch.object(snippets_db, "fetch", fake_fetch):
        out = await snippets_db.list_snippets(
            NPUB, sort_col="name", sort_dir="asc", page=1, page_size=10,
        )
    q = captured["query"]
    assert "WHERE npub = $1" in q
    assert "ORDER BY lower(name) ASC, created_at DESC" in q
    assert "LIMIT $2 OFFSET $3" in q
    assert captured["args"] == (NPUB, 10, 10)  # offset = page 1 * size 10
    assert out["total"] == 3 and out["page"] == 1 and out["page_size"] == 10


@pytest.mark.asyncio
async def test_list_snippets_search_matches_name_or_body_and_filters_count():
    captured = {}

    async def fake_fetchrow(query, *args):  # COUNT(*)
        captured["count_query"] = query
        captured["count_args"] = args
        return {"n": 2}

    async def fake_fetch(query, *args):
        captured["query"] = query
        captured["args"] = args
        return []

    with patch.object(snippets_db, "fetchrow", fake_fetchrow), \
         patch.object(snippets_db, "fetch", fake_fetch):
        await snippets_db.list_snippets(
            NPUB, search="cta", date_from="2026-01-01", page_size=10,
        )
    q = captured["query"]
    assert "(name ~* $2 OR body ~* $2)" in q  # one param, name OR body
    assert "created_at >= $3::date" in q
    # COUNT is filtered (same params), not a bare count-all
    assert captured["count_args"] == (NPUB, "cta", "2026-01-01")
    assert "WHERE npub = $1 AND (name ~* $2" in captured["count_query"]


@pytest.mark.asyncio
async def test_list_snippets_unknown_sort_falls_back_to_favorite():
    captured = {}

    async def fake_fetchrow(query, *args):
        return {"n": 0}

    async def fake_fetch(query, *args):
        captured["query"] = query
        return []

    with patch.object(snippets_db, "fetchrow", fake_fetchrow), \
         patch.object(snippets_db, "fetch", fake_fetch):
        await snippets_db.list_snippets(NPUB, sort_col="evil; DROP")
    assert "ORDER BY favorite DESC, created_at DESC" in captured["query"]
    assert "DROP" not in captured["query"]


@pytest.mark.asyncio
async def test_get_snippet_is_npub_scoped():
    captured = {}

    async def fake_fetchrow(query, *args):
        captured["query"] = query
        captured["args"] = args
        return {"id": SID, "name": "Footer", "text": "thanks", "doc": None,
                "favorite": True}

    with patch.object(snippets_db, "fetchrow", fake_fetchrow):
        row = await snippets_db.get_snippet(NPUB, SID)
    assert "WHERE id = $2::uuid AND npub = $1" in captured["query"]
    assert captured["args"] == (NPUB, SID)
    assert row["id"] == SID


@pytest.mark.asyncio
async def test_create_snippet_json_encodes_doc():
    captured = {}

    async def fake_fetchrow(query, *args):
        captured["query"] = query
        captured["args"] = args
        return {"id": SID}

    doc = {"blocks": [{"text": "hi", "flags": []}]}
    with patch.object(snippets_db, "fetchrow", fake_fetchrow):
        await snippets_db.create_snippet(NPUB, "Footer", "hi", True, doc=doc)
    # doc bound as a JSON string (the $5::jsonb param), npub first.
    assert captured["args"][0] == NPUB
    assert json.loads(captured["args"][4]) == doc


@pytest.mark.asyncio
async def test_update_snippet_only_patches_doc_when_given():
    captured = {}

    async def fake_fetchrow(query, *args):
        captured["query"] = query
        captured["args"] = args
        return {"id": SID}

    with patch.object(snippets_db, "fetchrow", fake_fetchrow):
        await snippets_db.update_snippet(NPUB, SID, favorite=True)
    q = captured["query"]
    assert "favorite = $3" in q
    assert "doc =" not in q  # not provided → not in SET (RETURNING still lists doc)
    assert "WHERE id = $2::uuid AND npub = $1" in q
