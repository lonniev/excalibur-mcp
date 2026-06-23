"""Low-level voice SQL tests — npub keying, upsert, and bans encoding.

The Neon layer (``fetchrow``) is faked so we can assert on the SQL and params the
CRUD functions build — the Voice is a per-npub singleton, so get is npub-keyed
and save is an ``ON CONFLICT (npub)`` upsert with ``bans`` json-encoded.
"""

import json
from unittest.mock import patch

import pytest

from excalibur_mcp.db import voices as voices_db

NPUB = "npub1l94pd4qu4eszrl6ek032ftcnsu3tt9a7xvq2zp7eaxeklp6mrpzssmq8pf"


@pytest.mark.asyncio
async def test_get_voice_is_npub_keyed_and_coerces_bans():
    captured = {}

    async def fake_fetchrow(query, *args):
        captured["query"] = query
        captured["args"] = args
        # Simulate a driver that handed bans back as a JSON string.
        return {"npub": NPUB, "profile": "plain", "bans": '[{"text": "x", "on": true}]'}

    with patch.object(voices_db, "fetchrow", fake_fetchrow):
        row = await voices_db.get_voice(NPUB)
    assert "WHERE npub = $1" in captured["query"]
    assert captured["args"] == (NPUB,)
    assert row["bans"] == [{"text": "x", "on": True}]  # decoded from string


@pytest.mark.asyncio
async def test_get_voice_missing_returns_none():
    async def fake_fetchrow(query, *args):
        return None

    with patch.object(voices_db, "fetchrow", fake_fetchrow):
        assert await voices_db.get_voice(NPUB) is None


@pytest.mark.asyncio
async def test_upsert_voice_is_on_conflict_and_json_encodes_bans():
    captured = {}

    async def fake_fetchrow(query, *args):
        captured["query"] = query
        captured["args"] = args
        return {"npub": NPUB, "profile": "plain", "bans": [{"text": "x", "on": True}]}

    bans = [{"text": "x", "on": True}]
    with patch.object(voices_db, "fetchrow", fake_fetchrow):
        await voices_db.upsert_voice(NPUB, "plain", bans)
    q = captured["query"]
    assert "ON CONFLICT (npub) DO UPDATE" in q
    assert "$3::jsonb" in q
    assert captured["args"][0] == NPUB
    assert captured["args"][1] == "plain"
    assert json.loads(captured["args"][2]) == bans  # bans bound as a JSON string
