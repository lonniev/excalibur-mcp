"""Scheduler-run audit-ring SQL tests.

The Neon layer (``execute``/``fetch``) is faked so we can assert the audit ring
json-encodes its summary, prunes to the retention cap, and reads back newest-first
with a clamped limit.
"""

import json
from unittest.mock import AsyncMock, patch

import pytest

from excalibur_mcp.db import scheduler_runs as sr


@pytest.mark.asyncio
async def test_record_run_json_encodes_and_prunes():
    calls = []

    async def fake_execute(query, *args):
        calls.append((query, args))
        return {"rowCount": 1}

    summary = {"processed": 1, "posted": [], "skipped": [{"post_id": "p", "reason": "x"}], "errors": []}
    with patch.object(sr, "execute", fake_execute):
        await sr.record_run(summary)

    # First statement inserts a json-encoded summary into scheduler_runs.
    insert_q, insert_args = calls[0]
    assert "INSERT INTO scheduler_runs" in insert_q
    assert json.loads(insert_args[0]) == summary

    # Second statement prunes the ring to the newest _KEEP rows.
    prune_q, prune_args = calls[1]
    assert "DELETE FROM scheduler_runs" in prune_q
    assert "ORDER BY run_at DESC LIMIT $1" in prune_q
    assert prune_args[0] == sr._KEEP


@pytest.mark.asyncio
async def test_list_runs_orders_desc_and_clamps_limit():
    captured = {}

    async def fake_fetch(query, *args):
        captured["query"] = query
        captured["args"] = args
        return [{"run_at": "t", "summary": {"processed": 0}}]

    with patch.object(sr, "fetch", fake_fetch):
        out = await sr.list_runs(limit=9999)  # over the cap

    assert "ORDER BY run_at DESC" in captured["query"]
    assert captured["args"][0] == 100  # clamped to max
    assert out[0]["summary"] == {"processed": 0}


@pytest.mark.asyncio
async def test_list_runs_floor_limit():
    with patch.object(sr, "fetch", AsyncMock(return_value=[])) as f:
        await sr.list_runs(limit=0)
    assert f.await_args.args[1] == 1  # clamped to min
