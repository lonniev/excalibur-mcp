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


OP = "npub1operator"
ALICE = "npub1alice"
BOB = "npub1bob"


def _run():
    return {
        "run_at": "t",
        "summary": {
            "processed": 2,
            "posted": [{"post_id": "a1", "owner": ALICE, "tweet_url": "u"}],
            "skipped": [{"post_id": "b1", "owner": BOB, "reason": "insufficient_balance"}],
            "errors": [],
        },
    }


def test_scope_runs_operator_sees_everything():
    runs = [_run()]
    assert sr.scope_runs(runs, OP, OP) is runs  # full, unfiltered


def test_scope_runs_owner_sees_only_their_entries_and_own_count():
    scoped = sr.scope_runs([_run()], ALICE, OP)
    s = scoped[0]["summary"]
    assert [e["post_id"] for e in s["posted"]] == ["a1"]  # alice's own
    assert s["skipped"] == []  # bob's skip is hidden from alice
    assert s["processed"] == 1  # alice's OWN count, NOT the global 2 (no leak)
    assert scoped[0]["run_at"] == "t"  # heartbeat (proof it ran) still present


def test_scope_runs_owner_with_no_posts_sees_heartbeat_but_no_global_count():
    scoped = sr.scope_runs([_run()], "npub1carol", OP)
    s = scoped[0]["summary"]
    assert scoped[0]["run_at"] == "t"  # worker ran (heartbeat)
    # no cross-patron leak: not the global 2, and none of bob's/alice's entries
    assert s["processed"] == 0 and s["posted"] == [] and s["skipped"] == [] and s["errors"] == []


# -- open/close pair ---------------------------------------------------------
#
# A tick whose request is cut off at the edge writes nothing at the end, so the
# row is opened BEFORE any work. One still reading `status: started` is a tick
# that never came back — the difference between a wedged Worker and a dead cron.

@pytest.mark.asyncio
async def test_begin_run_opens_a_started_row_and_prunes():
    calls = []

    async def fake_fetchrow(query, *args):
        calls.append((query, args))
        return {"id": "abc-123"}

    with patch.object(sr, "fetchrow", fake_fetchrow), \
         patch.object(sr, "execute", AsyncMock(return_value={})) as ex:
        run_id = await sr.begin_run()

    assert run_id == "abc-123"
    insert_q, insert_args = calls[0]
    assert "INSERT INTO scheduler_runs" in insert_q and "RETURNING id" in insert_q
    assert json.loads(insert_args[0]) == sr.STARTED
    # the ring is still capped on open, so a wedged scheduler can't grow it
    assert "DELETE FROM scheduler_runs" in ex.await_args.args[0]


@pytest.mark.asyncio
async def test_begin_run_survives_a_dead_audit_store():
    """Audit is never a gate: if the ring can't be written, the tick still runs."""
    with patch.object(sr, "fetchrow", AsyncMock(side_effect=RuntimeError("neon down"))):
        assert await sr.begin_run() is None


@pytest.mark.asyncio
async def test_complete_run_updates_the_opened_row():
    summary = {"processed": 1, "posted": [], "skipped": [], "errors": [], "deferred": []}
    with patch.object(sr, "execute", AsyncMock(return_value={})) as ex:
        await sr.complete_run("abc-123", summary)
    q, args = ex.await_args.args[0], ex.await_args.args[1:]
    assert "UPDATE scheduler_runs" in q
    assert args[0] == "abc-123"
    assert json.loads(args[1]) == summary


@pytest.mark.asyncio
async def test_complete_run_appends_when_the_open_failed():
    """No row to close → the outcome is still recorded, just as a fresh append."""
    summary = {"processed": 0, "posted": [], "skipped": [], "errors": [], "deferred": []}
    with patch.object(sr, "execute", AsyncMock(return_value={})) as ex:
        await sr.complete_run(None, summary)
    assert "INSERT INTO scheduler_runs" in ex.await_args_list[0].args[0]


def test_scope_runs_carries_the_started_marker_to_every_reader():
    """A cut-off tick has no per-post entries to scope, but every reader must
    still see it was tried — otherwise it reads as 'the cron never ran'."""
    runs = [{"run_at": "t", "summary": dict(sr.STARTED)}]
    scoped = sr.scope_runs(runs, ALICE, OP)
    assert scoped[0]["summary"]["status"] == "started"
    assert scoped[0]["summary"]["processed"] == 0


def test_scope_runs_counts_deferred_as_the_readers_own_work():
    runs = [{
        "run_at": "t",
        "summary": {
            "processed": 2, "posted": [], "skipped": [], "errors": [],
            "deferred": [
                {"post_id": "a1", "owner": ALICE, "reason": "tick_budget_exhausted"},
                {"post_id": "b1", "owner": BOB, "reason": "tick_budget_exhausted"},
            ],
        },
    }]
    s = sr.scope_runs(runs, ALICE, OP)[0]["summary"]
    assert [d["post_id"] for d in s["deferred"]] == ["a1"]  # bob's is hidden
    assert s["processed"] == 1  # alice's own held post, not the global 2
