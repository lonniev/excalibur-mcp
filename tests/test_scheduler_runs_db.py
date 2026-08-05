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
    summary = {"kind": "tick", "processed": 1, "launched": [{"post_id": "p1"}], "contended": []}
    with patch.object(sr, "execute", AsyncMock(return_value={})) as ex:
        await sr.complete_run("abc-123", summary)
    q, args = ex.await_args.args[0], ex.await_args.args[1:]
    assert "UPDATE scheduler_runs" in q
    assert args[0] == "abc-123"
    assert json.loads(args[1]) == summary


@pytest.mark.asyncio
async def test_complete_run_appends_when_the_open_failed():
    """No row to close → the outcome is still recorded, just as a fresh append."""
    summary = {"kind": "publication", "post_id": "p1", "outcome": "posted"}
    with patch.object(sr, "execute", AsyncMock(return_value={})) as ex:
        await sr.complete_run(None, summary)
    assert "INSERT INTO scheduler_runs" in ex.await_args_list[0].args[0]




# -- owner scoping over two row kinds ----------------------------------------
#
# The ring carries TICKS (the scheduler dispatching, across all owners) and
# PUBLICATIONS (one publisher's outcome for one post, belonging to one owner).

OP = "npub1operator"
ALICE = "npub1alice"
BOB = "npub1bob"


def _tick():
    """A tick summary in the shape `scheduler.process_due_posts` ACTUALLY emits.

    This helper built a `launched` list until 2026-08-04, long after the
    resolve/post split renamed those keys to `posted`/`resolving`. Because the
    fixture and `scope_runs` were wrong in the same direction, every test here
    passed while real patrons saw an empty log — their own posts scoped away by a
    key lookup that could never match. A fixture that mirrors the producer is the
    only thing that makes these assertions mean anything.
    """
    return {"run_at": "t", "summary": {
        "kind": "tick", "processed": 3,
        "posted": [{"post_id": "a1", "owner": ALICE, "outcome": "posted"},
                   {"post_id": "b1", "owner": BOB, "outcome": "posted"}],
        "resolving": [{"post_id": "a2", "owner": ALICE, "claim_check": "cc-a"}],
        "contended": [],
    }}


def _publication(owner, outcome="posted", **extra):
    return {"run_at": "t", "summary": {
        "kind": "publication", "post_id": "x1", "owner": owner,
        "outcome": outcome, **extra,
    }}


def test_operator_sees_everything_untouched():
    runs = [_tick(), _publication(ALICE)]
    assert sr.scope_runs(runs, OP, OP) is runs


def test_owner_sees_the_tick_heartbeat_with_only_their_own_work():
    scoped = sr.scope_runs([_tick()], ALICE, OP)
    s = scoped[0]["summary"]
    assert scoped[0]["run_at"] == "t"  # heartbeat survives — proof the cron ran
    assert [e["post_id"] for e in s["posted"]] == ["a1"]  # bob's is hidden
    assert [e["post_id"] for e in s["resolving"]] == ["a2"]
    assert s["processed"] == 2  # alice's OWN count, never the global 3


def test_third_party_sees_the_heartbeat_but_no_counts_at_all():
    s = sr.scope_runs([_tick()], "npub1carol", OP)[0]["summary"]
    assert s["processed"] == 0
    assert s["posted"] == [] and s["resolving"] == [] and s["contended"] == []


def test_a_recovered_post_is_scoped_to_its_owner_like_any_other():
    """Phase 0's repairs are per-post, so they scope per-post. Without this the
    `recovered` key would either leak Bob's stranded posts to Alice or vanish."""
    tick = _tick()
    tick["summary"]["recovered"] = {
        "resumed": [{"post_id": "a3", "npub": ALICE, "owner": ALICE}],
        "paused_unknown": [{"post_id": "b3", "npub": BOB, "owner": BOB}],
    }
    s = sr.scope_runs([tick], ALICE, OP)[0]["summary"]
    assert [e["post_id"] for e in s["recovered"]["resumed"]] == ["a3"]
    assert "paused_unknown" not in s["recovered"], "bob's repair is not alice's business"
    assert s["processed"] == 3  # 1 posted + 1 resolving + 1 recovered


def test_a_publication_reaches_only_its_own_owner():
    runs = [_publication(ALICE, tweet_url="u"), _publication(BOB)]
    scoped = sr.scope_runs(runs, ALICE, OP)
    assert len(scoped) == 1
    assert scoped[0]["summary"]["owner"] == ALICE
    # bob's publication is dropped entirely — not even an empty placeholder
    assert all(r["summary"]["owner"] == ALICE for r in scoped)


def test_owners_own_publication_keeps_its_detail():
    """Held reasons and fallback notes are the whole point of the row — scoping
    must not strip them from the person they belong to."""
    runs = [_publication(ALICE, outcome="held", reason="insufficient_balance")]
    s = sr.scope_runs(runs, ALICE, OP)[0]["summary"]
    assert s["outcome"] == "held" and s["reason"] == "insufficient_balance"


def test_scope_runs_carries_the_started_marker_to_every_reader():
    """A cut-off tick has no entries to scope, but every reader must still see
    it was tried — otherwise it reads as 'the cron never ran'."""
    scoped = sr.scope_runs([{"run_at": "t", "summary": dict(sr.STARTED)}], ALICE, OP)
    assert scoped[0]["summary"]["status"] == "started"
    assert scoped[0]["summary"]["processed"] == 0


def _tick_with_forecast():
    return {"run_at": "t", "summary": {
        "kind": "tick", "processed": 0, "launched": [], "contended": [],
        # The tick's own totals span every owner.
        "upcoming": {"count": 5, "next_in_minutes": 12, "by_owner": {
            ALICE: {"count": 2, "next_in_minutes": 47},
            BOB: {"count": 3, "next_in_minutes": 12},
        }},
    }}


def test_forecast_is_narrowed_to_the_readers_own_queue():
    s = sr.scope_runs([_tick_with_forecast()], ALICE, OP)[0]["summary"]
    assert s["upcoming"] == {"count": 2, "next_in_minutes": 47}  # hers, not the total


def test_forecast_never_leaks_the_global_total_or_another_owners_timing():
    """The tick knows 5 posts are coming and the soonest is 12 min out — both
    facts describe other patrons, so neither may reach this reader."""
    s = sr.scope_runs([_tick_with_forecast()], ALICE, OP)[0]["summary"]
    assert s["upcoming"]["count"] != 5
    assert s["upcoming"].get("next_in_minutes") != 12
    assert "by_owner" not in s["upcoming"]  # the whole map must not travel


def test_reader_with_nothing_queued_is_told_so():
    s = sr.scope_runs([_tick_with_forecast()], "npub1carol", OP)[0]["summary"]
    assert s["upcoming"] == {"count": 0}


def test_operator_keeps_the_whole_forecast():
    runs = [_tick_with_forecast()]
    assert sr.scope_runs(runs, OP, OP)[0]["summary"]["upcoming"]["count"] == 5
