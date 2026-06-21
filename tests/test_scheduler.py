"""Scheduler tests — recurrence math and the due-post firing loop.

The firing loop is exercised with everything faked: the due list, the X client
resolution, the wheel's pricing/billing methods, and ``mark_sent``. We assert
the money + lifecycle rules: charge then post, refund on post failure, skip on
insufficient balance / unavailable OAuth, and reschedule vs retire correctly.
"""

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from excalibur_mcp import scheduler
from excalibur_mcp.x_client import XAPIError

NPUB = "npub1l94pd4qu4eszrl6ek032ftcnsu3tt9a7xvq2zp7eaxeklp6mrpzssmq8pf"


@pytest.fixture(autouse=True)
def _stub_record_run():
    """Every process_due_posts call records its summary; keep that off Neon and
    expose the mock so a test can assert the recording contract."""
    with patch.object(scheduler.scheduler_runs, "record_run", AsyncMock()) as rec:
        yield rec


@pytest.fixture(autouse=True)
def _stub_mark_attempt():
    """Held attempts stamp the post (last_attempt_at/reason); keep that off Neon
    and expose the mock so a test can assert the stamping contract."""
    with patch.object(scheduler.posts_db, "mark_attempt", AsyncMock()) as m:
        yield m


# -- recurrence math ---------------------------------------------------------

def test_add_months_clamps_end_of_month():
    d = datetime(2026, 1, 31, 12, 0, tzinfo=timezone.utc)
    assert scheduler._add_months(d, 1).date().isoformat() == "2026-02-28"


def test_advance_units():
    d = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
    assert scheduler._advance(d, {"freq": "daily", "interval": 3}).day == 4
    assert scheduler._advance(d, {"freq": "weekly", "interval": 1}).day == 8
    assert scheduler._advance(d, {"freq": "hourly"}) is None


def test_next_state_no_recurrence_retires():
    d = datetime(2026, 6, 1, tzinfo=timezone.utc)
    assert scheduler._next_state(d, None, None) == ("sent", None)


def test_next_state_past_cease_retires():
    d = datetime(2026, 6, 1, tzinfo=timezone.utc)
    status, nxt = scheduler._next_state(d, {"freq": "daily", "interval": 1}, "2026-06-01T06:00:00+00:00")
    assert status == "sent" and nxt is None


def test_next_state_reschedules_within_cease():
    d = datetime(2026, 6, 1, tzinfo=timezone.utc)
    status, nxt = scheduler._next_state(d, {"freq": "daily", "interval": 1}, "2026-12-31T00:00:00+00:00")
    assert status == "scheduled" and nxt is not None


def test_as_dict_handles_string_jsonb():
    assert scheduler._as_dict('{"freq": "daily"}') == {"freq": "daily"}
    assert scheduler._as_dict({"freq": "weekly"}) == {"freq": "weekly"}
    assert scheduler._as_dict(None) is None


# -- firing loop -------------------------------------------------------------

def _runtime(*, billing=5, pricing=(5, None)):
    rt = SimpleNamespace()
    rt._resolve_pricing = AsyncMock(return_value=pricing)
    rt._apply_billing = AsyncMock(return_value=billing)
    rt.rollback_debit = AsyncMock()
    return rt


def _due_row(**over):
    row = {"post_id": "p1", "npub": NPUB, "text_cache": "hello world",
           "recurrence": {"freq": "daily", "interval": 1}, "cease_at": "2026-12-31T00:00:00+00:00"}
    row.update(over)
    return row


@pytest.mark.asyncio
async def test_recurring_fire_snapshots_occurrence_and_advances(_stub_record_run):
    rt = _runtime()
    # x_client.post_tweet returns {tweet_id, tweet_url} — the summary must read
    # those exact keys (not a bare "id").
    url = "https://x.com/i/status/tw1"
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "tw1", "tweet_url": url}))
    with patch.object(scheduler.posts_db, "list_due", AsyncMock(return_value=[_due_row(doc={"blocks": []})])), \
         patch.object(scheduler.posts_db, "mark_sent", AsyncMock()) as mark, \
         patch.object(scheduler.posts_db, "create_sent_occurrence", AsyncMock()) as occ, \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await scheduler.process_due_posts(rt)
    assert out["processed"] == 1 and len(out["posted"]) == 1
    rt._apply_billing.assert_awaited_once()
    client.post_tweet.assert_awaited_once()
    assert out["posted"][0]["tweet_id"] == "tw1"
    assert out["posted"][0]["tweet_url"] == url
    # recurring → a Sent occurrence is snapshotted WITH the url …
    occ.assert_awaited_once()
    assert occ.await_args.kwargs["tweet_url"] == url
    assert occ.await_args.kwargs["npub"] == NPUB
    # … and the template just advances (status scheduled, url NOT overwritten on it)
    assert mark.await_args.args[2] == "scheduled"
    assert mark.await_args.args[4] is None
    rt.rollback_debit.assert_not_awaited()
    # the tick records its summary for FE visibility
    _stub_record_run.assert_awaited_once_with(out)


@pytest.mark.asyncio
async def test_one_shot_fire_marks_row_sent_with_url():
    rt = _runtime()
    url = "https://x.com/i/status/tw2"
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "tw2", "tweet_url": url}))
    # no recurrence → one-shot
    with patch.object(scheduler.posts_db, "list_due",
                      AsyncMock(return_value=[_due_row(recurrence=None, cease_at=None)])), \
         patch.object(scheduler.posts_db, "mark_sent", AsyncMock()) as mark, \
         patch.object(scheduler.posts_db, "create_sent_occurrence", AsyncMock()) as occ, \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await scheduler.process_due_posts(rt)
    assert len(out["posted"]) == 1
    occ.assert_not_called()  # one-shot leaves no separate occurrence
    assert mark.await_args.args[2] == "sent"  # the row itself becomes Sent
    assert mark.await_args.args[4] == url


@pytest.mark.asyncio
async def test_record_run_failure_does_not_break_the_tick(_stub_record_run):
    # Audit is best-effort: a recording failure must not undo posting work.
    _stub_record_run.side_effect = RuntimeError("neon down")
    rt = _runtime()
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "tw1", "tweet_url": "u"}))
    with patch.object(scheduler.posts_db, "list_due", AsyncMock(return_value=[_due_row()])), \
         patch.object(scheduler.posts_db, "mark_sent", AsyncMock()), \
         patch.object(scheduler.posts_db, "create_sent_occurrence", AsyncMock()), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await scheduler.process_due_posts(rt)
    assert out["processed"] == 1 and len(out["posted"]) == 1  # tick still succeeded


@pytest.mark.asyncio
async def test_insufficient_balance_skips_without_posting(_stub_mark_attempt):
    rt = _runtime(billing={"success": False, "error_code": "insufficient_balance"})
    client = SimpleNamespace(post_tweet=AsyncMock())
    with patch.object(scheduler.posts_db, "list_due", AsyncMock(return_value=[_due_row()])), \
         patch.object(scheduler.posts_db, "mark_sent", AsyncMock()) as mark, \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await scheduler.process_due_posts(rt)
    assert out["skipped"] and out["skipped"][0]["reason"] == "insufficient_balance"
    client.post_tweet.assert_not_awaited()
    mark.assert_not_called()
    # the held post is stamped "attempted" with the finance reason
    _stub_mark_attempt.assert_awaited_once()
    assert _stub_mark_attempt.await_args.args[0] == "p1"
    assert _stub_mark_attempt.await_args.args[2] == "insufficient_balance"


@pytest.mark.asyncio
async def test_oauth_unavailable_skips_without_billing():
    rt = _runtime()
    with patch.object(scheduler.posts_db, "list_due", AsyncMock(return_value=[_due_row()])), \
         patch("excalibur_mcp.server._resolve_x_client",
               AsyncMock(return_value=(None, {"error_code": "oauth_token_expired"}))):
        out = await scheduler.process_due_posts(rt)
    assert out["skipped"][0]["reason"] == "oauth_token_expired"
    rt._apply_billing.assert_not_awaited()


@pytest.mark.asyncio
async def test_post_failure_refunds_owner():
    rt = _runtime()
    client = SimpleNamespace(post_tweet=AsyncMock(side_effect=XAPIError(500, "boom")))
    with patch.object(scheduler.posts_db, "list_due", AsyncMock(return_value=[_due_row()])), \
         patch.object(scheduler.posts_db, "mark_sent", AsyncMock()) as mark, \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await scheduler.process_due_posts(rt)
    assert out["errors"] and "x_api_error" in out["errors"][0]["reason"]
    rt.rollback_debit.assert_awaited_once()
    mark.assert_not_called()


@pytest.mark.asyncio
async def test_empty_text_cache_skipped_early():
    rt = _runtime()
    with patch.object(scheduler.posts_db, "list_due", AsyncMock(return_value=[_due_row(text_cache="   ")])), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock()) as resolve:
        out = await scheduler.process_due_posts(rt)
    assert out["skipped"][0]["reason"] == "empty_text_cache"
    resolve.assert_not_called()
