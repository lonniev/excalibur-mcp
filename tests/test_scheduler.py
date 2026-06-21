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
async def test_fires_charges_posts_and_reschedules():
    rt = _runtime()
    # x_client.post_tweet returns {tweet_id, tweet_url} — the summary + mark_sent
    # must read those exact keys (not a bare "id").
    url = "https://x.com/i/status/tw1"
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "tw1", "tweet_url": url}))
    with patch.object(scheduler.posts_db, "list_due", AsyncMock(return_value=[_due_row()])), \
         patch.object(scheduler.posts_db, "mark_sent", AsyncMock()) as mark, \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await scheduler.process_due_posts(rt)
    assert out["processed"] == 1 and len(out["posted"]) == 1
    rt._apply_billing.assert_awaited_once()
    client.post_tweet.assert_awaited_once()
    # summary surfaces the real tweet id + url (regression: was reading "id" → null)
    assert out["posted"][0]["tweet_id"] == "tw1"
    assert out["posted"][0]["tweet_url"] == url
    # rescheduled (daily, within cease) → status scheduled, mark_sent gets the url
    assert mark.await_args.args[2] == "scheduled"
    assert mark.await_args.args[4] == url
    rt.rollback_debit.assert_not_awaited()


@pytest.mark.asyncio
async def test_insufficient_balance_skips_without_posting():
    rt = _runtime(billing={"success": False, "error_code": "insufficient_balance"})
    client = SimpleNamespace(post_tweet=AsyncMock())
    with patch.object(scheduler.posts_db, "list_due", AsyncMock(return_value=[_due_row()])), \
         patch.object(scheduler.posts_db, "mark_sent", AsyncMock()) as mark, \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await scheduler.process_due_posts(rt)
    assert out["skipped"] and out["skipped"][0]["reason"] == "insufficient_balance"
    client.post_tweet.assert_not_awaited()
    mark.assert_not_called()


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
