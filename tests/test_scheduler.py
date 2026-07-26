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
def _stub_run_ring():
    """Every process_due_posts call OPENS an audit row before any work and closes
    it with the summary, so a tick cut off mid-flight still leaves a mark. Keep
    both off Neon and expose the closing mock for the recording contract."""
    with patch.object(scheduler.scheduler_runs, "begin_run", AsyncMock(return_value="run-1")), \
         patch.object(scheduler.scheduler_runs, "complete_run", AsyncMock()) as done:
        yield done


@pytest.fixture(autouse=True)
def _stub_mark_attempt():
    """Held attempts stamp the post (last_attempt_at/reason); keep that off Neon
    and expose the mock so a test can assert the stamping contract."""
    with patch.object(scheduler.posts_db, "mark_attempt", AsyncMock()) as m:
        yield m


@pytest.fixture(autouse=True)
def _stub_mark_paused():
    """A non-transient situation (e.g. X 402) pauses the post; keep that off Neon
    and expose the mock so a test can assert the pause contract."""
    with patch.object(scheduler.posts_db, "mark_paused", AsyncMock()) as m:
        yield m


@pytest.fixture(autouse=True)
def _stub_claim_due_post():
    """The loop atomically claims each due post (scheduled → sending) before
    working it, so overlapping ticks can't double-fire. Default: the claim wins
    (returns a truthy row) so the loop proceeds; a test overrides to None to
    simulate a post another concurrent tick already owns."""
    with patch.object(
        scheduler.posts_db, "claim_due_post",
        AsyncMock(side_effect=lambda pid: {"post_id": pid}),
    ) as m:
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


def test_advance_weekdays_skips_weekend():
    # 2026-06-05 is a Friday. One business day forward lands on Monday 06-08,
    # never Saturday/Sunday; the time of day is preserved.
    fri = datetime(2026, 6, 5, 9, 30, tzinfo=timezone.utc)
    nxt = scheduler._advance(fri, {"freq": "weekdays", "interval": 1})
    assert nxt.date().isoformat() == "2026-06-08" and nxt.hour == 9 and nxt.minute == 30
    # interval = 5 business days == one calendar week forward (Fri -> Fri).
    assert scheduler._advance(fri, {"freq": "weekdays", "interval": 5}).date().isoformat() == "2026-06-12"


def test_advance_weekdays_never_lands_on_weekend():
    cur = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)  # Monday
    for _ in range(40):
        cur = scheduler._advance(cur, {"freq": "weekdays", "interval": 1})
        assert cur.weekday() < 5  # Mon=0 .. Fri=4, never Sat(5)/Sun(6)


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
async def test_recurring_fire_snapshots_occurrence_and_advances(_stub_run_ring):
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
    # … back-linked to the template it fired from (post_id "p1") …
    assert occ.await_args.kwargs["template_id"] == "p1"
    # … and the template just advances (status scheduled, url NOT overwritten on it)
    assert mark.await_args.args[2] == "scheduled"
    assert mark.await_args.args[4] is None
    rt.rollback_debit.assert_not_awaited()
    # the tick closes the row it opened, with its summary, for FE visibility
    _stub_run_ring.assert_awaited_once_with("run-1", out)


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
async def test_post_claimed_by_another_tick_is_skipped(_stub_claim_due_post):
    """An overlapping cron tick that LOSES the atomic claim must not fire the
    post — the claim is what prevents double-posting under a fast (*/1) cron."""
    _stub_claim_due_post.side_effect = None
    _stub_claim_due_post.return_value = None  # another tick already owns it
    rt = _runtime()
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "x", "tweet_url": "u"}))
    with patch.object(scheduler.posts_db, "list_due",
                      AsyncMock(return_value=[_due_row(recurrence=None, cease_at=None)])), \
         patch.object(scheduler.posts_db, "mark_sent", AsyncMock()) as mark, \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await scheduler.process_due_posts(rt)
    client.post_tweet.assert_not_awaited()  # never posted
    mark.assert_not_awaited()
    rt._apply_billing.assert_not_awaited()  # nor billed
    assert out["posted"] == []


@pytest.mark.asyncio
async def test_record_run_failure_does_not_break_the_tick(_stub_run_ring):
    # Audit is best-effort: a recording failure must not undo posting work.
    _stub_run_ring.side_effect = RuntimeError("neon down")
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
async def test_402_pauses_post_and_refunds(_stub_mark_attempt, _stub_mark_paused):
    """A 402 (owner's X subscription lapsed) is non-transient: refund, PAUSE the
    post so list_due stops returning it, and report it — never leave it scheduled
    to re-fire (and re-bill/refund) every tick."""
    rt = _runtime()
    client = SimpleNamespace(
        post_tweet=AsyncMock(side_effect=XAPIError(402, "subscription lapsed")),
    )
    with patch.object(scheduler.posts_db, "list_due", AsyncMock(return_value=[_due_row()])), \
         patch.object(scheduler.posts_db, "mark_sent", AsyncMock()) as mark, \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await scheduler.process_due_posts(rt)
    assert out["errors"] and out["errors"][0]["paused"] is True
    assert "x_api_error" in out["errors"][0]["reason"]
    rt.rollback_debit.assert_awaited_once()
    # paused (not merely attempt-stamped), and never marked sent
    _stub_mark_paused.assert_awaited_once()
    assert _stub_mark_paused.await_args.args[0] == "p1"
    _stub_mark_attempt.assert_not_awaited()
    mark.assert_not_called()


@pytest.mark.asyncio
async def test_empty_text_cache_skipped_early():
    rt = _runtime()
    with patch.object(scheduler.posts_db, "list_due", AsyncMock(return_value=[_due_row(text_cache="   ")])), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock()) as resolve:
        out = await scheduler.process_due_posts(rt)
    assert out["skipped"][0]["reason"] == "empty_text_cache"
    resolve.assert_not_called()


# -- dynamic blocks ----------------------------------------------------------

def _dynamic_runtime():
    rt = _runtime()
    rt.load_credentials = AsyncMock(return_value={"anthropic_api_key": "k"})
    return rt


_DYNAMIC_DOC = {"blocks": [
    {"text": "Markets update.", "flags": []},
    {"text": "the BTC/USD price now", "flags": [], "dynamic": True, "fallback": "Markets moving fast."},
]}


@pytest.mark.asyncio
async def test_dynamic_block_resolved_then_posted():
    rt = _dynamic_runtime()
    url = "https://x.com/i/status/tw9"
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "tw9", "tweet_url": url}))
    with patch.object(scheduler.posts_db, "list_due",
                      AsyncMock(return_value=[_due_row(doc=_DYNAMIC_DOC, recurrence=None, cease_at=None)])), \
         patch.object(scheduler.posts_db, "mark_sent", AsyncMock()) as mark, \
         patch.object(scheduler, "_owner_voice", AsyncMock(return_value=("", []))), \
         patch("excalibur_mcp.resolve.resolve_block", AsyncMock(return_value="BTC at $64,000")), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await scheduler.process_due_posts(rt)
    assert len(out["posted"]) == 1
    posted_text = client.post_tweet.await_args.args[0]
    assert "Markets update." in posted_text and "BTC at $64,000" in posted_text
    # billed twice: resolve fare + post fare
    assert rt._apply_billing.await_count == 2
    # one-shot row marked sent with the resolved text reflected in its text_cache
    assert mark.await_args.args[2] == "sent"
    rt.rollback_debit.assert_not_awaited()


@pytest.mark.asyncio
async def test_dynamic_resolve_failure_uses_fallback_and_posts():
    rt = _dynamic_runtime()
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "t", "tweet_url": "u"}))
    with patch.object(scheduler.posts_db, "list_due",
                      AsyncMock(return_value=[_due_row(doc=_DYNAMIC_DOC, recurrence=None, cease_at=None)])), \
         patch.object(scheduler.posts_db, "mark_sent", AsyncMock()), \
         patch.object(scheduler, "_owner_voice", AsyncMock(return_value=("", []))), \
         patch("excalibur_mcp.resolve.resolve_block", AsyncMock(side_effect=RuntimeError("anthropic down"))), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await scheduler.process_due_posts(rt)
    assert len(out["posted"]) == 1
    posted_text = client.post_tweet.await_args.args[0]
    assert "Markets moving fast." in posted_text  # the author's fallback
    rt.rollback_debit.assert_not_awaited()  # it posted → resolve fare stands


@pytest.mark.asyncio
async def test_dynamic_resolve_failure_no_fallback_holds_and_refunds(_stub_mark_attempt):
    rt = _dynamic_runtime()
    doc = {"blocks": [{"text": "the price now", "flags": [], "dynamic": True}]}  # no fallback
    client = SimpleNamespace(post_tweet=AsyncMock())
    with patch.object(scheduler.posts_db, "list_due", AsyncMock(return_value=[_due_row(doc=doc)])), \
         patch.object(scheduler.posts_db, "mark_sent", AsyncMock()) as mark, \
         patch.object(scheduler, "_owner_voice", AsyncMock(return_value=("", []))), \
         patch("excalibur_mcp.resolve.resolve_block", AsyncMock(side_effect=RuntimeError("down"))), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await scheduler.process_due_posts(rt)
    assert out["errors"] and out["errors"][0]["reason"] == "dynamic_resolve_failed"
    client.post_tweet.assert_not_awaited()  # never post a gap
    mark.assert_not_called()
    rt.rollback_debit.assert_awaited_once()  # resolve fare refunded on hold
    # post_tweet fare was never charged (held before that billing)
    assert rt._apply_billing.await_count == 1


@pytest.mark.asyncio
async def test_multiple_dynamic_blocks_all_resolved_in_parallel():
    rt = _dynamic_runtime()
    doc = {"blocks": [
        {"text": "weather now", "flags": [], "dynamic": True, "fallback": "fa"},
        {"text": "btc price now", "flags": [], "dynamic": True, "fallback": "fb"},
        {"text": "static tail", "flags": []},
    ]}
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "t", "tweet_url": "u"}))
    rb = AsyncMock(side_effect=["Sunny 72F", "BTC $64k"])
    with patch.object(scheduler.posts_db, "list_due",
                      AsyncMock(return_value=[_due_row(doc=doc, recurrence=None, cease_at=None)])), \
         patch.object(scheduler.posts_db, "mark_sent", AsyncMock()), \
         patch.object(scheduler, "_owner_voice", AsyncMock(return_value=("", []))), \
         patch("excalibur_mcp.resolve.resolve_block", rb), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await scheduler.process_due_posts(rt)
    assert len(out["posted"]) == 1
    assert rb.await_count == 2  # both dynamic blocks resolved
    posted_text = client.post_tweet.await_args.args[0]
    assert "Sunny 72F" in posted_text and "BTC $64k" in posted_text and "static tail" in posted_text


@pytest.mark.asyncio
async def test_dynamic_block_passes_author_web_access_to_resolver():
    rt = _dynamic_runtime()
    doc = {"blocks": [{
        "text": "the current BTC price", "flags": [], "dynamic": True, "fallback": "x",
        "domains": "coindesk.com, kraken.com", "maxFetches": 9,
    }]}
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "t", "tweet_url": "u"}))
    rb = AsyncMock(return_value="BTC $64k")
    with patch.object(scheduler.posts_db, "list_due",
                      AsyncMock(return_value=[_due_row(doc=doc, recurrence=None, cease_at=None)])), \
         patch.object(scheduler.posts_db, "mark_sent", AsyncMock()), \
         patch.object(scheduler, "_owner_voice", AsyncMock(return_value=("", []))), \
         patch("excalibur_mcp.resolve.resolve_block", rb), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        await scheduler.process_due_posts(rt)
    kwargs = rb.await_args.kwargs
    assert kwargs["allowed_domains"] == ["coindesk.com", "kraken.com"]
    assert kwargs["max_fetches"] == 9


@pytest.mark.asyncio
async def test_dynamic_recurring_snapshots_static_keeps_template_dynamic():
    """The crux of the two-row model: a RECURRING post with a dynamic block fires
    to a STATIC snapshot (resolved text, no dynamic flag) that back-links to the
    template, while the template itself keeps its dynamic doc for the next fire.
    ``mark_sent`` has no doc/text_cache param, so the template's blocks are
    structurally untouchable — the recurrence never loses its dynamic prompt."""
    rt = _dynamic_runtime()
    url = "https://x.com/i/status/twd"
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "twd", "tweet_url": url}))
    with patch.object(scheduler.posts_db, "list_due",
                      AsyncMock(return_value=[_due_row(doc=_DYNAMIC_DOC, publish_at="2026-07-10T12:00:00+00:00")])), \
         patch.object(scheduler.posts_db, "mark_sent", AsyncMock()) as mark, \
         patch.object(scheduler.posts_db, "create_sent_occurrence", AsyncMock()) as occ, \
         patch.object(scheduler, "_owner_voice", AsyncMock(return_value=("", []))), \
         patch("excalibur_mcp.resolve.resolve_block", AsyncMock(return_value="BTC at $64,000")), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await scheduler.process_due_posts(rt)
    assert len(out["posted"]) == 1
    # the snapshot is STATIC (dynamic block frozen to resolved text, flag dropped) …
    occ.assert_awaited_once()
    snap_blocks = occ.await_args.kwargs["doc"]["blocks"]
    assert not any(b.get("dynamic") for b in snap_blocks)
    assert occ.await_args.kwargs["text_cache"] == "Markets update.\n\nBTC at $64,000"
    # … and back-links to the template ("p1")
    assert occ.await_args.kwargs["template_id"] == "p1"
    # the template just advances — mark_sent's signature can't carry a doc, so the
    # template's dynamic blocks are preserved by construction
    assert mark.await_args.args[2] == "scheduled"
    assert len(mark.await_args.args) == 5  # (pid, sent_at, status, next_publish, tweet_url) — no doc


@pytest.mark.asyncio
async def test_dynamic_insufficient_balance_for_resolve_holds(_stub_mark_attempt):
    rt = _runtime(billing={"success": False, "error_code": "insufficient_balance"})
    rt.load_credentials = AsyncMock(return_value={"anthropic_api_key": "k"})
    client = SimpleNamespace(post_tweet=AsyncMock())
    with patch.object(scheduler.posts_db, "list_due", AsyncMock(return_value=[_due_row(doc=_DYNAMIC_DOC)])), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await scheduler.process_due_posts(rt)
    assert out["skipped"][0]["reason"] == "insufficient_balance_resolve"
    client.post_tweet.assert_not_awaited()


# -- tick budget -------------------------------------------------------------
#
# The edge in front of the MCP cuts a request at a MEASURED ~128s (two ticks died
# at 129.7s / 131.2s on 2026-07-25). A tick that runs past it dies with nothing
# recorded and re-wedges on every cron, so the loop works to a deadline and hands
# the remainder to the next tick.

def test_resolve_timeout_clamps_author_budget_to_the_ceiling():
    full = scheduler.TICK_BUDGET_S  # a whole tick still ahead of us
    # A 900s block (the interactive maximum) can't take a tick down with it.
    assert scheduler._resolve_timeout(900, full) == scheduler.RESOLVE_BUDGET_S
    # An author asking for less than the ceiling keeps their smaller budget.
    assert scheduler._resolve_timeout(20, full) == 20.0
    # No stated budget → the scheduler's own ceiling.
    assert scheduler._resolve_timeout(None, full) == scheduler.RESOLVE_BUDGET_S
    # Garbage in the doc must not crash a fire.
    assert scheduler._resolve_timeout("soon", full) == scheduler.RESOLVE_BUDGET_S
    # The ceiling must leave room inside a tick for the X call and the writes
    # that follow the last resolve — otherwise one block eats the whole budget.
    assert scheduler.RESOLVE_BUDGET_S < scheduler.TICK_BUDGET_S


def test_resolve_timeout_never_exceeds_what_is_left_of_the_tick():
    # What remains of the tick wins over both the author's ask and the ceiling.
    assert scheduler._resolve_timeout(900, 12.0) == 12.0
    assert scheduler._resolve_timeout(5, 12.0) == 5.0
    # Never zero or negative, even past the deadline.
    assert scheduler._resolve_timeout(900, -30.0) == 1.0


@pytest.mark.asyncio
async def test_tick_defers_remaining_posts_once_the_budget_is_spent(_stub_claim_due_post):
    """A slow first post must not drag the rest of the queue past the deadline.
    The leftovers stay UNCLAIMED so the next tick finds them plainly scheduled."""
    rt = _runtime()
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "t", "tweet_url": "u"}))
    rows = [_due_row(post_id=f"p{i}", recurrence=None, cease_at=None) for i in range(3)]
    # First post burns the whole budget; the clock is read, never really waited.
    ticks = iter([0.0, 0.0, 1000.0, 1000.0, 1000.0, 1000.0])
    with patch.object(scheduler.posts_db, "list_due", AsyncMock(return_value=rows)), \
         patch.object(scheduler.posts_db, "mark_sent", AsyncMock()), \
         patch.object(scheduler.time, "monotonic", lambda: next(ticks)), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await scheduler.process_due_posts(rt)

    # The first post still fired — the budget can never starve the head of the queue.
    assert [p["post_id"] for p in out["posted"]] == ["p0"]
    # The other two are reported as deferred, with their owner, not silently dropped.
    assert [d["post_id"] for d in out["deferred"]] == ["p1", "p2"]
    assert {d["reason"] for d in out["deferred"]} == {"tick_budget_exhausted"}
    assert all(d["owner"] == NPUB for d in out["deferred"])
    # …and were never claimed, so they stay `scheduled` for the next tick.
    assert [c.args[0] for c in _stub_claim_due_post.await_args_list] == ["p0"]
    assert client.post_tweet.await_count == 1


@pytest.mark.parametrize("status,detail", [(401, "Unauthorized"), (403, "Forbidden")])
@pytest.mark.asyncio
async def test_rejected_x_token_holds_and_never_pauses(
    _stub_mark_attempt, _stub_mark_paused, status, detail,
):
    """A 401/403 must HOLD, not pause — it looks terminal and isn't.

    The SDK refreshes only when its own ``expires_at`` says the token is stale,
    so X rotating a refresh token out from under us yields a rejected token while
    our bookkeeping still reads fresh. That heals on the next refresh with no
    human involved — observed 2026-07-25, when a post that 401'd at 23:00 posted
    cleanly an hour later. Pausing would have stranded it awaiting a Resume it
    never needed. Only a 402 (the owner's own lapsed X subscription) pauses."""
    rt = _runtime()
    client = SimpleNamespace(post_tweet=AsyncMock(side_effect=XAPIError(status, detail)))
    with patch.object(scheduler.posts_db, "list_due", AsyncMock(return_value=[_due_row()])), \
         patch.object(scheduler.posts_db, "mark_sent", AsyncMock()) as mark, \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await scheduler.process_due_posts(rt)

    assert out["errors"] and "paused" not in out["errors"][0]  # held, still scheduled
    assert str(status) in out["errors"][0]["reason"]
    rt.rollback_debit.assert_awaited_once()  # the owner is made whole
    _stub_mark_paused.assert_not_awaited()  # NOT paused — it retries and self-heals
    _stub_mark_attempt.assert_awaited_once()
    mark.assert_not_called()


@pytest.mark.asyncio
async def test_transient_x_failure_still_only_holds(_stub_mark_attempt, _stub_mark_paused):
    """The pause is reserved for what the next tick can't fix — a 500 is exactly
    the kind of blip that SHOULD be retried, so it stays scheduled."""
    rt = _runtime()
    client = SimpleNamespace(post_tweet=AsyncMock(side_effect=XAPIError(500, "server error")))
    with patch.object(scheduler.posts_db, "list_due", AsyncMock(return_value=[_due_row()])), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await scheduler.process_due_posts(rt)
    assert out["errors"] and "paused" not in out["errors"][0]
    _stub_mark_paused.assert_not_awaited()
    _stub_mark_attempt.assert_awaited_once()


# -- fallback visibility -----------------------------------------------------
#
# Substituting a block's fallback changes what the world reads. That used to
# leave no trace but a log line: the run reported a clean `posted` while the
# tweet carried different words than the author wrote.

def test_fallback_reason_separates_our_budget_from_their_outage():
    """The distinction worth recording: did WE cut it short, or did the provider
    fail? The first is a tuning question, the second is an outage."""
    assert scheduler._fallback_reason(TimeoutError("slow"), 85.0) == "resolve_timed_out_at_85s"
    assert scheduler._fallback_reason(Exception("credit balance too low"), 85) == "operator_llm_unfunded"
    assert scheduler._fallback_reason(Exception("429 rate limited"), 85) == "upstream_rate_limited"
    assert scheduler._fallback_reason(ValueError("boom"), 85) == "resolve_failed:ValueError"


@pytest.mark.asyncio
async def test_timed_out_block_posts_fallback_and_records_why():
    """The tweet still goes out on the author's fallback (their choice), but the
    run now says the prompt never made it — with the budget that cut it, so the
    ceiling can be judged against real evidence instead of guessed at."""
    rt = _dynamic_runtime()
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "t", "tweet_url": "u"}))
    with patch.object(scheduler.posts_db, "list_due", AsyncMock(return_value=[_due_row(doc=_DYNAMIC_DOC)])), \
         patch.object(scheduler.posts_db, "mark_sent", AsyncMock()), \
         patch.object(scheduler.posts_db, "create_sent_occurrence", AsyncMock()), \
         patch.object(scheduler, "_owner_voice", AsyncMock(return_value=("", []))), \
         patch("excalibur_mcp.resolve.resolve_block", AsyncMock(side_effect=TimeoutError("too slow"))), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await scheduler.process_due_posts(rt)

    assert len(out["posted"]) == 1  # the post still went out
    notes = out["posted"][0]["fallbacks"]
    assert len(notes) == 1
    assert notes[0]["reason"].startswith("resolve_timed_out_at_")
    assert notes[0]["budget_s"] > 0  # the ceiling that cut it, for judging later
    # the author's fallback is what actually reached X, not their prompt
    posted_text = client.post_tweet.await_args.args[0]
    assert "Markets moving fast." in posted_text
    assert "BTC/USD" not in posted_text


@pytest.mark.asyncio
async def test_successful_resolve_records_no_fallback_noise():
    """A clean run must stay clean — no empty `fallbacks` key on every post."""
    rt = _dynamic_runtime()
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "t", "tweet_url": "u"}))
    with patch.object(scheduler.posts_db, "list_due", AsyncMock(return_value=[_due_row(doc=_DYNAMIC_DOC)])), \
         patch.object(scheduler.posts_db, "mark_sent", AsyncMock()), \
         patch.object(scheduler.posts_db, "create_sent_occurrence", AsyncMock()), \
         patch.object(scheduler, "_owner_voice", AsyncMock(return_value=("", []))), \
         patch("excalibur_mcp.resolve.resolve_block", AsyncMock(return_value="BTC at $64,000")), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await scheduler.process_due_posts(rt)
    assert "fallbacks" not in out["posted"][0]
