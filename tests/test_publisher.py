"""Publisher tests — recurrence math and one post's journey to X.

``publish_one`` is exercised with everything faked: the post row, the X client
resolution, the wheel's pricing/billing methods, and the post-row writes. We
assert the money + lifecycle rules: charge then post, refund whenever the post
doesn't go out, hold on a situation a later tick can retry, pause only on one
the owner must fix, and reschedule vs retire correctly.
"""

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest

from excalibur_mcp import publisher
from excalibur_mcp.x_client import XAPIError

NPUB = "npub1l94pd4qu4eszrl6ek032ftcnsu3tt9a7xvq2zp7eaxeklp6mrpzssmq8pf"


@pytest.fixture(autouse=True)
def _stub_record():
    """Every exit from publish_one appends its outcome to the audit ring; keep
    that off Neon and expose the mock so a test can assert it was recorded."""
    with patch.object(publisher.scheduler_runs, "record_run", AsyncMock()) as rec:
        yield rec


@pytest.fixture(autouse=True)
def _stub_mark_attempt():
    """A held post is stamped (last_attempt_at/reason) so it never sits silently."""
    with patch.object(publisher.posts_db, "mark_attempt", AsyncMock()) as m:
        yield m


@pytest.fixture(autouse=True)
def _stub_mark_paused():
    """A paused post is stamped the same way, in a stop-state."""
    with patch.object(publisher.posts_db, "mark_paused", AsyncMock()) as m:
        yield m


# -- recurrence math ---------------------------------------------------------

def test_add_months_clamps_end_of_month():
    d = datetime(2026, 1, 31, 12, 0, tzinfo=timezone.utc)
    assert publisher._add_months(d, 1).date().isoformat() == "2026-02-28"


def test_advance_units():
    d = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)
    assert publisher._advance(d, {"freq": "daily", "interval": 3}).day == 4
    assert publisher._advance(d, {"freq": "weekly", "interval": 1}).day == 8
    assert publisher._advance(d, {"freq": "hourly"}) is None


def test_advance_weekdays_skips_weekend():
    # 2026-06-05 is a Friday. One business day forward lands on Monday 06-08,
    # never Saturday/Sunday; the time of day is preserved.
    fri = datetime(2026, 6, 5, 9, 30, tzinfo=timezone.utc)
    nxt = publisher._advance(fri, {"freq": "weekdays", "interval": 1})
    assert nxt.date().isoformat() == "2026-06-08" and nxt.hour == 9 and nxt.minute == 30
    assert publisher._advance(fri, {"freq": "weekdays", "interval": 5}).date().isoformat() == "2026-06-12"


def test_advance_weekdays_never_lands_on_weekend():
    cur = datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc)  # Monday
    for _ in range(40):
        cur = publisher._advance(cur, {"freq": "weekdays", "interval": 1})
        assert cur.weekday() < 5  # Mon=0 .. Fri=4, never Sat(5)/Sun(6)


def test_next_state_no_recurrence_retires():
    d = datetime(2026, 6, 1, tzinfo=timezone.utc)
    assert publisher._next_state(d, None, None) == ("sent", None)


def test_next_state_past_cease_retires():
    d = datetime(2026, 6, 1, tzinfo=timezone.utc)
    status, nxt = publisher._next_state(d, {"freq": "daily", "interval": 1}, "2026-06-01T06:00:00+00:00")
    assert status == "sent" and nxt is None


def test_next_state_reschedules_within_cease():
    d = datetime(2026, 6, 1, tzinfo=timezone.utc)
    status, nxt = publisher._next_state(d, {"freq": "daily", "interval": 1}, "2026-12-31T00:00:00+00:00")
    assert status == "scheduled" and nxt is not None


def test_as_dict_handles_string_jsonb():
    assert publisher._as_dict('{"freq": "daily"}') == {"freq": "daily"}
    assert publisher._as_dict({"freq": "weekly"}) == {"freq": "weekly"}
    assert publisher._as_dict(None) is None


# -- one publication ---------------------------------------------------------

def _runtime(*, billing=5, pricing=(5, None)):
    rt = SimpleNamespace()
    rt._resolve_pricing = AsyncMock(return_value=pricing)
    rt._apply_billing = AsyncMock(return_value=billing)
    rt.rollback_debit = AsyncMock()
    return rt


def _dynamic_runtime():
    rt = _runtime()
    rt.load_credentials = AsyncMock(return_value={"llm_api_key": "k"})
    return rt


def _row(**over):
    row = {"post_id": "p1", "npub": NPUB, "text_cache": "hello world",
           "recurrence": {"freq": "daily", "interval": 1}, "cease_at": "2026-12-31T00:00:00+00:00"}
    row.update(over)
    return row


def _claimed(**over):
    """Patch the publisher's own read of the row it was handed."""
    return patch.object(publisher.posts_db, "get_claimed", AsyncMock(return_value=_row(**over)))


_DYNAMIC_DOC = {"blocks": [
    {"text": "Markets update.", "flags": []},
    {"text": "the BTC/USD price now", "flags": [], "dynamic": True, "fallback": "Markets moving fast."},
]}


@pytest.mark.asyncio
async def test_recurring_publication_snapshots_occurrence_and_advances(_stub_record):
    rt = _runtime()
    url = "https://x.com/i/status/tw1"
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "tw1", "tweet_url": url}))
    with _claimed(doc={"blocks": []}, last_attempt_at="2026-07-30 20:30:20+00"), \
         patch.object(publisher.posts_db, "record_occurrence_and_advance",
                      AsyncMock(return_value=True)) as occ, \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await publisher.publish_one(rt, "p1")

    assert out["outcome"] == "posted" and out["tweet_url"] == url
    rt._apply_billing.assert_awaited_once()
    # recurring → occurrence snapshot AND template advance, in ONE call. Two
    # awaits here is the bug: a publisher died between them and the post was
    # re-fired, tweeting the same slot twice.
    occ.assert_awaited_once()
    assert occ.await_args.kwargs["tweet_url"] == url
    assert occ.await_args.kwargs["npub"] == NPUB
    assert occ.await_args.kwargs["template_id"] == "p1"
    # …fenced by the claim we were handed, so a re-claim invalidates our write.
    assert occ.await_args.kwargs["claim_stamp"] == "2026-07-30 20:30:20+00"
    rt.rollback_debit.assert_not_awaited()
    # the publication records its own outcome — nothing else has to
    _stub_record.assert_awaited_once()
    assert _stub_record.await_args.args[0]["kind"] == "publication"


@pytest.mark.asyncio
async def test_one_shot_publication_marks_row_sent_with_url():
    rt = _runtime()
    url = "https://x.com/i/status/tw2"
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "tw2", "tweet_url": url}))
    with _claimed(recurrence=None, cease_at=None), \
         patch.object(publisher.posts_db, "mark_sent", AsyncMock(return_value=True)) as mark, \
         patch.object(publisher.posts_db, "record_occurrence_and_advance", AsyncMock()) as occ, \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await publisher.publish_one(rt, "p1")
    assert out["outcome"] == "posted"
    occ.assert_not_called()  # one-shot leaves no separate occurrence
    assert mark.await_args.args[2] == "sent"
    assert mark.await_args.args[4] == url


# ---------------------------------------------------------------------------
# The claim fence — a publisher that lost its claim must not pretend otherwise
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_recurring_publication_that_lost_its_claim_says_so(_stub_record):
    """The 2026-07-30 shape: we tweeted, but another tick owns the post now.

    Nothing can un-send a tweet, so the only honest outcome is to refuse to write
    over the new owner and report it. Reporting "posted" here is exactly how the
    duplicate went unnoticed — the second firing looked like the only firing.
    """
    rt = _runtime()
    url = "https://x.com/i/status/tw3"
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "tw3", "tweet_url": url}))
    with _claimed(doc={"blocks": []}), \
         patch.object(publisher.posts_db, "record_occurrence_and_advance",
                      AsyncMock(return_value=False)), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await publisher.publish_one(rt, "p1")

    assert out["outcome"] == "posted_claim_lost"
    assert out["tweet_url"] == url          # the tweet is real; don't hide it
    assert out["reason"] == "claim_reassigned_mid_publish"
    rt.rollback_debit.assert_not_awaited()  # the post DID go out — no refund


@pytest.mark.asyncio
async def test_one_shot_publication_that_lost_its_claim_says_so(_stub_record):
    """Same rule on the one-shot path — the fence is not recurring-only."""
    rt = _runtime()
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "t", "tweet_url": "u"}))
    with _claimed(recurrence=None, cease_at=None), \
         patch.object(publisher.posts_db, "mark_sent", AsyncMock(return_value=False)), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await publisher.publish_one(rt, "p1")

    assert out["outcome"] == "posted_claim_lost"


def test_claim_lease_outlives_the_cron_period():
    """The arithmetic that caused the double-post, asserted so it cannot return.

    A lease shorter than the cron period is not crash recovery — it guarantees
    every in-flight publisher is declared dead by the very next tick. At 20
    minutes against a 30-minute cron there was no margin whatsoever.
    """
    import re
    from pathlib import Path

    from excalibur_mcp.db import posts as posts_db

    lease_min = int(re.search(r"(\d+) minutes", posts_db._CLAIM_LEASE).group(1))

    wrangler = Path(__file__).resolve().parent.parent / "scheduler-worker" / "wrangler.toml"
    crons = re.search(r'crons\s*=\s*\["\*/(\d+) ', wrangler.read_text()).group(1)
    cron_min = int(crons)

    assert lease_min > cron_min, (
        f"claim lease ({lease_min} min) must exceed the cron period ({cron_min} min); "
        "otherwise every tick re-fires posts whose publishers are still working"
    )


@pytest.mark.asyncio
async def test_vanished_post_is_recorded_not_crashed(_stub_record):
    """The row can disappear between claim and publication (deleted by its
    owner). That is an outcome, not an exception."""
    rt = _runtime()
    with patch.object(publisher.posts_db, "get_claimed", AsyncMock(return_value=None)):
        out = await publisher.publish_one(rt, "gone-id")
    assert out["outcome"] == "gone"
    _stub_record.assert_awaited_once()


@pytest.mark.asyncio
async def test_insufficient_balance_holds_without_posting(_stub_mark_attempt):
    rt = _runtime(billing={"success": False, "error_code": "insufficient_balance"})
    client = SimpleNamespace(post_tweet=AsyncMock())
    with _claimed(), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await publisher.publish_one(rt, "p1")
    assert out["outcome"] == "held" and out["reason"] == "insufficient_balance"
    client.post_tweet.assert_not_awaited()
    _stub_mark_attempt.assert_awaited_once()  # stamped, never silently scheduled


@pytest.mark.asyncio
@pytest.mark.parametrize("code", [
    "oauth_token_expired",
    # X didn't answer the token refresh, so nothing is known about the session.
    # It must hold (a later tick retries) and never pause — a paused post waits
    # for a human, and there is nothing here for a human to do.
    "oauth_refresh_unavailable",
])
async def test_oauth_unavailable_holds_without_billing(code):
    rt = _runtime()
    situation = {"success": False, "error_code": code}
    with _claimed(), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(None, situation))):
        out = await publisher.publish_one(rt, "p1")
    assert out["outcome"] == "held" and out["reason"] == code
    rt._apply_billing.assert_not_awaited()  # never charged for work we can't do


@pytest.mark.asyncio
async def test_post_failure_refunds_owner():
    rt = _runtime()
    client = SimpleNamespace(post_tweet=AsyncMock(side_effect=RuntimeError("boom")))
    with _claimed(), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await publisher.publish_one(rt, "p1")
    assert out["outcome"] == "held"
    rt.rollback_debit.assert_awaited_once()


@pytest.mark.asyncio
async def test_402_pauses_post_and_refunds(_stub_mark_attempt, _stub_mark_paused):
    """A 402 (the owner's X subscription lapsed) is non-transient: refund, PAUSE
    so list_due stops returning it, and report — never leave it scheduled to
    re-fire and re-bill every tick."""
    rt = _runtime()
    client = SimpleNamespace(post_tweet=AsyncMock(side_effect=XAPIError(402, "subscription lapsed")))
    with _claimed(), \
         patch.object(publisher.posts_db, "mark_sent", AsyncMock()) as mark, \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await publisher.publish_one(rt, "p1")
    assert out["outcome"] == "paused" and "x_api_error" in out["reason"]
    rt.rollback_debit.assert_awaited_once()
    _stub_mark_paused.assert_awaited_once()
    _stub_mark_attempt.assert_not_awaited()
    mark.assert_not_called()


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
    never needed. Only a 402 pauses."""
    rt = _runtime()
    client = SimpleNamespace(post_tweet=AsyncMock(side_effect=XAPIError(status, detail)))
    with _claimed(), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await publisher.publish_one(rt, "p1")
    assert out["outcome"] == "held" and str(status) in out["reason"]
    rt.rollback_debit.assert_awaited_once()  # the owner is made whole
    _stub_mark_paused.assert_not_awaited()  # NOT paused — it retries and self-heals
    _stub_mark_attempt.assert_awaited_once()


@pytest.mark.asyncio
async def test_transient_x_failure_only_holds(_stub_mark_paused):
    """The pause is reserved for what no retry can fix — a 500 is exactly the
    kind of blip that SHOULD be retried."""
    rt = _runtime()
    client = SimpleNamespace(post_tweet=AsyncMock(side_effect=XAPIError(500, "server error")))
    with _claimed(), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await publisher.publish_one(rt, "p1")
    assert out["outcome"] == "held"
    _stub_mark_paused.assert_not_awaited()


@pytest.mark.asyncio
async def test_empty_text_cache_held_early():
    rt = _runtime()
    client = SimpleNamespace(post_tweet=AsyncMock())
    with _claimed(text_cache="", doc=None), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await publisher.publish_one(rt, "p1")
    assert out["outcome"] == "held" and out["reason"] == "empty_text_cache"
    rt._apply_billing.assert_not_awaited()


# -- dynamic blocks ----------------------------------------------------------

@pytest.mark.asyncio
async def test_dynamic_block_resolved_then_posted():
    rt = _dynamic_runtime()
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "tw9", "tweet_url": "u"}))
    with _claimed(doc=_DYNAMIC_DOC, recurrence=None, cease_at=None), \
         patch.object(publisher.posts_db, "mark_sent", AsyncMock()) as mark, \
         patch.object(publisher, "_owner_voice", AsyncMock(return_value=("", []))), \
         patch("excalibur_mcp.resolve.resolve_block", AsyncMock(return_value="BTC at $64,000")), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await publisher.publish_one(rt, "p1")
    assert out["outcome"] == "posted"
    posted_text = client.post_tweet.await_args.args[0]
    assert "Markets update." in posted_text and "BTC at $64,000" in posted_text
    assert rt._apply_billing.await_count == 2  # resolve fare + post fare
    assert mark.await_args.args[2] == "sent"
    rt.rollback_debit.assert_not_awaited()


@pytest.mark.asyncio
async def test_author_runtime_limit_is_honored_not_clipped():
    """The whole point of publishing as a background job: a block gets the time
    its author asked for, because no HTTP request is waiting on it."""
    rt = _dynamic_runtime()
    doc = {"blocks": [{"text": "a long research prompt", "flags": [], "dynamic": True,
                       "fallback": "x", "runtimeLimit": 600}]}
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "t", "tweet_url": "u"}))
    rb = AsyncMock(return_value="deep answer")
    with _claimed(doc=doc, recurrence=None, cease_at=None), \
         patch.object(publisher.posts_db, "mark_sent", AsyncMock()), \
         patch.object(publisher, "_owner_voice", AsyncMock(return_value=("", []))), \
         patch("excalibur_mcp.resolve.resolve_block", rb), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        await publisher.publish_one(rt, "p1")
    assert rb.await_args.kwargs["timeout_seconds"] == 600


@pytest.mark.asyncio
async def test_dynamic_resolve_failure_uses_fallback_and_records_why():
    """The tweet still goes out on the author's fallback (their choice), but the
    outcome says the prompt never made it — with the budget that bounded it."""
    rt = _dynamic_runtime()
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "t", "tweet_url": "u"}))
    with _claimed(doc=_DYNAMIC_DOC, recurrence=None, cease_at=None), \
         patch.object(publisher.posts_db, "mark_sent", AsyncMock()), \
         patch.object(publisher, "_owner_voice", AsyncMock(return_value=("", []))), \
         patch("excalibur_mcp.resolve.resolve_block", AsyncMock(side_effect=TimeoutError("slow"))), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await publisher.publish_one(rt, "p1")

    assert out["outcome"] == "posted"
    notes = out["fallbacks"]
    assert len(notes) == 1 and notes[0]["reason"].startswith("resolve_timed_out_at_")
    assert notes[0]["budget_s"] > 0
    posted_text = client.post_tweet.await_args.args[0]
    assert "Markets moving fast." in posted_text and "BTC/USD" not in posted_text


@pytest.mark.asyncio
async def test_successful_resolve_records_no_fallback_noise():
    """A clean publication stays clean — no empty `fallbacks` key."""
    rt = _dynamic_runtime()
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "t", "tweet_url": "u"}))
    with _claimed(doc=_DYNAMIC_DOC, recurrence=None, cease_at=None), \
         patch.object(publisher.posts_db, "mark_sent", AsyncMock()), \
         patch.object(publisher, "_owner_voice", AsyncMock(return_value=("", []))), \
         patch("excalibur_mcp.resolve.resolve_block", AsyncMock(return_value="BTC at $64,000")), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await publisher.publish_one(rt, "p1")
    assert "fallbacks" not in out


@pytest.mark.asyncio
async def test_dynamic_resolve_failure_no_fallback_holds_and_refunds(_stub_mark_attempt):
    rt = _dynamic_runtime()
    doc = {"blocks": [{"text": "the price now", "flags": [], "dynamic": True}]}  # no fallback
    client = SimpleNamespace(post_tweet=AsyncMock())
    with _claimed(doc=doc), \
         patch.object(publisher.posts_db, "mark_sent", AsyncMock()) as mark, \
         patch.object(publisher, "_owner_voice", AsyncMock(return_value=("", []))), \
         patch("excalibur_mcp.resolve.resolve_block", AsyncMock(side_effect=RuntimeError("down"))), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await publisher.publish_one(rt, "p1")
    assert out["outcome"] == "held" and out["reason"] == "dynamic_resolve_failed"
    client.post_tweet.assert_not_awaited()  # never post a gap
    mark.assert_not_called()
    rt.rollback_debit.assert_awaited_once()  # resolve fare refunded
    assert rt._apply_billing.await_count == 1  # post fare never charged


@pytest.mark.asyncio
async def test_multiple_dynamic_blocks_resolve_in_parallel():
    rt = _dynamic_runtime()
    doc = {"blocks": [
        {"text": "weather now", "flags": [], "dynamic": True, "fallback": "fa"},
        {"text": "btc price now", "flags": [], "dynamic": True, "fallback": "fb"},
        {"text": "static tail", "flags": []},
    ]}
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "t", "tweet_url": "u"}))
    rb = AsyncMock(side_effect=["Sunny 72F", "BTC $64k"])
    with _claimed(doc=doc, recurrence=None, cease_at=None), \
         patch.object(publisher.posts_db, "mark_sent", AsyncMock()), \
         patch.object(publisher, "_owner_voice", AsyncMock(return_value=("", []))), \
         patch("excalibur_mcp.resolve.resolve_block", rb), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await publisher.publish_one(rt, "p1")
    assert out["outcome"] == "posted" and rb.await_count == 2
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
    with _claimed(doc=doc, recurrence=None, cease_at=None), \
         patch.object(publisher.posts_db, "mark_sent", AsyncMock()), \
         patch.object(publisher, "_owner_voice", AsyncMock(return_value=("", []))), \
         patch("excalibur_mcp.resolve.resolve_block", rb), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        await publisher.publish_one(rt, "p1")
    assert rb.await_args.kwargs["allowed_domains"] == ["coindesk.com", "kraken.com"]
    assert rb.await_args.kwargs["max_fetches"] == 9


@pytest.mark.asyncio
async def test_dynamic_recurring_snapshots_static_keeps_template_dynamic():
    """A RECURRING post with a dynamic block fires to a STATIC snapshot (resolved
    text, no dynamic flag) back-linked to the template, while the template keeps
    its dynamic doc for the next fire."""
    rt = _dynamic_runtime()
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "twd", "tweet_url": "u"}))
    with _claimed(doc=_DYNAMIC_DOC, publish_at="2026-07-10T12:00:00+00:00"), \
         patch.object(publisher.posts_db, "record_occurrence_and_advance",
                      AsyncMock(return_value=True)) as occ, \
         patch.object(publisher, "_owner_voice", AsyncMock(return_value=("", []))), \
         patch("excalibur_mcp.resolve.resolve_block", AsyncMock(return_value="BTC at $64,000")), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await publisher.publish_one(rt, "p1")
    assert out["outcome"] == "posted"
    snap_blocks = occ.await_args.kwargs["doc"]["blocks"]
    assert not any(b.get("dynamic") for b in snap_blocks)
    assert occ.await_args.kwargs["text_cache"] == "Markets update.\n\nBTC at $64,000"
    assert occ.await_args.kwargs["template_id"] == "p1"
    # The template advances inside the SAME call — it is not passed a doc, so the
    # dynamic original is preserved by construction rather than by care.
    assert "doc" not in {k for k in occ.await_args.kwargs if k == "template_doc"}
    assert occ.await_args.kwargs["next_publish_at"] is not None


@pytest.mark.asyncio
async def test_dynamic_insufficient_balance_for_resolve_holds(_stub_mark_attempt):
    rt = _runtime(billing={"success": False, "error_code": "insufficient_balance"})
    rt.load_credentials = AsyncMock(return_value={"llm_api_key": "k"})
    client = SimpleNamespace(post_tweet=AsyncMock())
    with _claimed(doc=_DYNAMIC_DOC), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await publisher.publish_one(rt, "p1")
    assert out["reason"] == "insufficient_balance"
    assert out["stage"] == "resolve"  # which charge refused, without faking the reason
    client.post_tweet.assert_not_awaited()


@pytest.mark.asyncio
async def test_unreadable_ledger_is_not_reported_as_an_empty_wallet(_stub_mark_attempt):
    """``_apply_billing`` returns ``vault_unavailable`` when it could not read the
    ledger — charging nothing, precisely so a funded patron is never told they are
    broke. The publisher used to relabel it ``insufficient_balance``, which sent an
    owner holding 844 sats to go top up."""
    rt = _runtime(billing={"success": False, "error_code": "vault_unavailable"})
    rt.load_credentials = AsyncMock(return_value={"llm_api_key": "k"})
    client = SimpleNamespace(post_tweet=AsyncMock())
    with _claimed(doc=_DYNAMIC_DOC), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await publisher.publish_one(rt, "p1")
    assert out["reason"] == "vault_unavailable"
    assert out["outcome"] == "held"
    client.post_tweet.assert_not_awaited()


def test_fallback_reason_separates_the_blocks_budget_from_an_outage():
    assert publisher._fallback_reason(TimeoutError("slow"), 600.0) == "resolve_timed_out_at_600s"
    assert publisher._fallback_reason(Exception("credit balance too low"), 60) == "operator_llm_unfunded"
    assert publisher._fallback_reason(Exception("429 rate limited"), 60) == "upstream_rate_limited"
    assert publisher._fallback_reason(ValueError("boom"), 60) == "resolve_failed:ValueError"


def test_fallback_reason_names_an_empty_account_whoever_phrased_it():
    """This path holds only an exception string — no status code survives it — so
    an empty account here is recognised by wording alone. It read only the lab's
    phrasing before the wheel took over, which left a model router's exhausted
    account recorded in the audit ring as an anonymous failure."""
    assert publisher._fallback_reason(Exception("Insufficient credits"), 60) == "operator_llm_unfunded"
    assert publisher._fallback_reason(
        Exception("This request requires more credits than are available"), 60,
    ) == "operator_llm_unfunded"


# -- a hold always says why --------------------------------------------------
#
# `dict.get(k, default)` returns the STORED value when the key exists, so an
# upstream `{"error_code": None}` slips past the default and lands as a blank
# reason — a post that quietly didn't publish, which is the exact failure this
# service keeps relearning.

# -- Nostr companion notes ---------------------------------------------------
#
# A Nostr Post block is static copy that never enters the tweet; it is published
# instead as a companion note carrying the live X URL. The scheduler path bills
# and publishes each note AFTER the tweet is recorded sent, so a slow relay never
# delays the sent record and a relay miss never un-sends an already-live post.

_NOSTR_DOC = {"blocks": [
    {"text": "Fresh drop.", "flags": []},
    {"text": "Read the thread: {{tweet_url}}", "flags": [], "nostr": True},
]}


@pytest.mark.asyncio
async def test_nostr_block_excluded_from_tweet_and_note_published_with_url():
    """The companion copy never enters the tweet; it publishes as a note carrying
    the live X URL, after the tweet posts."""
    rt = _runtime()
    url = "https://x.com/i/status/twn"
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "twn", "tweet_url": url}))
    pub = Mock(return_value={"success": True, "event_id": "e1", "accepted": 2, "attempted": 3})
    with _claimed(doc=_NOSTR_DOC, recurrence=None, cease_at=None, text_cache="Fresh drop."), \
         patch.object(publisher.posts_db, "mark_sent", AsyncMock()), \
         patch("excalibur_mcp.nostr_note.publish_note", pub), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await publisher.publish_one(rt, "p1")
    assert out["outcome"] == "posted"
    # the tweet carried only the tweet copy, never the companion note text
    assert client.post_tweet.await_args.args[0] == "Fresh drop."
    # the note went out with the live URL substituted, scribed for the owner
    assert pub.call_args.args[0] == f"Read the thread: {url}"
    assert pub.call_args.args[1] == NPUB
    assert out["nostr"] == {"published": 1, "failed": []}


@pytest.mark.asyncio
@pytest.mark.parametrize("template,expected", [
    ("no token here", "no token here"),
    ("once: {{tweet_url}}", "once: U"),
    ("{{tweet_url}} and {{tweet_url}} again", "U and U again"),
])
async def test_nostr_url_substitution_zero_one_many(template, expected):
    rt = _runtime()
    doc = {"blocks": [{"text": "tweet", "flags": []},
                      {"text": template, "flags": [], "nostr": True}]}
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "t", "tweet_url": "U"}))
    pub = Mock(return_value={"success": True})
    with _claimed(doc=doc, recurrence=None, cease_at=None, text_cache="tweet"), \
         patch.object(publisher.posts_db, "mark_sent", AsyncMock()), \
         patch("excalibur_mcp.nostr_note.publish_note", pub), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        await publisher.publish_one(rt, "p1")
    assert pub.call_args.args[0] == expected


@pytest.mark.asyncio
async def test_nostr_note_never_published_when_tweet_fails():
    """A failed tweet leaves no URL to carry — the companion note is never sent."""
    rt = _runtime()
    client = SimpleNamespace(post_tweet=AsyncMock(side_effect=XAPIError(500, "server error")))
    pub = Mock(return_value={"success": True})
    with _claimed(doc=_NOSTR_DOC, text_cache="Fresh drop."), \
         patch.object(publisher.posts_db, "mark_sent", AsyncMock()), \
         patch("excalibur_mcp.nostr_note.publish_note", pub), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await publisher.publish_one(rt, "p1")
    assert out["outcome"] == "held"
    pub.assert_not_called()


@pytest.mark.asyncio
async def test_rejected_nostr_note_leaves_post_sent_and_refunds():
    """No relay accepted the note: the fare is refunded and the miss is reported
    in nostr.failed, but the already-live tweet stays sent — never held/paused."""
    rt = _runtime()
    url = "https://x.com/i/status/twr"
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "twr", "tweet_url": url}))
    pub = Mock(return_value={"success": False, "error": "no relay accepted"})
    with _claimed(doc=_NOSTR_DOC, recurrence=None, cease_at=None, text_cache="Fresh drop."), \
         patch.object(publisher.posts_db, "mark_sent", AsyncMock()) as mark, \
         patch("excalibur_mcp.nostr_note.publish_note", pub), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await publisher.publish_one(rt, "p1")
    assert out["outcome"] == "posted"
    assert mark.await_args.args[2] == "sent"
    assert out["nostr"]["published"] == 0 and len(out["nostr"]["failed"]) == 1
    rt.rollback_debit.assert_awaited_once()  # the note's fare is made whole


@pytest.mark.asyncio
async def test_nostr_pricing_denial_skips_note_but_keeps_post_sent():
    """A pricing denial on the note skips it and reports it; it never holds or
    pauses the post — the tweet is already out. Pricing succeeds for the tweet,
    then denies the note."""
    rt = _runtime()
    rt._resolve_pricing = AsyncMock(side_effect=[(5, None), (0, {"error_code": "pricing_unavailable"})])
    url = "https://x.com/i/status/twp"
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "twp", "tweet_url": url}))
    pub = Mock(return_value={"success": True})
    with _claimed(doc=_NOSTR_DOC, recurrence=None, cease_at=None, text_cache="Fresh drop."), \
         patch.object(publisher.posts_db, "mark_sent", AsyncMock()) as mark, \
         patch("excalibur_mcp.nostr_note.publish_note", pub), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await publisher.publish_one(rt, "p1")
    assert out["outcome"] == "posted" and mark.await_args.args[2] == "sent"
    pub.assert_not_called()  # the note was skipped, not published
    assert out["nostr"] == {"published": 0, "failed": [{"note": 0, "reason": "pricing_unavailable"}]}


@pytest.mark.asyncio
async def test_recurring_occurrence_snapshot_carries_substituted_note():
    """A recurring firing snapshots its own occurrence; the snapshot's Nostr block
    carries THIS occurrence's substituted URL, like rendered_blocks for dynamics."""
    rt = _runtime()
    url = "https://x.com/i/status/twc"
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "twc", "tweet_url": url}))
    pub = Mock(return_value={"success": True})
    with _claimed(doc=_NOSTR_DOC, text_cache="Fresh drop."), \
         patch.object(publisher.posts_db, "record_occurrence_and_advance",
                      AsyncMock(return_value=True)) as occ, \
         patch("excalibur_mcp.nostr_note.publish_note", pub), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await publisher.publish_one(rt, "p1")
    assert out["outcome"] == "posted"
    snap_blocks = occ.await_args.kwargs["doc"]["blocks"]
    nostr_snap = [b for b in snap_blocks if b.get("nostr")]
    assert nostr_snap and nostr_snap[0]["text"] == f"Read the thread: {url}"


@pytest.mark.asyncio
async def test_nostr_block_excluded_from_dynamic_tweet_text():
    """A post carrying both a dynamic and a Nostr block: the dynamic text enters
    the tweet, the Nostr copy never does — it publishes as its own note."""
    rt = _dynamic_runtime()
    doc = {"blocks": [
        {"text": "the BTC price now", "flags": [], "dynamic": True, "fallback": "fb"},
        {"text": "Companion note {{tweet_url}}", "flags": [], "nostr": True},
    ]}
    url = "https://x.com/i/status/twx"
    client = SimpleNamespace(post_tweet=AsyncMock(return_value={"tweet_id": "twx", "tweet_url": url}))
    pub = Mock(return_value={"success": True})
    with _claimed(doc=doc, recurrence=None, cease_at=None), \
         patch.object(publisher.posts_db, "mark_sent", AsyncMock()), \
         patch.object(publisher, "_owner_voice", AsyncMock(return_value=("", []))), \
         patch("excalibur_mcp.resolve.resolve_block", AsyncMock(return_value="BTC $64k")), \
         patch("excalibur_mcp.nostr_note.publish_note", pub), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        await publisher.publish_one(rt, "p1")
    posted_text = client.post_tweet.await_args.args[0]
    assert "BTC $64k" in posted_text and "Companion note" not in posted_text
    assert pub.call_args.args[0] == f"Companion note {url}"


def test_stated_falls_back_when_a_call_site_hands_over_nothing():
    assert publisher._stated("insufficient_balance", "p1") == "insufficient_balance"
    assert publisher._stated("  spaced  ", "p1") == "spaced"
    for blank in (None, "", "   "):
        assert publisher._stated(blank, "p1") == "unreported"


@pytest.mark.asyncio
async def test_situation_with_a_null_error_code_still_names_a_reason():
    """The shape that produced a bare '—' in the live log."""
    rt = _runtime()
    with _claimed(), \
         patch("excalibur_mcp.server._resolve_x_client",
               AsyncMock(return_value=(None, {"error_code": None}))):
        out = await publisher.publish_one(rt, "p1")
    assert out["outcome"] == "held"
    assert out["reason"] == "oauth_unavailable"  # not None, not ""


@pytest.mark.asyncio
async def test_exception_with_an_empty_message_is_named_by_its_type():
    """`str(RuntimeError())` is legitimately empty; the type still identifies it."""
    rt = _runtime()
    client = SimpleNamespace(post_tweet=AsyncMock(side_effect=RuntimeError()))
    with _claimed(), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await publisher.publish_one(rt, "p1")
    assert out["outcome"] == "held" and out["reason"] == "RuntimeError"


@pytest.mark.asyncio
async def test_no_hold_can_ever_record_a_blank_reason(_stub_record):
    """The backstop, asserted end to end: whatever a call site does, the row the
    reader sees names something."""
    rt = _runtime()
    with _claimed(), \
         patch("excalibur_mcp.server._resolve_x_client",
               AsyncMock(return_value=(None, {"error_code": ""}))):
        await publisher.publish_one(rt, "p1")
    recorded = _stub_record.await_args.args[0]
    assert recorded["reason"]  # non-empty, whatever path got us here
