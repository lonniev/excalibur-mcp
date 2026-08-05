"""Publisher tests — recurrence math and one post's journey to X.

``publish_one`` is exercised with everything faked: the post row, the X client
resolution, the wheel's pricing/billing methods, and the post-row writes. We
assert the money + lifecycle rules: charge then post, refund whenever the post
doesn't go out, hold on a situation a later tick can retry, pause only on one
the owner must fix, and reschedule vs retire correctly.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import httpx
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


@pytest.fixture(autouse=True)
def _stub_x_call_mark():
    """The compare-and-set that AUTHORIZES the call to X.

    Defaults to granted, so tests about everything downstream read normally.
    Note what its absence proved: unstubbed, every publication stopped before
    ``post_tweet`` — which is the gate behaving exactly as designed. A test that
    wants to exercise a refusal sets ``.return_value = False`` or a side effect.
    """
    with patch.object(
        publisher.posts_db, "mark_x_call_started", AsyncMock(return_value=True),
    ) as m:
        yield m


@pytest.fixture(autouse=True)
def _stub_release():
    """A held post goes back to the poster's queue, not the resolver's."""
    with patch.object(
        publisher.posts_db, "release_to_resolved", AsyncMock(return_value=True),
    ) as m:
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

    lease_min = int(re.search(r"(\d+) minutes", posts_db._SEND_LEASE).group(1))

    wrangler = Path(__file__).resolve().parent.parent / "scheduler-worker" / "wrangler.toml"
    crons = re.search(r'crons\s*=\s*\["\*/(\d+) ', wrangler.read_text())
    if crons is None:
        # No cron configured — the scheduler is deliberately halted (2026-08-04,
        # while resolution was writing over authored templates). The invariant is
        # vacuous with nothing firing, and un-skips itself the moment a schedule
        # is restored, which is exactly when it matters again.
        pytest.skip("scheduler-worker has no cron trigger; nothing fires to race a lease")
    cron_min = int(crons.group(1))

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
@pytest.mark.parametrize("exc", [
    httpx.ReadTimeout("timed out"),
    httpx.WriteTimeout("timed out"),
    httpx.RemoteProtocolError("server disconnected"),
    httpx.ReadError("connection reset"),
])
@pytest.mark.asyncio
async def test_delivered_but_unanswered_post_pauses_never_holds(
    exc, _stub_mark_attempt, _stub_mark_paused,
):
    """The request reached X; the answer never came. It must NOT be retried.

    Observed 2026-07-30: X created tweet …0735014637900 at 20:06:16, the read
    timed out, the post was HELD, and the 20:30 tick published the same content
    again as …7064064160148 — 25 minutes apart, with only the second recorded.

    A hold means "safe to try again", which is exactly what nobody knows here.
    Pausing costs a delayed post; holding costs a duplicate public one.
    """
    rt = _runtime()
    client = SimpleNamespace(post_tweet=AsyncMock(side_effect=exc))
    with _claimed(), \
         patch.object(publisher.posts_db, "mark_sent", AsyncMock()) as mark, \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await publisher.publish_one(rt, "p1")

    assert out["outcome"] == "paused", "a maybe-delivered post must never be held"
    assert out["reason"] == "x_post_outcome_unknown"
    _stub_mark_paused.assert_awaited_once()
    _stub_mark_attempt.assert_not_awaited()  # mark_attempt would leave it scheduled
    mark.assert_not_called()
    rt.rollback_debit.assert_awaited_once()


class TestNothingReachesXWithoutPermission:
    """The compare-and-set before `post_tweet` is the authorization, not a log
    line. Everything here pins a way the irreversible call could otherwise happen
    without durable evidence that it was about to."""

    @pytest.mark.asyncio
    async def test_an_unrecordable_mark_stops_the_post(self, _stub_x_call_mark):
        """The Neon-hiccup double-post. If the write's outcome is unknown and we
        post anyway, the row still reads `x_call_at IS NULL` and recovery later
        concludes nothing was sent — then sends it again."""
        rt = _runtime()
        _stub_x_call_mark.side_effect = RuntimeError("neon unreachable")
        client = SimpleNamespace(post_tweet=AsyncMock())
        with _claimed(), \
             patch("excalibur_mcp.server._resolve_x_client",
                   AsyncMock(return_value=(client, None))):
            out = await publisher.publish_one(rt, "p1")

        client.post_tweet.assert_not_awaited(), "never post without a durable mark"
        assert out["outcome"] == "held" and out["reason"] == "x_call_mark_unavailable"
        rt.rollback_debit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_a_superseded_publisher_stands_down_before_posting(
        self, _stub_x_call_mark, _stub_mark_attempt, _stub_mark_paused,
    ):
        """A worker that stalled in OAuth or billing while its row was reassigned
        must not post, and must not stamp state it no longer owns."""
        rt = _runtime()
        _stub_x_call_mark.return_value = False
        client = SimpleNamespace(post_tweet=AsyncMock())
        with _claimed(), \
             patch("excalibur_mcp.server._resolve_x_client",
                   AsyncMock(return_value=(client, None))):
            out = await publisher.publish_one(rt, "p1")

        client.post_tweet.assert_not_awaited()
        assert out["outcome"] == "claim_lost_before_post"
        _stub_mark_attempt.assert_not_awaited(), "the row belongs to someone else now"
        _stub_mark_paused.assert_not_awaited()
        rt.rollback_debit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_the_mark_is_taken_before_the_call(self, _stub_x_call_mark):
        """Order is the whole point. Reversed, every orphan would read 'nothing
        sent' and the sweep would repost tweets that are already live."""
        order: list[str] = []
        rt = _runtime()
        _stub_x_call_mark.side_effect = lambda *a, **k: (order.append("mark"), True)[1]

        async def _post(_text):
            order.append("post")
            return {"tweet_id": "1", "tweet_url": "u"}

        client = SimpleNamespace(post_tweet=_post)
        with _claimed(recurrence=None), \
             patch.object(publisher.posts_db, "mark_sent", AsyncMock(return_value=True)), \
             patch("excalibur_mcp.server._resolve_x_client",
                   AsyncMock(return_value=(client, None))):
            await publisher.publish_one(rt, "p1")

        assert order == ["mark", "post"]

    @pytest.mark.asyncio
    async def test_a_hold_returns_the_body_to_the_poster_and_carries_the_claim(
        self, _stub_mark_attempt, _stub_release,
    ):
        """A post-phase failure retries the post, not the resolve — and stamps
        only while we still own the row."""
        rt = _runtime()
        client = SimpleNamespace(
            post_tweet=AsyncMock(side_effect=XAPIError(429, "slow down")),
        )
        with _claimed(last_attempt_at="2026-08-02 01:30:20+00"), \
             patch("excalibur_mcp.server._resolve_x_client",
                   AsyncMock(return_value=(client, None))):
            out = await publisher.publish_one(rt, "p1")

        assert out["outcome"] == "held"
        _stub_release.assert_awaited_once()
        assert _stub_release.await_args.args[1] == "2026-08-02 01:30:20+00"
        assert _stub_mark_attempt.await_args.kwargs["claim_stamp"] == "2026-08-02 01:30:20+00"


@pytest.mark.asyncio
async def test_connect_failure_still_holds_because_nothing_was_sent(_stub_mark_attempt):
    """The counter-case that keeps the rule honest.

    A connect failure means the request never left — `_post_retrying_connect`
    already retried the one phase that is safe to retry. Nothing is ambiguous, so
    this stays a hold and the next tick simply tries again. Pausing here would
    strand a post for a blip.
    """
    rt = _runtime()
    client = SimpleNamespace(post_tweet=AsyncMock(side_effect=httpx.ConnectTimeout("no route")))
    with _claimed(), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await publisher.publish_one(rt, "p1")

    assert out["outcome"] == "held"
    assert out["reason"] != "x_post_outcome_unknown"


@pytest.mark.asyncio
async def test_402_pauses_post_and_refunds(_stub_mark_attempt, _stub_mark_paused):
    """A 402 (the owner's X subscription lapsed) is non-transient: refund, PAUSE
    so the work-lists stop returning it, and report — never leave it scheduled to
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
async def test_a_held_post_carries_the_situations_own_words(
    _stub_record, _stub_mark_attempt,
):
    """The reason is a code a machine reads; the detail is why, for a human.

    Recording only the code is how a grant killed by a lost renewal, an
    operator's rotated app secret, and a genuine expiry all reached the owner
    as the same four words — answered, every time, with a reconnect that could
    not have helped.
    """
    rt = _runtime()
    situation = {
        "success": False,
        "error_code": "oauth_refresh_token_lost",
        "detail": "A token renewal at 2026-07-31T15:14:58+00:00 was cut off.",
    }
    with _claimed(), \
         patch("excalibur_mcp.server._resolve_x_client",
               AsyncMock(return_value=(None, situation))):
        out = await publisher.publish_one(rt, "p1")

    assert out["outcome"] == "held"
    assert out["reason"] == "oauth_refresh_token_lost"
    assert "15:14:58" in out["detail"]
    # Stamped on the post row too, so the Posts tab can say it even if the
    # audit ring row is lost.
    assert _stub_mark_attempt.await_args.args[3] == situation["detail"]
    assert _stub_record.await_args.args[0]["detail"] == situation["detail"]


@pytest.mark.asyncio
async def test_a_situation_with_no_detail_falls_back_to_its_prose(
    _stub_mark_attempt,
):
    """Not every situation carries provider words; the recipe's own sentence is
    still better than a bare code."""
    rt = _runtime()
    situation = {
        "success": False,
        "error_code": "warming_up",
        "error": "The server is establishing its connection to the vault.",
    }
    with _claimed(), \
         patch("excalibur_mcp.server._resolve_x_client",
               AsyncMock(return_value=(None, situation))):
        out = await publisher.publish_one(rt, "p1")

    assert out["detail"] == situation["error"]


@pytest.mark.asyncio
async def test_a_bare_reason_records_no_empty_detail(_stub_mark_attempt):
    """An absent detail must not become an empty string in the log."""
    rt = _runtime()
    with _claimed(), \
         patch("excalibur_mcp.server._resolve_x_client",
               AsyncMock(return_value=(None, {"error_code": "oauth_unavailable"}))):
        out = await publisher.publish_one(rt, "p1")

    assert "detail" not in out
    assert _stub_mark_attempt.await_args.args[3] is None


@pytest.mark.asyncio
async def test_a_flaky_audit_write_is_retried_rather_than_lost(_stub_record):
    """On 2026-07-31 three ticks launched a publisher for the same post and the
    log showed only the launches. The posts were released correctly — it was the
    audit INSERT that failed, and it was swallowed, so a tick that dispatched
    work it never heard back from was indistinguishable from a dead publisher.
    """
    rt = _runtime()
    _stub_record.side_effect = [RuntimeError("neon hiccup"), None]
    with _claimed(), \
         patch("excalibur_mcp.server._resolve_x_client",
               AsyncMock(return_value=(None, {"error_code": "warming_up"}))):
        out = await publisher.publish_one(rt, "p1")

    assert _stub_record.await_count == 2, "the write is retried once"
    assert out["outcome"] == "held", "and the outcome still reaches the caller"


@pytest.mark.asyncio
async def test_an_audit_row_lost_twice_never_fails_the_publication(_stub_record):
    """Audit is a witness, not a gate. Losing it must not undo the work."""
    rt = _runtime()
    _stub_record.side_effect = RuntimeError("neon down")
    with _claimed(), \
         patch("excalibur_mcp.server._resolve_x_client",
               AsyncMock(return_value=(None, {"error_code": "warming_up"}))):
        out = await publisher.publish_one(rt, "p1")

    assert _stub_record.await_count == 2
    assert out["outcome"] == "held"


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


# ---------------------------------------------------------------------------
# Recurrence anchors on the SLOT, not on the success moment
# ---------------------------------------------------------------------------


class TestRecurrenceDoesNotDrift:
    """A weekly Sunday-morning post must stay Sunday morning.

    It did not. `_next_state` advanced from `sent_at` — the moment the post
    actually succeeded — so every delay (the tick's own 30-minute granularity,
    the model, X) was compounded into the next occurrence. Post 0314fe59 walked
    from Sunday morning to Wednesday evening that way.
    """

    def _sun(self, h=9, m=0, day=2):
        return datetime(2026, 8, day, h, m, tzinfo=timezone.utc)

    def test_weekly_advances_from_the_slot_not_the_send_time(self):
        slot = self._sun()                       # Sun 09:00
        sent = self._sun(h=9, m=37)              # actually went out 37 min late
        status, nxt = publisher._next_state(
            slot, {"freq": "weekly", "interval": 1}, None, now=sent,
        )
        assert status == "scheduled"
        assert nxt == datetime(2026, 8, 9, 9, 0, tzinfo=timezone.utc)
        assert nxt.weekday() == slot.weekday(), "same day of week"
        assert (nxt.hour, nxt.minute) == (9, 0), "the 37 minutes must not compound"

    def test_lateness_never_accumulates_across_occurrences(self):
        """Ten weeks of 20-minutes-late posting must not move the time of day."""
        slot = self._sun()
        for _ in range(10):
            sent = slot + timedelta(minutes=20)
            _, slot = publisher._next_state(
                slot, {"freq": "weekly", "interval": 1}, None, now=sent,
            )
        assert (slot.hour, slot.minute) == (9, 0)
        assert slot.weekday() == 6  # still Sunday

    def test_a_missed_run_skips_to_the_next_real_occurrence(self):
        """Recovering from a three-week outage rejoins the rhythm — it does not
        schedule a date already in the past, nor fire three times to catch up."""
        slot = self._sun()                                  # Sun Aug 2
        now = datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)  # 20 days later
        status, nxt = publisher._next_state(
            slot, {"freq": "weekly", "interval": 1}, None, now=now,
        )
        assert status == "scheduled"
        assert nxt > now, "never schedule into the past"
        assert nxt == datetime(2026, 8, 23, 9, 0, tzinfo=timezone.utc)
        assert nxt.weekday() == 6 and (nxt.hour, nxt.minute) == (9, 0)

    def test_cease_at_still_retires_the_series(self):
        slot = self._sun()
        status, nxt = publisher._next_state(
            slot, {"freq": "weekly", "interval": 1},
            "2026-08-05T00:00:00+00:00", now=slot,
        )
        assert status == "sent" and nxt is None

    def test_a_pattern_whose_next_slot_is_unreachable_retires(self):
        """A malformed recurrence must terminate, not spin looking for a future."""
        slot = self._sun()
        status, nxt = publisher._next_state(slot, {"freq": "nonsense"}, None, now=slot)
        assert status == "sent" and nxt is None

    @pytest.mark.asyncio
    async def test_publish_one_anchors_the_next_slot_on_publish_at(self, _stub_record):
        """The wiring, not just the arithmetic.

        `_next_state` can be correct while `publish_one` still hands it the wrong
        anchor — reverting the call site alone broke no unit test, so this asserts
        the value that actually reaches the database.
        """
        rt = _runtime()
        client = SimpleNamespace(post_tweet=AsyncMock(
            return_value={"tweet_id": "tw1", "tweet_url": "https://x.com/i/status/tw1"}))
        with _claimed(
            doc={"blocks": []}, text_cache="gm",
            publish_at="2026-08-02 09:00:00+00",           # Sunday 09:00
            recurrence={"freq": "weekly", "interval": 1},
            last_attempt_at="2026-08-02 09:37:00+00",      # claimed 37 min late
        ), patch.object(publisher.posts_db, "record_occurrence_and_advance",
                        AsyncMock(return_value=True)) as occ, \
             patch("excalibur_mcp.server._resolve_x_client",
                   AsyncMock(return_value=(client, None))):
            out = await publisher.publish_one(rt, "p1")

        assert out["outcome"] == "posted"
        nxt = occ.await_args.kwargs["next_publish_at"]
        assert nxt.startswith("2026-08-09T09:00"), nxt


# ---------------------------------------------------------------------------
# A degraded send must not read as a clean one
# ---------------------------------------------------------------------------


_FELL_BACK_RENDER = {"blocks": [
    {"text": "Markets update.", "flags": []},
    {"text": "Markets moving fast.", "flags": [], "dynamic": True,
     "fallback": "Markets moving fast.", "resolved": True,
     "fellBack": {"reason": "upstream_llm_unfunded", "budget_s": 480.0}},
]}


@pytest.mark.asyncio
async def test_a_publication_that_sent_fallback_text_says_so(_stub_record):
    """The tweet went out, but not with the words the author asked for.

    `fallbacks` was declared in publish_one and never appended to, so this key
    could not fire and every degraded send recorded as a clean success. Four
    flattened templates posted their fallback line on schedule for days and
    nothing in the log or the FE could tell them from real posts.
    """
    rt = _runtime()
    client = SimpleNamespace(post_tweet=AsyncMock(
        return_value={"tweet_id": "tw9", "tweet_url": "https://x.com/i/status/tw9"}))
    with _claimed(render=_FELL_BACK_RENDER), \
         patch.object(publisher.posts_db, "record_occurrence_and_advance",
                      AsyncMock(return_value=True)), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        out = await publisher.publish_one(rt, "p1")

    assert out["outcome"] == "posted"          # the send itself still succeeded
    recorded = _stub_record.await_args.args[0]
    assert recorded["fallbacks"] == [
        {"block": 1, "reason": "upstream_llm_unfunded", "budget_s": 480.0},
    ], "a fallback send must be distinguishable from a real one"


@pytest.mark.asyncio
async def test_a_clean_publication_carries_no_fallbacks_key(_stub_record):
    """The flip side: an undegraded send must stay quiet, or the marker is noise."""
    rt = _runtime()
    client = SimpleNamespace(post_tweet=AsyncMock(
        return_value={"tweet_id": "tw8", "tweet_url": "https://x.com/i/status/tw8"}))
    with _claimed(render={"blocks": [{"text": "All good.", "flags": [], "resolved": True}]}), \
         patch.object(publisher.posts_db, "record_occurrence_and_advance",
                      AsyncMock(return_value=True)), \
         patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))):
        await publisher.publish_one(rt, "p1")

    assert "fallbacks" not in _stub_record.await_args.args[0]
