"""Building a body — the slow half, on its own.

These moved out of ``test_publisher.py`` when resolution and posting were split,
and they assert more than they used to. The old shape resolved everything inside
one publication: a crash lost every block, and the owner bought them all again on
the next tick. So alongside the behaviours that carried over — fall back rather
than post a gap, refuse rather than post nothing, name the reason — these pin the
guarantees the split exists to provide:

* progress is persisted **per block**, so a death costs only what was unfinished;
* a resumed worker re-buys **nothing** it already paid for;
* a block that bought nothing has its fare **refunded**, not carried;
* a body only becomes ``resolved`` when every block holds an answer.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from excalibur_mcp import resolver

NPUB = "npub1d999638gqpn8c594teklxtxva0uvxdng80q3ycyqvldjdl457c7qcrq64z"


@pytest.fixture(autouse=True)
def _stub_record():
    with patch.object(resolver, "_record", AsyncMock(side_effect=lambda o: o)) as m:
        yield m


@pytest.fixture(autouse=True)
def _stub_voice():
    with patch("excalibur_mcp.publisher._owner_voice", AsyncMock(return_value=("", []))):
        yield


@pytest.fixture(autouse=True)
def _stub_writes():
    """The two row-writes the resolver makes, exposed for assertion."""
    with patch.object(resolver.posts_db, "save_render", AsyncMock(return_value=True)) as save, \
         patch.object(resolver.posts_db, "mark_resolved", AsyncMock(return_value=True)) as done, \
         patch.object(resolver.posts_db, "mark_attempt", AsyncMock()):
        yield SimpleNamespace(save=save, done=done)


def _runtime(*, cost: int = 3, billing_denies=None):
    rt = SimpleNamespace()
    rt._resolve_pricing = AsyncMock(return_value=(cost, None))
    rt._apply_billing = AsyncMock(return_value=billing_denies)
    rt.rollback_debit = AsyncMock()
    rt.load_credentials = AsyncMock(return_value={"llm_api_key": "k"})
    return rt


def _claimed(doc, **over):
    row = {"post_id": "p1", "npub": NPUB, "doc": doc,
           "text_cache": "", "last_attempt_at": "2026-08-01 22:00:00+00"}
    row.update(over)
    return patch.object(resolver.posts_db, "get_claimed", AsyncMock(return_value=row))


def _doc(*blocks):
    return {"blocks": list(blocks)}


_STATIC = {"text": "Markets update.", "flags": []}
_DYN = {"text": "the BTC/USD price now", "flags": [], "dynamic": True,
        "fallback": "Markets moving fast."}


# ---------------------------------------------------------------------------
# The static/dynamic fork is gone
# ---------------------------------------------------------------------------


class TestNothingToResolve:
    @pytest.mark.asyncio
    async def test_a_plain_post_resolves_instantly_and_costs_nothing(self, _stub_writes):
        """The whole point of the split: a post with no dynamic blocks takes the
        same path, does no work, and is never billed a resolve fare."""
        rt = _runtime()
        with _claimed(_doc(_STATIC, {"text": "Second line.", "flags": []})):
            out = await resolver.resolve_one(rt, "p1")

        assert out["outcome"] == "resolved"
        assert out["blocks_resolved"] == 0
        rt._apply_billing.assert_not_awaited()
        _stub_writes.done.assert_awaited_once()
        assert _stub_writes.done.await_args.args[1] == "Markets update.\n\nSecond line."

    @pytest.mark.asyncio
    async def test_a_nostr_block_stays_out_of_the_body(self, _stub_writes):
        rt = _runtime()
        nostr = {"text": "companion {{tweet_url}}", "flags": [], "nostr": True}
        with _claimed(_doc(_STATIC, nostr)):
            await resolver.resolve_one(rt, "p1")
        assert _stub_writes.done.await_args.args[1] == "Markets update."


# ---------------------------------------------------------------------------
# Money already spent must survive
# ---------------------------------------------------------------------------


class TestProgressIsPersisted:
    @pytest.mark.asyncio
    async def test_each_block_is_saved_as_it_completes(self, _stub_writes):
        """Not once at the end. A block runs 90-210s and costs a real fare, so a
        worker that dies after three of four must not make the owner re-buy them."""
        rt = _runtime()
        doc = _doc(_STATIC, dict(_DYN), dict(_DYN))
        with _claimed(doc), \
             patch("excalibur_mcp.resolve.resolve_block", AsyncMock(return_value="$64,000")):
            out = await resolver.resolve_one(rt, "p1")

        assert out["outcome"] == "resolved" and out["blocks_resolved"] == 2
        assert _stub_writes.save.await_count == 2, "one save per resolved block"

    @pytest.mark.asyncio
    async def test_a_resumed_worker_rebuys_nothing(self, _stub_writes):
        """A block already carrying an answer is marked resolved. A second worker
        must skip it — charging again for work the owner already owns is the
        failure this flag exists to prevent.

        The evidence lives in ``render``, this firing's working copy. It cannot
        live in ``doc``: that is the author's template, it outlives the firing,
        and reading paid-for-ness from it is what froze recurring posts."""
        rt = _runtime()
        already = {**_DYN, "text": "$64,000", "resolved": True}
        with _claimed(_doc(_STATIC, dict(_DYN), dict(_DYN)),
                      render=_doc(_STATIC, already, dict(_DYN))), \
             patch("excalibur_mcp.resolve.resolve_block", AsyncMock(return_value="fresh")):
            out = await resolver.resolve_one(rt, "p1")

        assert out["blocks_resolved"] == 1, "only the outstanding block"
        assert rt._apply_billing.await_count == 1, "the paid-for block is not re-billed"

    @pytest.mark.asyncio
    async def test_a_fully_resumed_body_costs_nothing_at_all(self, _stub_writes):
        rt = _runtime()
        done_block = {**_DYN, "text": "$64,000", "resolved": True}
        with _claimed(_doc(_STATIC, dict(_DYN)),
                      render=_doc(_STATIC, done_block)):
            out = await resolver.resolve_one(rt, "p1")
        assert out["outcome"] == "resolved" and out.get("resumed") is True
        rt._apply_billing.assert_not_awaited()


# ---------------------------------------------------------------------------
# Failure: refund, fall back, or refuse — and always say which
# ---------------------------------------------------------------------------


class TestFailure:
    @pytest.mark.asyncio
    async def test_a_failed_block_with_a_fallback_degrades_and_refunds(self, _stub_writes):
        rt = _runtime()
        with _claimed(_doc(_STATIC, dict(_DYN))), \
             patch("excalibur_mcp.resolve.resolve_block",
                   AsyncMock(side_effect=RuntimeError("provider down"))):
            out = await resolver.resolve_one(rt, "p1")

        assert out["outcome"] == "resolved", "a fallback still yields a postable body"
        rt.rollback_debit.assert_awaited_once()  # the fare bought nothing
        assert out["degraded"][0]["block"] == 1
        assert "resolve_failed:RuntimeError" in out["degraded"][0]["reason"]
        assert "Markets moving fast." in _stub_writes.done.await_args.args[1]

    @pytest.mark.asyncio
    async def test_a_failed_block_with_no_fallback_refuses_and_names_why(self, _stub_writes):
        """Never post a gap — and never report the refusal as a bare category.
        The block's own reason used to be computed and dropped on the way out."""
        rt = _runtime()
        no_fb = {"text": "the price now", "flags": [], "dynamic": True}
        with _claimed(_doc(_STATIC, no_fb)), \
             patch("excalibur_mcp.resolve.resolve_block",
                   AsyncMock(side_effect=RuntimeError("provider down"))):
            out = await resolver.resolve_one(rt, "p1")

        assert out["outcome"] == "held"
        assert "resolve_failed:RuntimeError" in out["reason"]
        rt.rollback_debit.assert_awaited_once()
        _stub_writes.done.assert_not_awaited(), "a refused body never becomes postable"

    @pytest.mark.asyncio
    async def test_no_operator_key_is_named_not_swallowed(self, _stub_writes):
        rt = _runtime()
        rt.load_credentials = AsyncMock(side_effect=RuntimeError("vault cold"))
        no_fb = {"text": "the price now", "flags": [], "dynamic": True}
        with _claimed(_doc(no_fb)):
            out = await resolver.resolve_one(rt, "p1")
        assert out["outcome"] == "held" and "no_operator_llm_key" in out["reason"]

    @pytest.mark.asyncio
    async def test_insufficient_balance_holds_before_spending_the_model(self, _stub_writes):
        """Billing refuses per block, BEFORE the call — so a short owner is never
        charged for a resolve that then cannot be paid for."""
        rt = _runtime(billing_denies={"error_code": "insufficient_balance"})
        resolve = AsyncMock(return_value="$64,000")
        with _claimed(_doc(_STATIC, dict(_DYN))), \
             patch("excalibur_mcp.resolve.resolve_block", resolve):
            out = await resolver.resolve_one(rt, "p1")

        assert out["outcome"] == "held" and out["reason"] == "insufficient_balance"
        resolve.assert_not_awaited()
        _stub_writes.done.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_a_superseded_claim_stands_down(self, _stub_writes):
        """The fence rejected our final write: a later tick decided we were dead
        and re-claimed. Its worker owns the row, so we must not fight for it."""
        rt = _runtime()
        _stub_writes.done.return_value = False
        with _claimed(_doc(_STATIC)):
            out = await resolver.resolve_one(rt, "p1")
        assert out["outcome"] == "superseded"


# ---------------------------------------------------------------------------
# The author's budget still reaches the model
# ---------------------------------------------------------------------------


class TestAuthorControls:
    @pytest.mark.asyncio
    async def test_runtime_limit_and_web_access_are_passed_through(self, _stub_writes):
        rt = _runtime()
        block = {**_DYN, "runtimeLimit": 300, "maxFetches": 2,
                 "domains": ["coindesk.com", "kraken.com"]}
        resolve = AsyncMock(return_value="$64,000")
        with _claimed(_doc(block)), \
             patch("excalibur_mcp.resolve.resolve_block", resolve):
            await resolver.resolve_one(rt, "p1")

        kw = resolve.await_args.kwargs
        assert kw["timeout_seconds"] == 300
        assert kw["max_fetches"] == 2
        assert kw["allowed_domains"] == ["coindesk.com", "kraken.com"]


# ---------------------------------------------------------------------------
# The author's template is not the resolver's scratch paper
# ---------------------------------------------------------------------------


class TestTheAuthoredDocIsNeverWritten:
    """The 2026-08-04 defect, pinned from several directions.

    A dynamic block's prompt IS its ``text``, and resolution used to write its
    answer back over that — into ``doc``, the authored row. One firing of a
    recurring template therefore consumed the template: the prompt became the
    answer (or the fallback, when the model was unreachable), the block was
    marked ``resolved``, and every later firing found nothing pending and
    reposted the same frozen words. ``doc`` has no history, so the prompts were
    gone for good.

    These assert the separation rather than the symptom: whatever else happens,
    the resolver writes ``render`` and only ``render``.
    """

    @pytest.mark.asyncio
    async def test_a_successful_resolve_leaves_the_prompt_untouched(self, _stub_writes):
        """The success path did the damage too — this is not a failure-only bug.
        A template that resolves perfectly still had its prompt overwritten, and
        looked fine doing it, because generated prose reads like content."""
        rt = _runtime()
        doc = _doc(_STATIC, dict(_DYN))
        with _claimed(doc), \
             patch("excalibur_mcp.resolve.resolve_block", AsyncMock(return_value="$64,000")):
            await resolver.resolve_one(rt, "p1")

        saved = _stub_writes.save.await_args.args[1]
        assert saved["blocks"][1]["text"] == "$64,000", "the render carries the answer"
        assert doc["blocks"][1]["text"] == "the BTC/USD price now", "the doc keeps the prompt"
        assert "resolved" not in doc["blocks"][1], "and is not marked spent"

    @pytest.mark.asyncio
    async def test_a_fallback_never_becomes_the_prompt(self, _stub_writes):
        """The visible half of the bug: an unreachable model substituted the
        fallback, and the fallback then WAS the prompt for every firing after."""
        rt = _runtime()
        doc = _doc(_STATIC, dict(_DYN))
        with _claimed(doc), \
             patch("excalibur_mcp.resolve.resolve_block",
                   AsyncMock(side_effect=RuntimeError("provider down"))):
            out = await resolver.resolve_one(rt, "p1")

        assert out["outcome"] == "resolved" and out["degraded"]
        assert doc["blocks"][1]["text"] == "the BTC/USD price now"
        saved = _stub_writes.save.await_args.args[1]
        assert saved["blocks"][1]["text"] == "Markets moving fast."

    @pytest.mark.asyncio
    async def test_the_prompt_is_read_from_the_doc_not_the_render(self, _stub_writes):
        """The mechanism, isolated. Given a render whose block already holds last
        firing's ANSWER, the model must still be asked the authored QUESTION —
        reading the prompt from the working copy is what made a substituted
        fallback self-perpetuating."""
        rt = _runtime()
        stale = {**_DYN, "text": "Markets moving fast."}  # last firing's fallback
        resolve = AsyncMock(return_value="$64,000")
        with _claimed(_doc(_STATIC, dict(_DYN)), render=_doc(_STATIC, stale)), \
             patch("excalibur_mcp.resolve.resolve_block", resolve):
            await resolver.resolve_one(rt, "p1")

        assert resolve.await_args.kwargs["prompt"] == "the BTC/USD price now"

    @pytest.mark.asyncio
    async def test_an_already_flattened_template_pauses_instead_of_guessing(
        self, _stub_writes,
    ):
        """Templates damaged before the fix carry ``resolved: true`` in their doc,
        which only the resolver ever writes — so the prompt there is really last
        firing's output, and it is gone for good.

        Two wrong answers were available. Honour the flag and the post stays
        frozen, reposting stale text forever. Ignore it and the fallback becomes
        the prompt, so the owner is billed for fluent posts nobody wrote. Pause:
        the one outcome that tells the truth and costs nothing."""
        rt = _runtime()
        flattened = {**_DYN, "text": "Markets moving fast.", "resolved": True}
        resolve = AsyncMock(return_value="$64,000")
        with _claimed(_doc(_STATIC, flattened)), \
             patch.object(resolver.posts_db, "mark_paused", AsyncMock()) as paused, \
             patch("excalibur_mcp.resolve.resolve_block", resolve):
            out = await resolver.resolve_one(rt, "p1")

        assert out["outcome"] == "paused"
        assert out["reason"] == "template_prompt_lost"
        assert out["blocks"] == [1]
        assert "re-author" in out["detail"]
        resolve.assert_not_awaited(), "never run last firing's output as a prompt"
        rt._apply_billing.assert_not_awaited(), "and never bill for it"
        paused.assert_awaited_once()
        _stub_writes.done.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_an_undamaged_template_is_not_mistaken_for_a_flattened_one(
        self, _stub_writes,
    ):
        """The detector keys on `resolved` in an authored DYNAMIC block. A static
        block, or a dynamic one that has simply never fired, is untouched."""
        rt = _runtime()
        with _claimed(_doc(_STATIC, dict(_DYN))), \
             patch("excalibur_mcp.resolve.resolve_block", AsyncMock(return_value="$64k")):
            out = await resolver.resolve_one(rt, "p1")
        assert out["outcome"] == "resolved"

    @pytest.mark.asyncio
    async def test_a_stale_render_is_rebuilt_not_resumed(self, _stub_writes):
        """A render that no longer matches the authored doc would pair block N's
        answer with block N's new prompt. Rebuild rather than post a body the
        author never wrote."""
        rt = _runtime()
        resolve = AsyncMock(return_value="$64,000")
        with _claimed(_doc(_STATIC, dict(_DYN), dict(_DYN)),
                      render=_doc(_STATIC, {**_DYN, "text": "old", "resolved": True})), \
             patch("excalibur_mcp.resolve.resolve_block", resolve):
            out = await resolver.resolve_one(rt, "p1")

        assert out["blocks_resolved"] == 2, "both blocks rebuilt from the doc"


# ---------------------------------------------------------------------------
# One retry — and only where the request was never delivered
# ---------------------------------------------------------------------------


class TestConnectRetry:
    """A connect-class failure is the one kind that is free to try again.

    On 2026-08-06 a single `ConnectError` cost post 844c6b64 its content 135s
    into a 480s budget, and the identical request reproduced cleanly minutes
    later. Nothing retried, so 72% of the author's time went unspent and the
    reader got the fallback.
    """

    @pytest.mark.asyncio
    async def test_a_connect_error_is_retried_once_and_can_succeed(self):
        rt = _runtime()
        calls: list[float] = []

        async def flaky(**kw):
            calls.append(kw["timeout_seconds"])
            if len(calls) == 1:
                raise httpx.ConnectError("connection refused")
            return "the resolved words"

        with _claimed(_doc(_STATIC, {**_DYN, "runtimeLimit": 480})), \
             patch("excalibur_mcp.resolve.resolve_block", side_effect=flaky):
            out = await resolver.resolve_one(rt, "p1")

        assert out["outcome"] == "resolved"
        assert "degraded" not in out, "a recovered block is not a degradation"
        assert len(calls) == 2, "one retry, not zero and not a loop"
        # The retry runs inside the block's OWN remaining budget — it may not
        # hand itself a fresh 480s and double the author's ceiling.
        assert calls[1] <= calls[0]
        rt.rollback_debit.assert_not_awaited()  # the fare bought something

    @pytest.mark.asyncio
    async def test_a_timeout_is_not_retried(self):
        # The provider may have been mid-generation; a second attempt re-bills
        # upstream and can duplicate work. Fall back, as before.
        rt = _runtime()
        calls: list[float] = []

        async def timing_out(**kw):
            calls.append(kw["timeout_seconds"])
            raise httpx.ReadTimeout("took too long")

        with _claimed(_doc(_STATIC, {**_DYN, "runtimeLimit": 480})), \
             patch("excalibur_mcp.resolve.resolve_block", side_effect=timing_out):
            out = await resolver.resolve_one(rt, "p1")

        assert len(calls) == 1, "a timeout must not be retried"
        assert out["degraded"][0]["reason"] == "resolve_timed_out_at_480s"

    @pytest.mark.asyncio
    async def test_both_attempts_failing_reports_the_retrys_reason(self):
        rt = _runtime()

        async def always_refused(**kw):
            raise httpx.ConnectError("connection refused")

        with _claimed(_doc(_STATIC, {**_DYN, "runtimeLimit": 480})), \
             patch("excalibur_mcp.resolve.resolve_block", side_effect=always_refused):
            out = await resolver.resolve_one(rt, "p1")

        assert out["degraded"][0]["reason"] == "resolve_failed:ConnectError"
        rt.rollback_debit.assert_awaited()  # bought nothing, so refunded
