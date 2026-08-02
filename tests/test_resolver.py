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
    with patch.object(resolver.posts_db, "save_resolved_doc", AsyncMock(return_value=True)) as save, \
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
        failure this flag exists to prevent."""
        rt = _runtime()
        already = {**_DYN, "text": "$64,000", "resolved": True}
        with _claimed(_doc(_STATIC, already, dict(_DYN))), \
             patch("excalibur_mcp.resolve.resolve_block", AsyncMock(return_value="fresh")):
            out = await resolver.resolve_one(rt, "p1")

        assert out["blocks_resolved"] == 1, "only the outstanding block"
        assert rt._apply_billing.await_count == 1, "the paid-for block is not re-billed"

    @pytest.mark.asyncio
    async def test_a_fully_resumed_body_costs_nothing_at_all(self, _stub_writes):
        rt = _runtime()
        done_block = {**_DYN, "text": "$64,000", "resolved": True}
        with _claimed(_doc(_STATIC, done_block)):
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
