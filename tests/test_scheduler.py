"""Scheduler tests — finding due posts and launching a publisher for each.

The tick's whole contract: claim atomically, launch one background publisher per
due post, record what was dispatched, and return. It must never build content,
bill anyone, or wait to see how a publication turned out — those belong to the
publisher, and keeping them out is what lets a dynamic block take minutes.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from excalibur_mcp import scheduler

NPUB = "npub1l94pd4qu4eszrl6ek032ftcnsu3tt9a7xvq2zp7eaxeklp6mrpzssmq8pf"


@pytest.fixture(autouse=True)
def _stub_run_ring():
    """The tick opens an audit row before any work and closes it with the
    summary; keep both off Neon and expose the closing mock."""
    with patch.object(scheduler.scheduler_runs, "begin_run", AsyncMock(return_value="run-1")), \
         patch.object(scheduler.scheduler_runs, "complete_run", AsyncMock()) as done:
        yield done


@pytest.fixture(autouse=True)
def _stub_claim():
    """Each template is claimed atomically before a resolver is launched.
    Default: the claim wins; a test overrides to None to simulate another tick
    already owning it."""
    with patch.object(
        scheduler.posts_db, "claim_for_resolve",
        AsyncMock(side_effect=lambda pid: {"post_id": pid}),
    ) as m:
        yield m


@pytest.fixture(autouse=True)
def _stub_ready():
    """Phase 1 (posting finished bodies) is empty unless a test says otherwise.
    Keeping it empty also keeps `publish_one` — and with it the whole server
    bootstrap — out of a tick that has nothing to post."""
    with patch.object(
        scheduler.posts_db, "list_resolved_due", AsyncMock(return_value=[]),
    ) as m:
        yield m


def _runtime(**over):
    rt = SimpleNamespace()
    rt.start_async_job = AsyncMock(return_value={"claim_check": "cc-1", "status": "pending"})
    for k, v in over.items():
        setattr(rt, k, v)
    return rt


def _due(*ids):
    return [{"post_id": i, "npub": NPUB} for i in ids]


def _list_due(*ids):
    """Templates the RESOLVE phase should pick up this tick."""
    return patch.object(
        scheduler.posts_db, "list_due_for_resolve", AsyncMock(return_value=_due(*ids)),
    )


@pytest.mark.asyncio
async def test_launches_one_resolver_per_due_template(_stub_run_ring):
    rt = _runtime()
    with _list_due("p1", "p2", "p3"):
        out = await scheduler.process_due_posts(rt)

    assert out["processed"] == 3
    assert [x["post_id"] for x in out["resolving"]] == ["p1", "p2", "p3"]
    assert rt.start_async_job.await_count == 3
    # each launch names the publisher kind, the owner, and only the post id —
    # content never travels through job params
    kind, owner, params = rt.start_async_job.await_args.args
    assert kind == "resolve_post_body" and owner == NPUB and params == {"post_id": "p3"}
    # bounded well past a single block's 900s ceiling, under the claim lease
    assert rt.start_async_job.await_args.kwargs["max_runtime_seconds"] == scheduler.RESOLVE_MAX_RUNTIME_S
    assert scheduler.RESOLVE_MAX_RUNTIME_S > 900
    _stub_run_ring.assert_awaited_once_with("run-1", out)


@pytest.mark.asyncio
async def test_claims_before_launching(_stub_claim):
    """The claim is what removes the post from the due set. Launching first
    would let a second tick find the same post and publish it twice."""
    rt = _runtime()
    order = []
    _stub_claim.side_effect = lambda pid: (order.append(f"claim:{pid}"), {"post_id": pid})[1]
    rt.start_async_job = AsyncMock(side_effect=lambda *a, **k: (order.append("launch"), {})[1])
    with _list_due("p1"):
        await scheduler.process_due_posts(rt)
    assert order == ["claim:p1", "launch"]


@pytest.mark.asyncio
async def test_post_claimed_by_another_tick_is_not_launched(_stub_claim):
    rt = _runtime()
    _stub_claim.side_effect = None
    _stub_claim.return_value = None  # another tick already owns it
    with _list_due("p1"):
        out = await scheduler.process_due_posts(rt)
    rt.start_async_job.assert_not_awaited()
    assert out["resolving"] == []
    assert out["contended"][0]["reason"] == "claimed_by_another_tick"


@pytest.mark.asyncio
async def test_one_failed_launch_does_not_stop_the_rest():
    """A tick dispatches for many owners; one bad launch must not strand the
    others. The failed post keeps its claim and returns via the lease."""
    rt = _runtime()
    rt.start_async_job = AsyncMock(
        side_effect=[RuntimeError("job store down"), {"claim_check": "cc-2"}],
    )
    with _list_due("p1", "p2"):
        out = await scheduler.process_due_posts(rt)
    assert [x["post_id"] for x in out["resolving"]] == ["p2"]
    assert out["contended"][0]["post_id"] == "p1"
    assert "launch_failed" in out["contended"][0]["reason"]


@pytest.mark.asyncio
async def test_quiet_tick_records_a_heartbeat(_stub_run_ring):
    """Nothing due is still a tick that ran — the row proves the cron is alive."""
    rt = _runtime()
    with _list_due():
        out = await scheduler.process_due_posts(rt)
    assert out["kind"] == "tick"
    assert out["processed"] == 0 and out["resolving"] == [] and out["contended"] == []
    _stub_run_ring.assert_awaited_once()


@pytest.mark.asyncio
async def test_tick_never_touches_content_or_money():
    """The separation, asserted: a tick has no billing surface and no X client.
    If it grew one, these attributes would be accessed and the fake would raise."""
    rt = _runtime()
    with _list_due("p1", "p2"):
        await scheduler.process_due_posts(rt)
    # SimpleNamespace has no _apply_billing / rollback_debit / load_credentials —
    # reaching for any of them would have raised AttributeError above.
    assert not hasattr(rt, "_apply_billing")
    assert not hasattr(rt, "load_credentials")


# -- heartbeat identity ------------------------------------------------------

def test_who_names_the_build(monkeypatch):
    """A heartbeat that only says "alive" can't answer "which deployment?" —
    and this service has served cached bytes while reporting a fresh version,
    so the commit travels alongside."""
    monkeypatch.setenv("FASTMCP_CLOUD_GIT_COMMIT_SHA", "da6905443ecb99fafcf9d78")
    who = scheduler._who()
    assert who["commit"] == "da69054"  # short, not the full 40 chars
    assert who["version"]  # whatever the wheel reports


def test_who_omits_the_commit_when_unbuilt(monkeypatch):
    """Local runs have no build SHA; the field is absent rather than empty."""
    monkeypatch.delenv("FASTMCP_CLOUD_GIT_COMMIT_SHA", raising=False)
    assert "commit" not in scheduler._who()


@pytest.mark.asyncio
async def test_quiet_tick_still_says_who_it_is():
    """The whole point: the do-nothing tick is the one that most needs to be
    worth reading."""
    rt = _runtime()
    with _list_due():
        out = await scheduler.process_due_posts(rt)
    assert out["processed"] == 0
    assert out["who"]["version"]


# -- the forecast ------------------------------------------------------------

def _upcoming_rows(*rows):
    return patch.object(scheduler.posts_db, "upcoming_by_owner", AsyncMock(return_value=list(rows)))


@pytest.mark.asyncio
async def test_quiet_tick_forecasts_what_is_coming():
    """The heartbeat's whole job: say what happens next, not just that we live."""
    rt = _runtime()
    soon = datetime.now(timezone.utc) + timedelta(minutes=47)
    with _list_due(), _upcoming_rows({"npub": NPUB, "count": 3, "next_at": soon}):
        out = await scheduler.process_due_posts(rt)
    up = out["upcoming"]
    assert up["count"] == 3
    assert 46 <= up["next_in_minutes"] <= 48  # rounded from real clock arithmetic


@pytest.mark.asyncio
async def test_forecast_totals_across_owners_and_takes_the_soonest():
    rt = _runtime()
    now = datetime.now(timezone.utc)
    with _list_due(), _upcoming_rows(
        {"npub": NPUB, "count": 2, "next_at": now + timedelta(minutes=120)},
        {"npub": "npub1other", "count": 1, "next_at": now + timedelta(minutes=10)},
    ):
        out = await scheduler.process_due_posts(rt)
    assert out["upcoming"]["count"] == 3  # every owner's posts
    assert out["upcoming"]["next_in_minutes"] <= 11  # the soonest of them all
    # …but kept per-owner too, so the log can be scoped without re-querying
    assert out["upcoming"]["by_owner"][NPUB]["count"] == 2


@pytest.mark.asyncio
async def test_empty_queue_is_stated_not_omitted():
    """'nothing scheduled ahead' is information — a queue that quietly emptied
    should be visible, not indistinguishable from a missing field."""
    rt = _runtime()
    with _list_due(), _upcoming_rows():
        out = await scheduler.process_due_posts(rt)
    assert out["upcoming"]["count"] == 0


@pytest.mark.asyncio
async def test_a_broken_forecast_never_fails_the_tick():
    """Dispatching the present matters more than describing the future."""
    rt = _runtime()
    with _list_due("p1"), \
         patch.object(scheduler.posts_db, "upcoming_by_owner",
                      AsyncMock(side_effect=RuntimeError("neon down"))):
        out = await scheduler.process_due_posts(rt)
    assert [x["post_id"] for x in out["resolving"]] == ["p1"]  # the work still happened
    assert out["upcoming"] == {}
