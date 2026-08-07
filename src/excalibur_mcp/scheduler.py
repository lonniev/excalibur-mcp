"""Two things, on their own clocks: posting what is ready, building what is next.

The scheduler still builds no content and talks to nobody upstream. What changed
is that it no longer hands a *publication* to a background job — it hands a
*resolution*, and does the publishing itself.

That inversion follows from how long each takes. Building a body can run minutes
(a dynamic block is a model prompt with web lookups, capped by the author's own
runtimeLimit). Posting a finished body is one HTTPS call, tens of milliseconds.
Only the first needs to outlive the tick.

**Phase 1 — post.** Every ``resolved`` body whose moment has arrived is claimed
and sent inline. No background job, no lease measured in tens of minutes, nothing
that can outlive the tick that started it.

**Phase 2 — resolve.** Templates due within ``RESOLVE_LEAD_SECONDS`` are claimed
and handed to a worker. Starting a tick EARLY is what keeps publishing punctual:
resolving at publish_at guarantees the post is late by whatever the model took.

Posting first is deliberate — a body finished during the previous tick goes out
at the top of this one rather than waiting behind this tick's model work.

**Phase 0 — recover.** Before either, repair what a previous tick stranded. A
publisher that dies leaves its post ``sending``, and no timer may re-fire that:
one did on 2026-07-30 and tweeted twice. So recovery decides on evidence instead.
``x_call_at`` records that a publisher was cleared to call X; only where it is
absent — and the row is provably one this code claimed — is the post resumed.
Everything ambiguous is paused, which is a state the owner can see and act on.

Four guards, each earned:

* ``claim_for_resolve`` and ``claim_for_post`` are atomic, so overlapping ticks
  can never double-start the same work.
* the resolve lease (20 min, in ``posts.py``) hands back a slot whose worker died
  with its container. Nothing supervises workers; the lease is the recovery.
* ``mark_x_call_started`` is a fenced compare-and-set that AUTHORIZES the call,
  so a superseded publisher stands down before touching X.
* ``resolve_attempts`` caps how many times a post may fail to fire — and at the
  cap it is now paused rather than silently dropped from the work-list, because a
  row that reads ``scheduled`` and can never fire again is the worst of both.

A recurrence that fires faster than its content can be built still needs no
special handling: a template already ``resolving`` inside its lease is not due.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from excalibur_mcp.config import get_settings
from excalibur_mcp.db import posts as posts_db
from excalibur_mcp.db import scheduler_runs

logger = logging.getLogger(__name__)

# Two of the resolve budget rings. Both are DERIVED from the single configured
# block ceiling (config.Settings) rather than authored here — see the ring
# comment there for why an inversion between them is dangerous rather than
# merely untidy. Read once at import: settings come from the environment and do
# not change under a running process.
_budgets = get_settings()

# How long one publication may run before the wheel's watchdog considers it
# stale. Sits outside the largest block a template may ask for, and inside the
# claim lease that would otherwise hand the post to another tick.
RESOLVE_MAX_RUNTIME_S = _budgets.resolve_job_attempt_s

# How far ahead of publish_at to start building a body. A tick, or a full-budget
# block, whichever is longer. The cost of a longer lead is staleness; the cost of
# too short a one is lateness.
RESOLVE_LEAD_SECONDS = _budgets.resolve_lead_s

# A publisher's value is its side effects — the tweet and the post row it
# updates. Nobody redeems its claim check, so the result only needs to outlive
# the job itself for debugging.
RESOLVE_RESULT_TTL_S = 3600


# The shape of the summary this module produces. A LITERAL in the source, so it
# travels only with the code — unlike the version and the commit, which are read
# from the package metadata and the environment and therefore describe what the
# container was BUILT for, not what Python is executing.
#
# That distinction is not academic. On 2026-08-02 twelve consecutive ticks
# reported commit a9a4ca3 while emitting the previous build's summary shape: a
# cached wheel layer serving old bytes under a new SHA. The commit read as
# confirmation and confirmed nothing. Bump this string whenever the summary
# changes, and a stale layer becomes visible in the heartbeat itself.
_TICK_CONTRACT = "recover-post-resolve-harvest/1"


def _who() -> dict[str, str]:
    """Who is answering — the deployed identity behind this tick.

    A heartbeat that only says "alive" doesn't say WHICH build is alive, and this
    service has been bitten by a container serving cached bytes while reporting a
    fresh version. The commit does NOT settle that: it comes from the
    environment, so it describes the build request rather than the running code.
    ``contract`` is the half that cannot lie, because it is compiled in.
    """
    from excalibur_mcp import __version__

    who = {"version": __version__, "contract": _TICK_CONTRACT}
    sha = os.environ.get("FASTMCP_CLOUD_GIT_COMMIT_SHA", "")
    if sha:
        who["commit"] = sha[:7]
    return who


async def _upcoming(now: datetime) -> dict[str, Any]:
    """The forecast a heartbeat carries: how many posts are still ahead and how
    far off the soonest is — in total, and per owner.

    ``by_owner`` is what lets the log stay owner-scoped: the operator reads the
    whole queue, a patron reads only their own slice of it, and neither has to
    be told the other's numbers. Best-effort — a tick that can't see the future
    still dispatches the present.
    """
    try:
        rows = await posts_db.upcoming_by_owner(now.isoformat())
    except Exception:  # noqa: BLE001 — a forecast is never worth failing a tick over
        logger.exception("scheduler: could not read the upcoming queue")
        return {}

    def _mins(at: Any) -> int | None:
        when = at if isinstance(at, datetime) else _parse_pg(str(at)) if at else None
        return None if when is None else max(0, round((when - now).total_seconds() / 60))

    by_owner: dict[str, Any] = {}
    total, soonest = 0, None
    for r in rows:
        count = int(r.get("count") or 0)
        mins = _mins(r.get("next_at"))
        total += count
        if mins is not None and (soonest is None or mins < soonest):
            soonest = mins
        entry: dict[str, Any] = {"count": count}
        if mins is not None:
            entry["next_in_minutes"] = mins
        by_owner[str(r.get("npub") or "")] = entry

    out: dict[str, Any] = {"count": total, "by_owner": by_owner}
    if soonest is not None:
        out["next_in_minutes"] = soonest
    return out


def _parse_pg(value: str) -> datetime | None:
    """Postgres hands back ``2026-07-26 19:00:00+00`` — a two-digit offset that
    ``fromisoformat`` won't take before 3.11's relaxation covers it."""
    try:
        return datetime.fromisoformat(value.replace(" ", "T").replace("+00", "+00:00"))
    except ValueError:
        return None


async def process_due_posts(runtime: Any) -> dict[str, Any]:
    """One tick, two phases: post what is ready, then start building what is next.

    The order matters. Posting first means a body finished during the previous
    tick goes out at the top of this one, rather than waiting behind however long
    this tick's resolutions take. Posting is milliseconds; resolution is minutes.

    **Phase 1 — post.** Every ``resolved`` body whose moment has arrived is
    claimed and sent inline. No background job, no claim lease measured in tens of
    minutes, nothing that can outlive the tick.

    **Phase 2 — resolve.** Templates due within the lookahead window are claimed
    and handed to a worker that builds their body. Starting a tick EARLY is what
    keeps publishing punctual: resolving at publish_at guarantees the post is late
    by however long the model took. A post with nothing dynamic resolves instantly
    and is unaffected.
    """
    from tollbooth.tool_identity import capability_uuid

    tick_id = capability_uuid("process_scheduled_posts")
    run_id = await scheduler_runs.begin_run()
    now = datetime.now(timezone.utc)

    # -- Phase 0: repair whatever the last tick left stranded ----------------
    #
    # Runs first so a post recovered here is published by Phase 1 in this same
    # tick rather than waiting half an hour for the next one. Best-effort: state
    # repair is never worth losing a publication over.
    #
    # Both sweeps are bulk statements. Neither retries a send on a timer — the
    # resume branch fires only where `x_call_at` proves the publisher died before
    # reaching X, and everything ambiguous is paused for a human.
    recovered: dict[str, Any] = {}
    try:
        recovered = await posts_db.recover_orphaned_sends()
        recovered["exhausted"] = await posts_db.pause_exhausted_firings(
            (now + timedelta(seconds=RESOLVE_LEAD_SECONDS)).isoformat(),
        )
    except Exception:  # noqa: BLE001 — a failed repair must never sink a tick
        logger.exception("scheduler: recovery sweep failed")
    recovered = {k: v for k, v in recovered.items() if v}
    if recovered:
        logger.info("scheduler: recovered %s", {k: len(v) for k, v in recovered.items()})

    # -- Phase 1: post finished bodies -------------------------------------
    posted: list[dict[str, Any]] = []
    ready = await posts_db.list_resolved_due(now.isoformat())
    if ready:
        # Imported only when there is something to post. `publish_one` reaches
        # into server.py for the patron's X client, which boots the whole
        # runtime — a quiet tick must not pay that, and must not require an
        # operator identity merely to report that nothing was due.
        from excalibur_mcp.publisher import publish_one
    for row in ready:
        pid, owner = row["post_id"], row["npub"]
        if await posts_db.claim_for_post(pid) is None:
            continue  # another tick got there first; not worth reporting
        try:
            out = await publish_one(runtime, pid)
            posted.append({"post_id": pid, "owner": owner,
                           "outcome": out.get("outcome"), "reason": out.get("reason")})
        except Exception as exc:  # noqa: BLE001 — one bad post must not stop the rest
            logger.exception("scheduler: posting %s failed", pid)
            posted.append({"post_id": pid, "owner": owner,
                           "outcome": "error", "reason": str(exc) or type(exc).__name__})

    # -- Phase 2: start building the next ones ------------------------------
    horizon = now + timedelta(seconds=RESOLVE_LEAD_SECONDS)
    resolving: list[dict[str, Any]] = []
    contended: list[dict[str, Any]] = []
    for row in await posts_db.list_due_for_resolve(horizon.isoformat()):
        pid, owner = row["post_id"], row["npub"]
        if await posts_db.claim_for_resolve(pid) is None:
            contended.append({"post_id": pid, "owner": owner,
                              "reason": "claimed_by_another_tick"})
            continue
        try:
            claim = await runtime.start_async_job(
                "resolve_post_body", owner, {"post_id": pid},
                tool_id=tick_id, max_runtime_seconds=RESOLVE_MAX_RUNTIME_S,
                result_ttl_seconds=RESOLVE_RESULT_TTL_S,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("scheduler: failed to launch resolver for %s", pid)
            contended.append({"post_id": pid, "owner": owner,
                              "reason": f"launch_failed: {exc}"})
            continue
        entry = {"post_id": pid, "owner": owner,
                 "claim_check": (claim or {}).get("claim_check")}
        # A dispatch that fell back in-process says so now (SDK 0.79.0). Carry it
        # into the tick summary: a job running somewhere that may not outlive the
        # next container recycle is worth seeing without reading a log.
        if isinstance(claim, dict) and claim.get("degraded"):
            entry["degraded"] = claim["degraded"]
            entry["degraded_reason"] = claim.get("degraded_reason")
        resolving.append(entry)

    # -- Phase 3: harvest post metrics (decaying cadence; missed = lost) -----
    # X drops non_public/organic metrics after 30 days. Drain due harvest jobs
    # on the same tick that posts/resolves so no separate cron is required.
    harvest: dict[str, Any] = {"kind": "harvest", "captured": [], "failed": [], "processed": 0}
    try:
        from excalibur_mcp.metrics_harvest import process_due_harvests

        harvest = await process_due_harvests(runtime)
    except Exception:  # noqa: BLE001 — harvest must never sink a publish tick
        logger.exception("scheduler: metrics harvest phase failed")

    summary = {"kind": "tick", "who": _who(),
               "posted": posted, "resolving": resolving, "contended": contended,
               "harvest": harvest,
               **({"recovered": recovered} if recovered else {}),
               "processed": len(posted) + len(resolving) + int(harvest.get("processed") or 0)
               + sum(len(v) for v in recovered.values()),
               "upcoming": await _upcoming(now)}
    logger.info(
        "scheduler: posted=%d resolving=%d contended=%d harvest=%d recovered=%d",
        len(posted), len(resolving), len(contended),
        int(harvest.get("processed") or 0),
        sum(len(v) for v in recovered.values()),
    )
    try:
        await scheduler_runs.complete_run(run_id, summary)
    except Exception:  # noqa: BLE001 — audit is non-critical
        logger.exception("scheduler: failed to record run summary")
    return summary
