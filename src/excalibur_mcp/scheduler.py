"""Finding posts that are due, and launching a publisher for each.

That is the whole job. The scheduler does not build content, does not talk to X,
does not bill anyone, and does not wait to see how any of it turned out — a
publisher owns one post's publication end to end and records its own outcome
(see ``publisher.py``). Keeping the two apart is what lets a dynamic block take
the minutes it needs: the tick is a dispatch, over in seconds, while the LLM
work runs as a background job on the wheel's own queue.

Two guards, both already earned elsewhere:

* ``claim_due_post`` flips ``scheduled → sending`` atomically, so overlapping
  ticks can never launch two publishers for the same post.
* the claim lease means a post whose publisher died with its container simply
  falls back into the due set later. Nothing supervises the publishers; the
  lease is the recovery.

A recurrence that fires faster than its content can be built needs no special
handling either — a post still ``sending`` inside its lease is not due, so it
quietly serializes instead of piling up.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

from excalibur_mcp.db import posts as posts_db
from excalibur_mcp.db import scheduler_runs

logger = logging.getLogger(__name__)

# How long one publication may run before the wheel's watchdog considers it
# stale. Comfortably over the 900s ceiling a single dynamic block can ask for,
# and under the claim lease that would otherwise hand the post to another tick.
PUBLISH_MAX_RUNTIME_S = 960

# A publisher's value is its side effects — the tweet and the post row it
# updates. Nobody redeems its claim check, so the result only needs to outlive
# the job itself for debugging.
PUBLISH_RESULT_TTL_S = 3600


def _who() -> dict[str, str]:
    """Who is answering — the deployed identity behind this tick.

    A heartbeat that only says "alive" doesn't say WHICH build is alive, and this
    service has been bitten by a container serving cached bytes while reporting a
    fresh version. The commit is the honest half of that pair, so every tick
    carries both and the log can be read as evidence rather than reassurance.
    """
    from excalibur_mcp import __version__

    who = {"version": __version__}
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
    """Launch a publisher for every due post; return what was dispatched."""
    from tollbooth.tool_identity import capability_uuid

    # The tool that requested the work. Nothing is charged at launch — the
    # publisher bills the owner as it does the work — so this only ever serves
    # the wheel's rollback on a failed dispatch, where it is a no-op.
    tick_id = capability_uuid("process_scheduled_posts")
    run_id = await scheduler_runs.begin_run()
    now = datetime.now(timezone.utc)
    due = await posts_db.list_due(now.isoformat())

    launched: list[dict[str, Any]] = []
    contended: list[dict[str, Any]] = []

    for row in due:
        pid = row["post_id"]
        owner = row["npub"]
        # Claim first: the post leaves the due set before anyone starts work, so a
        # second tick arriving mid-publication finds nothing to do.
        if await posts_db.claim_due_post(pid) is None:
            contended.append({"post_id": pid, "owner": owner, "reason": "claimed_by_another_tick"})
            continue
        try:
            claim = await runtime.start_async_job(
                "publish_post", owner, {"post_id": pid},
                tool_id=tick_id, max_runtime_seconds=PUBLISH_MAX_RUNTIME_S,
                result_ttl_seconds=PUBLISH_RESULT_TTL_S,
            )
        except Exception as exc:  # noqa: BLE001 — one bad launch must not stop the rest
            # The post stays claimed; its lease expires and a later tick retries.
            logger.exception("scheduler: failed to launch publisher for %s", pid)
            contended.append({"post_id": pid, "owner": owner, "reason": f"launch_failed: {exc}"})
            continue
        launched.append({
            "post_id": pid, "owner": owner,
            "claim_check": (claim or {}).get("claim_check"),
        })

    summary = {"kind": "tick", "who": _who(), "processed": len(due),
               "launched": launched, "contended": contended,
               "upcoming": await _upcoming(now)}
    logger.info("scheduler: due=%d launched=%d", len(due), len(launched))
    try:
        await scheduler_runs.complete_run(run_id, summary)
    except Exception:  # noqa: BLE001 — audit is non-critical
        logger.exception("scheduler: failed to record run summary")
    return summary
