"""Scheduler-tick audit ring — persistence for ``process_scheduled_posts`` runs.

Each scheduler tick (fired by the Cloudflare cron Worker, or a manual trigger)
records its outcome ``summary`` here so the FE debug log can surface what the
Worker is doing — most usefully the per-post skip/error reasons that explain why
a due post didn't reach X. The vault is single-operator, so there is no npub
column: the whole table is the operator's.

Thin SQL over ``neon`` like ``db.posts``. ``summary`` is JSONB; the ring is
pruned to the newest ``_KEEP`` rows on each insert so it never grows unbounded.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from excalibur_mcp.db.neon import execute, fetch, fetchrow

logger = logging.getLogger(__name__)

# How many recent rows to retain. The ring holds both tick heartbeats (one per
# 30 min) and publication outcomes (one per post published), so a busy day of
# posting would otherwise crowd the heartbeats out of view.
_KEEP = 200

# The summary a run carries between ``begin_run`` and ``complete_run``. A row
# still wearing it is a tick that started and never came back.
STARTED: dict[str, Any] = {"status": "started"}


async def _prune() -> None:
    await execute(
        """
        DELETE FROM scheduler_runs
        WHERE id NOT IN (
            SELECT id FROM scheduler_runs ORDER BY run_at DESC LIMIT $1
        )
        """,
        _KEEP,
    )


async def begin_run() -> str | None:
    """Open a run row the moment the tick starts, before any work.

    A tick that dies mid-flight — the Cloudflare edge cuts the Worker's POST at
    ~100s and the server task goes with it — used to write NOTHING, so a wedged
    scheduler and a dead cron looked identical in the log. Opening the row first
    means the tick always leaves a mark: a row still reading ``status: started``
    is a tick that was cut off. Returns the row id, or ``None`` if the audit
    write failed (the caller still does the real work — audit is never a gate).
    """
    try:
        row = await fetchrow(
            "INSERT INTO scheduler_runs (summary) VALUES ($1::jsonb) RETURNING id",
            json.dumps(STARTED),
        )
        await _prune()
        return str(row["id"]) if row and row.get("id") else None
    except Exception:  # noqa: BLE001 — audit is non-critical
        logger.exception("scheduler: failed to open run row")
        return None


async def complete_run(run_id: str | None, summary: dict[str, Any]) -> None:
    """Close the run opened by ``begin_run`` with its outcome summary.

    Falls back to appending a fresh row when the open failed, so a tick's
    outcome is recorded either way.
    """
    if run_id is None:
        await record_run(summary)
        return
    await execute(
        "UPDATE scheduler_runs SET summary = $2::jsonb WHERE id = $1::uuid",
        run_id,
        json.dumps(summary),
    )


async def record_run(summary: dict[str, Any]) -> None:
    """Append a tick summary, then prune the ring to the newest ``_KEEP`` rows."""
    await execute(
        "INSERT INTO scheduler_runs (summary) VALUES ($1::jsonb)",
        json.dumps(summary),
    )
    await _prune()


async def list_runs(limit: int = 25) -> list[dict[str, Any]]:
    """Recent runs, newest first: ``[{run_at, summary}]``."""
    lim = max(1, min(100, limit))
    return await fetch(
        "SELECT run_at, summary FROM scheduler_runs ORDER BY run_at DESC LIMIT $1",
        lim,
    )


def _owned(items: Any, npub: str) -> list[dict[str, Any]]:
    return [e for e in (items or []) if isinstance(e, dict) and e.get("owner") == npub]


def scope_runs(
    runs: list[dict[str, Any]], npub: str, operator_npub: str
) -> list[dict[str, Any]]:
    """Owner-scope ring rows for the reader.

    The ring carries two kinds of row. A **tick** is the scheduler dispatching:
    it names every post it launched, across all owners. A **publication** is one
    publisher's outcome for one post, and belongs to exactly one owner.

    The operator sees everything. Any other reader sees every tick's heartbeat
    (``run_at`` — proof the cron is alive) with its per-post lists narrowed to
    THEIR OWN posts and ``processed`` recomputed to that count, plus only the
    publications for their own posts. No cross-patron activity leaks — not even
    an aggregate count.
    """
    if npub and npub == operator_npub:
        return runs

    scoped: list[dict[str, Any]] = []
    for r in runs:
        s = r.get("summary") or {}
        if s.get("kind") == "publication":
            # One post, one owner: show it whole or not at all.
            if s.get("owner") == npub:
                scoped.append(r)
            continue
        launched = _owned(s.get("launched"), npub)
        contended = _owned(s.get("contended"), npub)
        summary: dict[str, Any] = {
            "kind": "tick",
            "processed": len(launched) + len(contended),
            "launched": launched,
            "contended": contended,
        }
        # Which build answered. Not owner-specific, and it's what makes a
        # heartbeat evidence instead of reassurance — every reader gets it.
        if s.get("who"):
            summary["who"] = s["who"]
        # The forecast, narrowed to this reader's own queue. The tick's totals
        # describe every owner at once, so handing them over would leak exactly
        # the aggregate this function exists to withhold.
        mine = ((s.get("upcoming") or {}).get("by_owner") or {}).get(npub)
        summary["upcoming"] = dict(mine) if mine else {"count": 0}
        # A tick that never came back carries no per-post entries to scope, but
        # every reader should still see that it started and was cut off — that's
        # the difference between "the Worker is wedged" and "the cron is dead".
        if s.get("status"):
            summary["status"] = s["status"]
        scoped.append({"run_at": r.get("run_at"), "summary": summary})
    return scoped
