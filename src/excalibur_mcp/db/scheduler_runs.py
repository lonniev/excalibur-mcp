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

# How many recent runs to retain. At one tick / 30 min this is ~25h of history —
# plenty to diagnose "why isn't this posting?" without unbounded growth.
_KEEP = 50

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


def scope_runs(
    runs: list[dict[str, Any]], npub: str, operator_npub: str
) -> list[dict[str, Any]]:
    """Owner-scope ring rows for the reader.

    The operator sees every run in full. Any other reader sees the per-tick
    heartbeat (``run_at`` — proof the Worker ran) plus only the per-post entries
    (posted/skipped/errors) for THEIR OWN posts, keyed by the ``owner`` npub the
    scheduler records on each entry. ``processed`` is recomputed to the reader's
    OWN entry count — never the global total — so no cross-patron activity (not
    even an aggregate count) leaks between patrons.
    """
    if npub and npub == operator_npub:
        return runs

    def _mine(items: Any) -> list[dict[str, Any]]:
        return [e for e in (items or []) if isinstance(e, dict) and e.get("owner") == npub]

    scoped: list[dict[str, Any]] = []
    for r in runs:
        s = r.get("summary") or {}
        posted = _mine(s.get("posted"))
        skipped = _mine(s.get("skipped"))
        errors = _mine(s.get("errors"))
        deferred = _mine(s.get("deferred"))
        summary: dict[str, Any] = {
            "processed": len(posted) + len(skipped) + len(errors) + len(deferred),
            "posted": posted,
            "skipped": skipped,
            "errors": errors,
            "deferred": deferred,
        }
        # A tick that never came back carries no per-post entries to scope, but
        # every reader should still see that it started and was cut off — that's
        # the difference between "the Worker is wedged" and "the cron is dead".
        if s.get("status"):
            summary["status"] = s["status"]
        scoped.append({"run_at": r.get("run_at"), "summary": summary})
    return scoped
