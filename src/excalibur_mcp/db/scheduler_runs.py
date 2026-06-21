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

from excalibur_mcp.db.neon import execute, fetch

logger = logging.getLogger(__name__)

# How many recent runs to retain. At one tick / 10 min this is ~8h of history —
# plenty to diagnose "why isn't this posting?" without unbounded growth.
_KEEP = 50


async def record_run(summary: dict[str, Any]) -> None:
    """Append a tick summary, then prune the ring to the newest ``_KEEP`` rows."""
    await execute(
        "INSERT INTO scheduler_runs (summary) VALUES ($1::jsonb)",
        json.dumps(summary),
    )
    await execute(
        """
        DELETE FROM scheduler_runs
        WHERE id NOT IN (
            SELECT id FROM scheduler_runs ORDER BY run_at DESC LIMIT $1
        )
        """,
        _KEEP,
    )


async def list_runs(limit: int = 25) -> list[dict[str, Any]]:
    """Recent runs, newest first: ``[{run_at, summary}]``."""
    lim = max(1, min(100, limit))
    return await fetch(
        "SELECT run_at, summary FROM scheduler_runs ORDER BY run_at DESC LIMIT $1",
        lim,
    )
