"""Daily follower readings — the history X does not keep for you.

X reports only the current follower count, so growth is visible only if
someone writes the count down. One row per (npub, UTC day): the first reading
of a day stands, later ones that day are ignored. Every statement carries
``npub`` so a patron only ever reads their own history.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from excalibur_mcp.db.neon import execute, fetch, fetchrow


def _today_utc() -> str:
    return datetime.now(timezone.utc).date().isoformat()


async def has_reading_today(npub: str) -> bool:
    """True when today's (UTC) reading is already recorded."""
    row = await fetchrow(
        "SELECT 1 AS hit FROM follower_snapshot WHERE npub = $1 AND captured_on = $2::date",
        npub,
        _today_utc(),
    )
    return row is not None


async def record_daily(npub: str, *, followers: int, following: int | None) -> None:
    """Record today's reading; a second reading the same day is a no-op."""
    await execute(
        """
        INSERT INTO follower_snapshot (npub, captured_on, followers, following)
        VALUES ($1, $2::date, $3, $4)
        ON CONFLICT (npub, captured_on) DO NOTHING
        """,
        npub,
        _today_utc(),
        int(followers),
        None if following is None else int(following),
    )


async def list_history(npub: str, *, days: int = 90) -> list[dict[str, Any]]:
    """Readings for the last ``days`` days, oldest first."""
    span = max(1, min(366, int(days)))
    rows = await fetch(
        """
        SELECT captured_on, followers, following
        FROM follower_snapshot
        WHERE npub = $1 AND captured_on >= (CURRENT_DATE - $2::int)
        ORDER BY captured_on ASC
        """,
        npub,
        span,
    )
    return [
        {
            "date": str(r.get("captured_on")),
            "followers": r.get("followers"),
            "following": r.get("following"),
        }
        for r in rows
    ]
