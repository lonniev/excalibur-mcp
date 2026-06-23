"""Voice persistence — a per-npub singleton over the ``voice`` table.

A patron's writing **Voice** is one profile blurb plus a list of "banned
construction" chips (``{text, on}``). Unlike snippets there is exactly one Voice
per npub, so this is an upsert keyed on ``npub`` — no id, no list, no delete.
Every statement carries ``npub`` so a patron only ever touches their own Voice.

``bans`` is JSONB (a JSON array of ``{text, on}`` objects). The Neon HTTP SQL API
returns JSONB already parsed, but ``get_voice`` defensively json-decodes a string
in case a row was written by a different client.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from excalibur_mcp.db.neon import fetchrow

logger = logging.getLogger(__name__)

_COLS = "npub, profile, bans, updated_at"


def _coerce_bans(value: Any) -> list[dict[str, Any]]:
    """Return ``bans`` as a list whether the driver gave us a list or a JSON
    string. Anything unexpected collapses to an empty list."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return []
    return value if isinstance(value, list) else []


async def get_voice(npub: str) -> dict[str, Any] | None:
    """The patron's Voice row, or ``None`` if they have not saved one yet."""
    row = await fetchrow(
        f"SELECT {_COLS} FROM voice WHERE npub = $1", npub
    )
    if row is not None:
        row["bans"] = _coerce_bans(row.get("bans"))
    return row


async def upsert_voice(
    npub: str, profile: str, bans: list[dict[str, Any]]
) -> dict[str, Any]:
    """Create or replace the patron's single Voice; returns the stored row."""
    row = await fetchrow(
        f"INSERT INTO voice (npub, profile, bans) VALUES ($1, $2, $3::jsonb) "
        f"ON CONFLICT (npub) DO UPDATE SET "
        f"profile = EXCLUDED.profile, bans = EXCLUDED.bans, updated_at = NOW() "
        f"RETURNING {_COLS}",
        npub,
        profile,
        json.dumps(bans),
    )
    assert row is not None  # INSERT/UPDATE … RETURNING always yields a row
    row["bans"] = _coerce_bans(row.get("bans"))
    return row
