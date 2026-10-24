"""Voice persistence — a per-npub singleton over the ``voice`` table.

A patron's writing **Voice** is one profile blurb plus a list of "banned
construction" chips (``{text, on}``). Unlike snippets there is exactly one Voice
per npub, so this is an upsert keyed on ``npub`` — no id, no list, no delete.
Every statement carries ``npub`` so a patron only ever touches their own Voice.

``bans`` is JSONB (a JSON array of ``{text, on}`` objects). The Neon HTTP SQL API
returns JSONB already parsed, but ``get_voice`` defensively json-decodes a string
in case a row was written by a different client.

``link_tags`` rides on the same row: the owner's shop-link tagging,
``{"on": bool, "hosts": [...]}``, or NULL when they never chose (see ``utm.py``).
"""

from __future__ import annotations

import json
import logging
from typing import Any

from excalibur_mcp.db.neon import fetchrow

logger = logging.getLogger(__name__)

_COLS = "npub, profile, bans, link_tags, updated_at"


def _coerce_bans(value: Any) -> list[dict[str, Any]]:
    """Return ``bans`` as a list whether the driver gave us a list or a JSON
    string. Anything unexpected collapses to an empty list."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return []
    return value if isinstance(value, list) else []


def _coerce_link_tags(value: Any) -> dict[str, Any] | None:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return None
    return value if isinstance(value, dict) else None


def _shaped(row: dict[str, Any]) -> dict[str, Any]:
    row["bans"] = _coerce_bans(row.get("bans"))
    row["link_tags"] = _coerce_link_tags(row.get("link_tags"))
    return row


async def get_voice(npub: str) -> dict[str, Any] | None:
    """The patron's Voice row, or ``None`` if they have not saved one yet."""
    row = await fetchrow(
        f"SELECT {_COLS} FROM voice WHERE npub = $1", npub
    )
    return _shaped(row) if row is not None else None


async def get_link_tags(npub: str) -> dict[str, Any] | None:
    """The owner's shop-link tagging setting, or ``None`` if never chosen."""
    row = await fetchrow("SELECT link_tags FROM voice WHERE npub = $1", npub)
    return _coerce_link_tags(row.get("link_tags")) if row else None


async def upsert_voice(
    npub: str, profile: str, bans: list[dict[str, Any]],
    link_tags: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create or replace the patron's single Voice; returns the stored row.

    ``link_tags`` of ``None`` keeps whatever the owner chose before, so an editor
    saving only the Voice never resets their tagging."""
    row = await fetchrow(
        f"INSERT INTO voice AS cur (npub, profile, bans, link_tags) "
        f"VALUES ($1, $2, $3::jsonb, $4::jsonb) "
        f"ON CONFLICT (npub) DO UPDATE SET "
        f"profile = EXCLUDED.profile, bans = EXCLUDED.bans, "
        f"link_tags = COALESCE(EXCLUDED.link_tags, cur.link_tags), updated_at = NOW() "
        f"RETURNING {_COLS}",
        npub,
        profile,
        json.dumps(bans),
        json.dumps(link_tags) if link_tags is not None else None,
    )
    assert row is not None  # INSERT/UPDATE … RETURNING always yields a row
    return _shaped(row)
