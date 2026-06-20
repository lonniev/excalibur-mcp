"""Snippet persistence — npub-scoped CRUD over the ``snippets`` table.

Reusable post fragments (openings, footers, CTAs) the patron saves once and
drops into the editor. Every statement carries ``npub = $1`` so a patron only
ever touches their own snippets — there is no cross-npub read or write here.
Business rules (validation) live in the tool layer; these are thin SQL.

The Neon HTTP SQL API returns ``rowCount`` (capital C), not ``rowcount``.
"""

from __future__ import annotations

import logging
from typing import Any

from excalibur_mcp.db.neon import execute, fetch, fetchrow

logger = logging.getLogger(__name__)

# ``body`` is the column; the wire/tool contract calls it ``text``.
_COLS = "id::text AS id, name, body AS text, favorite, created_at, updated_at"


async def list_snippets(npub: str) -> list[dict[str, Any]]:
    """All of a patron's snippets — favorites first, then newest."""
    return await fetch(
        f"SELECT {_COLS} FROM snippets WHERE npub = $1 "
        "ORDER BY favorite DESC, created_at DESC",
        npub,
    )


async def create_snippet(
    npub: str, name: str, text: str, favorite: bool
) -> dict[str, Any]:
    """Insert a new snippet; returns the stored row."""
    row = await fetchrow(
        f"INSERT INTO snippets (npub, name, body, favorite) "
        f"VALUES ($1, $2, $3, $4) RETURNING {_COLS}",
        npub, name, text, favorite,
    )
    assert row is not None  # INSERT … RETURNING always yields a row
    return row


async def update_snippet(
    npub: str,
    snippet_id: str,
    *,
    name: str | None = None,
    text: str | None = None,
    favorite: bool | None = None,
) -> dict[str, Any] | None:
    """Patch the provided fields of one owner-scoped snippet.

    Returns the updated row, or ``None`` if no row matched (wrong id, or not
    this npub's snippet). Only non-``None`` fields are written.
    """
    sets: list[str] = []
    args: list[Any] = [npub, snippet_id]
    if name is not None:
        args.append(name)
        sets.append(f"name = ${len(args)}")
    if text is not None:
        args.append(text)
        sets.append(f"body = ${len(args)}")
    if favorite is not None:
        args.append(favorite)
        sets.append(f"favorite = ${len(args)}")
    if not sets:
        # Nothing to change — return the current row as-is.
        return await fetchrow(
            f"SELECT {_COLS} FROM snippets WHERE id = $2::uuid AND npub = $1",
            *args,
        )
    set_clause = ", ".join(sets) + ", updated_at = NOW()"
    return await fetchrow(
        f"UPDATE snippets SET {set_clause} "
        f"WHERE id = $2::uuid AND npub = $1 RETURNING {_COLS}",
        *args,
    )


async def delete_snippet(npub: str, snippet_id: str) -> bool:
    """Remove one owner-scoped snippet. Returns whether a row was deleted."""
    res = await execute(
        "DELETE FROM snippets WHERE id = $1::uuid AND npub = $2",
        snippet_id, npub,
    )
    return (res.get("rowCount") or 0) > 0
