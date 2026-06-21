"""Snippet persistence — npub-scoped CRUD over the ``snippets`` table.

Reusable post fragments (openings, footers, CTAs) the patron saves once and
drops into the editor. Every statement carries ``npub = $1`` so a patron only
ever touches their own snippets — there is no cross-npub read or write here.
Business rules (validation) live in the tool layer; these are thin SQL.

A snippet carries the same ``doc`` block/flag document a post does, so the
editor is identical for both. ``doc`` is JSONB; the Neon HTTP SQL API returns
``rowCount`` (capital C), not ``rowcount``.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from excalibur_mcp.db.neon import execute, fetch, fetchrow

logger = logging.getLogger(__name__)

# ``body`` is the column; the wire/tool contract calls it ``text``.
_COLS = "id::text AS id, name, body AS text, doc, favorite, created_at, updated_at"

# Whitelisted sort keys → column expressions. Caller input only selects a key,
# so an unknown value falls back to a safe default rather than reaching the
# query as raw SQL (same safety posture as optionality-mcp's journal list).
_SORT_MAP: dict[str, str] = {
    "created": "created_at",
    "updated": "updated_at",
    "name": "lower(name)",
    "favorite": "favorite",
}

# Whitelisted date-filter targets → column (caller selects a key only).
_DATE_FIELDS: dict[str, str] = {
    "created": "created_at",
    "updated": "updated_at",
}


async def list_snippets(
    npub: str,
    sort_col: str = "favorite",
    sort_dir: str = "desc",
    page: int = 0,
    page_size: int = 25,
    search: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    date_field: str = "created",
) -> dict[str, Any]:
    """Server-side sorted, offset-paginated, optionally filtered snippet list.

    Returns FULL rows (incl. ``text`` and ``doc``) — snippets are small and the
    editor's favorite chiclets need the full text to insert. ``search`` is a
    case-insensitive regex matched against the name OR body (``~*``);
    ``date_from``/``date_to`` bound the ``date_field`` column (``_DATE_FIELDS``
    whitelist, default ``created_at``), end-inclusive. All user input is
    parameterized; the same WHERE drives the COUNT and the page. Shape:
    ``{snippets, total, page, page_size}``. ORDER BY comes from the fixed
    ``_SORT_MAP`` whitelist; ``created_at DESC`` is a stable tiebreak.
    """
    psize = max(1, min(200, page_size))
    pg = max(0, page)
    offset = pg * psize

    sort_expr = _SORT_MAP.get(sort_col, "favorite")
    row_dir = "DESC" if str(sort_dir).lower() == "desc" else "ASC"
    date_col = _DATE_FIELDS.get(date_field, "created_at")

    params: list[Any] = [npub]
    where = "npub = $1"
    if search:
        params.append(search)
        where += f" AND (name ~* ${len(params)} OR body ~* ${len(params)})"
    if date_from:
        params.append(date_from)
        where += f" AND {date_col} >= ${len(params)}::date"
    if date_to:
        params.append(date_to)
        where += f" AND {date_col} < (${len(params)}::date + interval '1 day')"

    total_row = await fetchrow(
        f"SELECT COUNT(*) AS n FROM snippets WHERE {where}", *params
    )
    total = int(total_row["n"]) if total_row and total_row.get("n") is not None else 0

    params.append(psize)
    limit_idx = len(params)
    params.append(offset)
    offset_idx = len(params)

    snippets = await fetch(
        f"SELECT {_COLS} FROM snippets WHERE {where} "
        f"ORDER BY {sort_expr} {row_dir}, created_at DESC "
        f"LIMIT ${limit_idx} OFFSET ${offset_idx}",
        *params,
    )
    return {"snippets": snippets, "total": total, "page": pg, "page_size": psize}


async def get_snippet(npub: str, snippet_id: str) -> dict[str, Any] | None:
    """Full snippet row, scoped to the owner (mirror of posts.get_post)."""
    return await fetchrow(
        f"SELECT {_COLS} FROM snippets WHERE id = $2::uuid AND npub = $1",
        npub,
        snippet_id,
    )


async def create_snippet(
    npub: str,
    name: str,
    text: str,
    favorite: bool,
    doc: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Insert a new snippet; returns the stored row."""
    row = await fetchrow(
        f"INSERT INTO snippets (npub, name, body, favorite, doc) "
        f"VALUES ($1, $2, $3, $4, $5::jsonb) RETURNING {_COLS}",
        npub,
        name,
        text,
        favorite,
        json.dumps(doc) if doc is not None else None,
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
    doc: dict[str, Any] | None = None,
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
    if doc is not None:
        args.append(json.dumps(doc))
        sets.append(f"doc = ${len(args)}::jsonb")
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
