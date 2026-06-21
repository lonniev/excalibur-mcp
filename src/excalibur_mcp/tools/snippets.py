"""Snippet CRUD tool handlers.

Thin orchestration over ``db.snippets``: validate adversarial tool input and
keep handlers npub-scoped (a patron can only ever reach their own snippets).
These tools are *free* (proof-gated, no fare), so there is no debit to roll
back — invalid input simply ``raise ValueError`` and the standard error wrapper
returns ``tool_input_invalid``.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from excalibur_mcp.db import snippets as snippets_db

logger = logging.getLogger(__name__)

_NAME_MAX = 120
_BODY_MAX = 8000


def _require_uuid(snippet_id: str) -> str:
    try:
        return str(uuid.UUID(str(snippet_id)))
    except (ValueError, AttributeError, TypeError):
        raise ValueError("snippet id must be a valid UUID")


def _clean_name(name: str) -> str:
    name = (name or "").strip()
    if not name:
        raise ValueError("name is required")
    if len(name) > _NAME_MAX:
        raise ValueError(f"name exceeds {_NAME_MAX} characters")
    return name


def _clean_body(text: str) -> str:
    if text is None or text == "":
        raise ValueError("text is required")
    if len(text) > _BODY_MAX:
        raise ValueError(f"text exceeds {_BODY_MAX} characters")
    return text


def _clean_doc(doc: Any) -> dict[str, Any] | None:
    """A snippet's block/flag document is optional, but must be an object when
    present — tool input is treated as adversarial."""
    if doc is None:
        return None
    if not isinstance(doc, dict):
        raise ValueError("doc must be an object or null")
    return doc


async def list_(
    npub: str,
    *,
    sort_col: str = "favorite",
    sort_dir: str = "desc",
    page: int = 0,
    page_size: int = 25,
) -> dict[str, Any]:
    out = await snippets_db.list_snippets(
        npub, sort_col=sort_col, sort_dir=sort_dir, page=page, page_size=page_size,
    )
    return {"success": True, **out}


async def get(npub: str, *, snippet_id: str) -> dict[str, Any]:
    sid = _require_uuid(snippet_id)
    row = await snippets_db.get_snippet(npub, sid)
    if row is None:
        return {"success": False, "error_code": "snippet_not_found",
                "message": "No snippet with that id for this npub."}
    return {"success": True, "snippet": row}


async def save(
    npub: str,
    *,
    snippet_id: str = "",
    name: str = "",
    text: str = "",
    favorite: bool = False,
    doc: Any = None,
) -> dict[str, Any]:
    """Upsert: create when ``snippet_id`` is empty, else patch in place."""
    clean_doc = _clean_doc(doc)
    if snippet_id:
        sid = _require_uuid(snippet_id)
        row = await snippets_db.update_snippet(
            npub, sid,
            name=_clean_name(name) if name else None,
            text=_clean_body(text) if text else None,
            favorite=favorite,
            doc=clean_doc,
        )
        if row is None:
            return {"success": False, "error_code": "snippet_not_found",
                    "message": "No snippet with that id for this npub."}
        return {"success": True, "snippet": row}

    row = await snippets_db.create_snippet(
        npub, _clean_name(name), _clean_body(text), bool(favorite), doc=clean_doc,
    )
    return {"success": True, "snippet": row}


async def delete(npub: str, *, snippet_id: str) -> dict[str, Any]:
    sid = _require_uuid(snippet_id)
    deleted = await snippets_db.delete_snippet(npub, sid)
    if not deleted:
        return {"success": False, "error_code": "snippet_not_found",
                "message": "No snippet with that id for this npub."}
    return {"success": True, "deleted": True, "id": sid}
