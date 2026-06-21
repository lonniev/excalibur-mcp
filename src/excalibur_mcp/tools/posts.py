"""Posts CRUD tool handlers.

Thin orchestration over ``db.posts``: validate adversarial tool input, enforce
idempotency, and keep billing honest. The ``@paid_tool`` decorator (in
``server.py``) debits *before* these run and — with ``catch_errors=True`` —
rolls the debit back if we ``raise``. So:

- **Invalid input** → ``raise ValueError`` → decorator refunds + returns
  ``tool_input_invalid``.
- **Idempotent retry / not-found write** → we refund explicitly via
  ``runtime.rollback_debit`` and return a plain situation dict (no double charge).

All handlers are npub-scoped at the SQL layer (``db.posts``): a patron can only
reach their own posts.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from excalibur_mcp.db import posts as posts_db

logger = logging.getLogger(__name__)

# "sent" is a terminal status the FE sets after a successful post_tweet (and the
# scheduler after a fired post). It's valid on both create (compose → Post It on
# a brand-new draft) and patch (Post It on an existing draft).
_CREATE_STATUS = {"draft", "scheduled", "sent"}
_PATCH_STATUS = {"draft", "scheduled", "archived", "sent"}
_PATCHABLE = {"doc", "publish_at", "recurrence", "cease_at", "status", "tweet_url"}
_FREQ = {"daily", "weekly", "monthly"}


# -- validation --------------------------------------------------------------

def _require_uuid(post_id: str) -> str:
    try:
        return str(uuid.UUID(str(post_id)))
    except (ValueError, AttributeError, TypeError):
        raise ValueError("post_id must be a valid UUID")


def _validate_recurrence(recurrence: Any) -> None:
    if recurrence is None:
        return
    if not isinstance(recurrence, dict):
        raise ValueError("recurrence must be an object or null")
    freq = recurrence.get("freq")
    if freq not in _FREQ:
        raise ValueError(f"recurrence.freq must be one of {sorted(_FREQ)}")
    interval = recurrence.get("interval", 1)
    if not isinstance(interval, int) or interval < 1:
        raise ValueError("recurrence.interval must be a positive integer")


# -- handlers ----------------------------------------------------------------

async def create(
    runtime: Any,
    tool_id: str,
    *,
    doc: Any,
    text_cache: str,
    publish_at: str | None,
    recurrence: Any,
    cease_at: str | None,
    status: str,
    client_req_id: str,
    npub: str,
    tweet_url: str = "",
) -> dict[str, Any]:
    if not isinstance(doc, dict) or not doc:
        raise ValueError("doc must be a non-empty object")
    if status not in _CREATE_STATUS:
        raise ValueError(f"status must be one of {sorted(_CREATE_STATUS)}")
    if status == "scheduled" and not publish_at:
        raise ValueError("a scheduled post requires publish_at")
    _validate_recurrence(recurrence)

    # Idempotency: a repeated client_req_id returns the prior post, no 2nd charge.
    if client_req_id:
        prior = await posts_db.find_by_req_id(npub, client_req_id)
        if prior:
            await runtime.rollback_debit(tool_id, npub)
            return {
                "post_id": prior["post_id"],
                "status": prior["status"],
                "created_at": str(prior.get("created_at") or ""),
                "idempotent": True,
            }

    row = await posts_db.create_post(
        npub=npub, doc=doc, text_cache=text_cache or None,
        publish_at=publish_at or None, recurrence=recurrence,
        cease_at=cease_at or None, status=status,
        client_req_id=client_req_id or None, tweet_url=tweet_url or None,
    )
    return {
        "post_id": row["post_id"],
        "status": row["status"],
        "created_at": str(row.get("created_at") or ""),
    }


async def get(runtime: Any, tool_id: str, *, post_id: str, npub: str) -> dict[str, Any]:
    pid = _require_uuid(post_id)
    row = await posts_db.get_post(npub, pid)
    if not row:
        # A read that found nothing still cost a lookup — but a missing/foreign
        # post is a clean "not found" situation, so refund and report it.
        await runtime.rollback_debit(tool_id, npub)
        return {"success": False, "error_code": "post_not_found",
                "error": f"No post {pid} owned by this npub."}
    return {
        "post_id": row["post_id"], "npub": row["npub"], "status": row["status"],
        "doc": row["doc"], "text_cache": row.get("text_cache"),
        "publish_at": str(row["publish_at"]) if row.get("publish_at") else None,
        "recurrence": row.get("recurrence"),
        "cease_at": str(row["cease_at"]) if row.get("cease_at") else None,
        "last_sent_at": str(row["last_sent_at"]) if row.get("last_sent_at") else None,
        "created_at": str(row.get("created_at") or ""),
        "updated_at": str(row.get("updated_at") or ""),
    }


async def list_(
    runtime: Any, tool_id: str, *, status: str, sort_col: str, sort_dir: str,
    page: int, page_size: int, npub: str,
) -> dict[str, Any]:
    return await posts_db.list_posts(
        npub, status=status or None, sort_col=sort_col, sort_dir=sort_dir,
        page=page, page_size=page_size,
    )


async def update(
    runtime: Any,
    tool_id: str,
    *,
    post_id: str,
    patch: Any,
    text_cache: Any,
    client_req_id: str,
    npub: str,
) -> dict[str, Any]:
    pid = _require_uuid(post_id)
    if not isinstance(patch, dict):
        raise ValueError("patch must be an object")
    unknown = set(patch) - _PATCHABLE
    if unknown:
        raise ValueError(f"unknown patch keys: {sorted(unknown)}")
    if "status" in patch and patch["status"] not in _PATCH_STATUS:
        raise ValueError(f"status must be one of {sorted(_PATCH_STATUS)}")
    if "recurrence" in patch:
        _validate_recurrence(patch["recurrence"])

    # Idempotency: a repeated client_req_id (debounced autosave retry) is a no-op.
    if client_req_id:
        stored = await posts_db.current_req_id(npub, pid)
        if stored is not None and stored == client_req_id:
            await runtime.rollback_debit(tool_id, npub)
            cur = await posts_db.get_post(npub, pid)
            return {"post_id": pid,
                    "status": cur["status"] if cur else "unknown",
                    "updated_at": str(cur.get("updated_at") or "") if cur else "",
                    "idempotent": True}

    row = await posts_db.update_post(
        npub, pid, patch,
        text_cache=text_cache if text_cache not in ("", None) else None,
        client_req_id=client_req_id or None,
    )
    if not row:
        await runtime.rollback_debit(tool_id, npub)
        return {"success": False, "error_code": "post_not_found",
                "error": f"No post {pid} owned by this npub."}
    return {"post_id": row["post_id"], "status": row["status"],
            "updated_at": str(row.get("updated_at") or "")}


async def delete(
    runtime: Any, tool_id: str, *, post_id: str, hard: bool, npub: str,
) -> dict[str, Any]:
    pid = _require_uuid(post_id)
    if hard:
        removed = await posts_db.hard_delete(npub, pid)
        if not removed:
            await runtime.rollback_debit(tool_id, npub)
            return {"success": False, "error_code": "post_not_found",
                    "error": f"No post {pid} owned by this npub."}
        return {"post_id": pid, "deleted": True}

    row = await posts_db.soft_delete(npub, pid)
    if not row:
        await runtime.rollback_debit(tool_id, npub)
        return {"success": False, "error_code": "post_not_found",
                "error": f"No post {pid} owned by this npub."}
    return {"post_id": row["post_id"], "status": row["status"]}
