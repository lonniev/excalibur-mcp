"""Conversation-lead tool handlers.

Find X questioners a patron could answer with a marketing reply. eXcalibur's
whole job here is to deliver the questioner — thread, author signal, score —
fast and cheaply; what backs the reply is the patron's own business, in their
own client, and the reply itself is posted by hand. Read-only on X: nothing in
this module posts, likes, follows, replies or DMs.

Shapes mirror the Snippet tools: the catalog, listing and status tools are
free (proof-gated, npub-scoped) and simply ``raise ValueError`` on bad input;
``find`` is priced because every post X returns is billed to the operator's X
project, and it refunds explicitly whenever it stops before X was read.
"""

from __future__ import annotations

import logging
import re
import uuid
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from excalibur_mcp import conversation_scoring as scoring
from excalibur_mcp.db import conversations as db
from excalibur_mcp.tools._filters import validate_search

logger = logging.getLogger(__name__)

_NAME_MAX = 120
_TEXT_MAX = 1000
_LOCATION_MAX = 64
MAX_POSTS_FLOOR = 10
MAX_POSTS_CAP = 300
TOP_N = 10
_SINCE_ID_WINDOW = timedelta(days=7)
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _require_uuid(value: str, what: str) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, AttributeError, TypeError):
        raise ValueError(f"{what} must be a valid UUID")


def _clean_name(name: str) -> str:
    name = (name or "").strip()
    if not name:
        raise ValueError("name is required")
    if len(name) > _NAME_MAX:
        raise ValueError(f"name exceeds {_NAME_MAX} characters")
    return name


def _clean_query(query: str) -> str:
    q = (query or "").strip()
    if not q:
        raise ValueError("query is required")
    if len(q) > scoring.MAX_CLAUSE:
        raise ValueError(
            f"query exceeds {scoring.MAX_CLAUSE} characters — X allows {scoring.MAX_EFFECTIVE_QUERY} "
            "and the safe defaults plus your own-account exclusion use the rest"
        )
    if _CONTROL_RE.search(q):
        raise ValueError("query must not contain control characters")
    if "?" in q:
        raise ValueError("X search has no '?' operator — spell the question out as phrases")
    return q


def _clean_status(status: str) -> str:
    s = (status or "").strip().lower()
    if s not in db.STATUSES:
        raise ValueError(f"status must be one of {', '.join(db.STATUSES)}")
    return s


def _clean_statuses(csv: str) -> list[str]:
    return [_clean_status(part) for part in (csv or "").split(",") if part.strip()]


def _clamp_int(value: Any, lo: int, hi: int, what: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{what} must be an integer")
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{what} must be an integer")
    return max(lo, min(hi, n))


_REPLY_MAX = 280


def _url_for(row: dict[str, Any]) -> str:
    return f"https://x.com/{row.get('author_username')}/status/{row.get('tweet_id')}"


def _with_url(row: dict[str, Any]) -> dict[str, Any]:
    out = {**row, "url": _url_for(row)}
    rid = row.get("reply_tweet_id")
    out["reply_url"] = f"https://x.com/i/status/{rid}" if rid else None
    return out


def _clean_reply(text: str) -> str:
    t = (text or "").strip()
    if not t:
        raise ValueError("reply text is required")
    if len(t) > _REPLY_MAX:
        raise ValueError(f"reply exceeds {_REPLY_MAX} characters")
    return t


# ---------------------------------------------------------------------------
# Catalog (free)
# ---------------------------------------------------------------------------


async def list_queries(npub: str) -> dict[str, Any]:
    return {"success": True, "queries": await db.list_queries(npub)}


async def save_query(
    npub: str,
    *,
    query_id: str = "",
    name: str = "",
    query: str = "",
    weights: Any = None,
    safe_defaults: bool | None = None,
) -> dict[str, Any]:
    """Create when ``query_id`` is empty, else patch only the provided fields."""
    clean_weights = scoring.validate_weights(weights) if weights is not None else None
    if query_id:
        qid = _require_uuid(query_id, "query_id")
        new_name = _clean_name(name) if name else None
        if new_name:
            clash = await db.find_query_by_name(npub, new_name)
            if clash and clash["id"] != qid:
                return {"success": False, "error_code": "conversation_query_name_taken",
                        "message": "Another saved query already has that name."}
        row = await db.update_query(
            npub, qid,
            name=new_name,
            query=_clean_query(query) if query else None,
            weights=clean_weights,
            safe_defaults=safe_defaults,
        )
        if row is None:
            return {"success": False, "error_code": "conversation_query_not_found",
                    "message": "No saved query with that id for this npub."}
        return {"success": True, "query": row}

    clean_name = _clean_name(name)
    clean_q = _clean_query(query)
    if await db.find_query_by_name(npub, clean_name):
        return {"success": False, "error_code": "conversation_query_name_taken",
                "message": "A saved query already has that name."}
    if await db.count_queries(npub) >= db.QUERY_LIMIT_PER_NPUB:
        return {"success": False, "error_code": "conversation_query_limit",
                "message": f"At most {db.QUERY_LIMIT_PER_NPUB} saved queries per npub."}
    row = await db.create_query(
        npub, name=clean_name, query=clean_q, weights=clean_weights or {},
        safe_defaults=True if safe_defaults is None else bool(safe_defaults),
    )
    return {"success": True, "query": row}


async def delete_query(npub: str, *, query_id: str) -> dict[str, Any]:
    qid = _require_uuid(query_id, "query_id")
    if not await db.delete_query(npub, qid):
        return {"success": False, "error_code": "conversation_query_not_found",
                "message": "No saved query with that id for this npub."}
    return {"success": True, "deleted": True, "id": qid}


# ---------------------------------------------------------------------------
# Leads (free)
# ---------------------------------------------------------------------------


async def list_(
    npub: str,
    *,
    query_id: str = "",
    status: str = "",
    min_score: int = 0,
    sort_col: str = "score",
    sort_dir: str = "desc",
    page: int = 0,
    page_size: int = 25,
    search: str = "",
    date_from: str = "",
    date_to: str = "",
    date_field: str = "found",
) -> dict[str, Any]:
    qid: str | None = None
    adhoc = False
    if query_id == "adhoc":
        adhoc = True
    elif query_id:
        qid = _require_uuid(query_id, "query_id")
    out = await db.list_conversations(
        npub,
        query_id=qid,
        adhoc_only=adhoc,
        statuses=_clean_statuses(status) or None,
        min_score=_clamp_int(min_score, 0, 100, "min_score"),
        sort_col=sort_col, sort_dir=sort_dir, page=page, page_size=page_size,
        search=validate_search(search), date_from=date_from or None,
        date_to=date_to or None, date_field=date_field or "found",
    )
    out["conversations"] = [_with_url(r) for r in out["conversations"]]
    return {"success": True, **out}


async def set_status(npub: str, *, conversation_id: str, status: str) -> dict[str, Any]:
    rid = _require_uuid(conversation_id, "conversation_id")
    row = await db.set_status(npub, rid, _clean_status(status))
    if row is None:
        return {"success": False, "error_code": "conversation_not_found",
                "message": "No lead with that id for this npub."}
    return {"success": True, "conversation": _with_url(row)}


# ---------------------------------------------------------------------------
# find (priced)
# ---------------------------------------------------------------------------


def _parse_ts(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _row_from(
    tweet: dict[str, Any], author: dict[str, Any], *,
    query_id: str | None, query_text: str, score: int, signals: list[str],
) -> dict[str, Any]:
    metrics = tweet.get("public_metrics") or {}
    author_metrics = author.get("public_metrics") or {}
    tid = str(tweet.get("id") or "")
    cid = str(tweet.get("conversation_id") or tid)
    location = str(author.get("location") or "").strip()[:_LOCATION_MAX] or None
    return {
        "query_id": query_id,
        "query_text": query_text,
        "conversation_id": cid,
        "tweet_id": tid,
        "author_id": str(tweet.get("author_id") or ""),
        "author_username": str(author.get("username") or ""),
        "author_followers": author_metrics.get("followers_count"),
        "author_location": location,
        "text": str(tweet.get("text") or "")[:_TEXT_MAX],
        "posted_at": tweet.get("created_at"),
        "reply_count": metrics.get("reply_count") or 0,
        "like_count": metrics.get("like_count") or 0,
        "is_reply": bool(tweet.get("in_reply_to_user_id")) or cid != tid,
        "has_media": "attachments" in tweet,
        "score": score,
        "signals": signals,
    }


async def find(
    npub: str,
    *,
    runtime: Any,
    tool_id: str,
    prepare_client: Callable[[str, str], Awaitable[Any]],
    x_error_to_response: Callable[[Any, str], Awaitable[dict[str, Any]]],
    query_id: str = "",
    query: str = "",
    max_posts: int = 100,
    weights: Any = None,
    safe_defaults: bool = True,
) -> dict[str, Any]:
    """Run one query against X's 7-day window, score what came back, store it.

    ``prepare_client`` is the server's ``_prepare_x_client`` (it refunds on an
    OAuth situation); ``x_error_to_response`` is ``_x_api_error_to_response``.
    Both are passed in so this handler can be exercised without the server.
    """
    from excalibur_mcp.x_client import XAPIError

    if bool(query_id) == bool(query):
        raise ValueError("pass exactly one of query_id or query")
    cap = _clamp_int(max_posts, MAX_POSTS_FLOOR, MAX_POSTS_CAP, "max_posts")
    call_weights = scoring.validate_weights(weights) if weights is not None else {}

    saved: dict[str, Any] | None = None
    if query_id:
        qid = _require_uuid(query_id, "query_id")
        saved = await db.get_query(npub, qid)
        if saved is None:
            await runtime.rollback_debit(tool_id, npub)
            return {"success": False, "error_code": "conversation_query_not_found",
                    "message": "No saved query with that id for this npub."}
        query_text = _clean_query(saved["query"])
        use_defaults = bool(saved.get("safe_defaults", True))
        saved_weights = saved.get("weights") or {}
        if not isinstance(saved_weights, dict):
            saved_weights = {}
    else:
        qid = None
        query_text = _clean_query(query)
        use_defaults = bool(safe_defaults)
        saved_weights = {}
    merged_weights = scoring.effective_weights(saved_weights, call_weights)

    client_or_err = await prepare_client(tool_id, npub)
    if isinstance(client_or_err, dict):
        return client_or_err
    client, _ = client_or_err

    try:
        me = await client.get_me()
    except XAPIError as exc:
        await runtime.rollback_debit(tool_id, npub)
        return await x_error_to_response(exc, npub)
    own_id = str(me.get("id") or "")

    effective = scoring.compose_query(query_text, own_id, use_defaults)

    since_id: str | None = None
    if saved and saved.get("since_id"):
        last_run = _parse_ts(saved.get("last_run_at"))
        if last_run and datetime.now(timezone.utc) - last_run <= _SINCE_ID_WINDOW:
            since_id = str(saved["since_id"])

    tweets: list[dict[str, Any]] = []
    users: dict[str, dict[str, Any]] = {}
    posts_read = 0
    pages = 0
    newest_id: str | None = None
    truncated: str | None = None
    next_token: str | None = None
    while posts_read < cap:
        want = max(MAX_POSTS_FLOOR, min(100, cap - posts_read))
        try:
            page = await client.search_recent(
                effective, max_results=want, next_token=next_token, since_id=since_id,
            )
        except XAPIError as exc:
            if posts_read == 0:
                # Refund once, here — a raise would make the decorator refund
                # again (rollback_debit credits unconditionally).
                await runtime.rollback_debit(tool_id, npub)
                if exc.status_code == 400:
                    return {"success": False, "error_code": "tool_input_invalid",
                            "message": f"X rejected the query: {exc.detail}"}
                return await x_error_to_response(exc, npub)
            truncated = "rate_limited" if exc.status_code == 429 else "upstream_error"
            break
        pages += 1
        posts_read += int(page.get("result_count") or 0)
        tweets.extend(page.get("tweets") or [])
        users.update(page.get("users") or {})
        if newest_id is None and page.get("newest_id"):
            newest_id = str(page["newest_id"])
        next_token = page.get("next_token")
        if not next_token:
            break
    if posts_read >= cap and next_token:
        truncated = "max_posts"

    now = datetime.now(timezone.utc)
    skipped_own = 0
    best: dict[str, dict[str, Any]] = {}
    for tweet in tweets:
        author_id = str(tweet.get("author_id") or "")
        if own_id and author_id == own_id:
            skipped_own += 1
            continue
        author = users.get(author_id) or {}
        score, signals = scoring.score_tweet(tweet, author, weights=merged_weights, now=now)
        row = _row_from(tweet, author, query_id=qid, query_text=query_text,
                        score=score, signals=signals)
        if not row["tweet_id"] or not row["author_id"]:
            continue
        held = best.get(row["conversation_id"])
        if held is None or row["score"] > held["score"]:
            best[row["conversation_id"]] = row
    kept = list(best.values())
    skipped_dupe = len(tweets) - skipped_own - len(kept)

    await db.purge_stale(npub)
    new, refreshed = await db.upsert_conversations(npub, kept) if kept else (0, 0)
    if qid:
        await db.mark_query_run(npub, qid, since_id=newest_id, posts_read=posts_read)

    logger.info(
        "find_conversations: pages=%d posts_read=%d kept=%d new=%d refreshed=%d truncated=%s",
        pages, posts_read, len(kept), new, refreshed, truncated,
    )
    kept.sort(key=lambda r: -r["score"])
    return {
        "success": True,
        "query_id": qid,
        "query": query_text,
        "effective_query": effective,
        "posts_read": posts_read,
        "pages": pages,
        "new": new,
        "refreshed": refreshed,
        "skipped_own": skipped_own,
        "skipped_dupe": max(0, skipped_dupe),
        "since_id": since_id,
        "newest_id": newest_id,
        "truncated_reason": truncated,
        "top": [_with_url(r) for r in kept[:TOP_N]],
    }


# ---------------------------------------------------------------------------
# reply (priced — a write to X)
# ---------------------------------------------------------------------------


async def reply(
    npub: str,
    *,
    runtime: Any,
    tool_id: str,
    prepare_client: Callable[[str, str], Awaitable[Any]],
    x_error_to_response: Callable[[Any, str], Awaitable[dict[str, Any]]],
    conversation_id: str,
    text: str,
) -> dict[str, Any]:
    """Post the patron's reply into a lead's thread, then mark it engaged.

    The patron wrote the words and pressed the button — eXcalibur only carries
    them. The row flips to ``engaged`` on X's confirmation and not before, so a
    refused post leaves the lead exactly as it was; the fare is refunded when
    nothing was posted.
    """
    from excalibur_mcp.formatter import markdown_to_unicode
    from excalibur_mcp.x_client import XAPIError

    rid = _require_uuid(conversation_id, "conversation_id")
    body = _clean_reply(text)
    row = await db.get_conversation(npub, rid)
    if row is None:
        await runtime.rollback_debit(tool_id, npub)
        return {"success": False, "error_code": "conversation_not_found",
                "message": "No lead with that id for this npub."}

    client_or_err = await prepare_client(tool_id, npub)
    if isinstance(client_or_err, dict):
        return client_or_err
    client, _ = client_or_err

    try:
        posted = await client.post_tweet(markdown_to_unicode(body), in_reply_to=row["tweet_id"])
    except XAPIError as exc:
        await runtime.rollback_debit(tool_id, npub)
        return await x_error_to_response(exc, npub)

    updated = await db.record_reply(npub, rid, str(posted["tweet_id"]))
    logger.info("reply_to_conversation: posted reply for lead %s", rid)
    return {
        "success": True,
        "reply": {"tweet_id": posted["tweet_id"], "url": posted["tweet_url"]},
        "conversation": _with_url(updated or row),
    }
