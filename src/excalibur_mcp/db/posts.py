"""Stored-post persistence — CRUD + scheduler queries.

Low-level, npub-scoped CRUD over the ``posts`` table. Every statement carries
``npub = $1`` so a patron can only ever touch their own posts — there is no
cross-npub read or write at this layer. Business rules (idempotency, billing,
recurrence math) live in the tool/scheduler layers; these functions are
deliberately thin SQL.

``doc`` and ``recurrence`` are JSONB; timestamps are ISO-8601 strings cast to
``timestamptz`` (``None`` → SQL NULL). The Neon HTTP SQL API returns ``rowCount``
(capital C), not ``rowcount``.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from excalibur_mcp.db.neon import execute, fetch, fetchrow

logger = logging.getLogger(__name__)

# Columns returned for a full single-post read.
_FULL_COLS = (
    "id::text AS post_id, npub, status, title, doc, render, text_cache, "
    "publish_at, recurrence, cease_at, last_sent_at, tweet_url, "
    "last_attempt_at, last_attempt_reason, last_attempt_detail, "
    "template_id::text AS template_id, "
    "created_at, updated_at"
)

# Whitelisted sort keys → column expressions. Caller input only selects a key,
# so an unknown value falls back to a safe default rather than reaching the
# query as raw SQL (same safety posture as optionality-mcp's journal list).
_SORT_MAP: dict[str, str] = {
    "created": "created_at",
    "updated": "updated_at",
    "status": "status",
    "scheduled": "publish_at",
}

# Whitelisted date-filter targets → column. Like _SORT_MAP, the caller only
# selects a key; the column expression never comes from input.
_DATE_FIELDS: dict[str, str] = {
    "created": "created_at",
    "updated": "updated_at",
    "scheduled": "publish_at",
    "sent": "last_sent_at",
}

# Patch keys a caller may set on update, mapped to their column cast. Caller
# input only selects a key; the column expression never comes from the caller,
# so an unknown patch key can't reach the query as raw SQL.
_PATCHABLE: dict[str, str] = {
    "title": "",
    "doc": "::jsonb",
    "publish_at": "::timestamptz",
    "recurrence": "::jsonb",
    "cease_at": "::timestamptz",
    "status": "",
    "tweet_url": "",
}
_JSON_KEYS = {"doc", "recurrence"}


# Marks the resolver stamps on a block while building ONE firing. They describe a
# render, never authored intent, so they never belong in `doc`.
_PER_FIRING_BLOCK_KEYS = frozenset({"resolved", "fellBack"})


def _authored(doc: Any) -> Any:
    """``doc`` as the author meant it: per-firing marks stripped from every block.

    ``resolved`` on a dynamic block in ``doc`` is the signature of a template
    flattened before the doc/render split, and ``resolver._lost_prompts`` reads it
    to refuse building from a destroyed prompt. That detector turns on the FE: a
    surface that loads a damaged block and PATCHes it back would re-assert the
    flag, and the template would then be diagnosed prompt-lost forever while
    holding the prompt its owner had just carefully rewritten.

    Stripping on the way in makes every surface's behaviour irrelevant — there is
    one gate, and it is the one immediately before the column.
    """
    if not isinstance(doc, dict) or not isinstance(doc.get("blocks"), list):
        return doc
    return {**doc, "blocks": [
        {k: v for k, v in b.items() if k not in _PER_FIRING_BLOCK_KEYS}
        if isinstance(b, dict) else b
        for b in doc["blocks"]
    ]}


async def create_post(
    npub: str,
    doc: dict[str, Any],
    text_cache: str | None,
    publish_at: str | None,
    recurrence: dict[str, Any] | None,
    cease_at: str | None,
    status: str,
    client_req_id: str | None,
    tweet_url: str | None = None,
    title: str | None = None,
) -> dict[str, Any]:
    """Insert a post; return ``{post_id, status, created_at}``.

    A post created already ``sent`` (the FE's Post It on a brand-new draft)
    stamps ``last_sent_at`` server-side, so every send records its time.
    """
    row = await fetchrow(
        """
        INSERT INTO posts
            (npub, status, title, doc, text_cache, publish_at, recurrence, cease_at,
             client_req_id, tweet_url, last_sent_at)
        VALUES ($1, $2, $3, $4::jsonb, $5, $6::timestamptz, $7::jsonb, $8::timestamptz,
                $9, $10, CASE WHEN $2 = 'sent' THEN NOW() ELSE NULL END)
        RETURNING id::text AS post_id, status, created_at
        """,
        npub,
        status,
        title or None,
        json.dumps(_authored(doc)),
        text_cache,
        publish_at,
        json.dumps(recurrence) if recurrence is not None else None,
        cease_at,
        client_req_id or None,
        tweet_url or None,
    )
    if not row:
        raise RuntimeError("create_post: INSERT … RETURNING returned no row")
    return row


async def find_by_req_id(npub: str, client_req_id: str) -> dict[str, Any] | None:
    """Find a live post previously created with this client_req_id (create dedup)."""
    if not client_req_id:
        return None
    return await fetchrow(
        """
        SELECT id::text AS post_id, status, created_at
        FROM posts
        WHERE npub = $1 AND client_req_id = $2 AND status <> 'archived'
        ORDER BY created_at ASC
        LIMIT 1
        """,
        npub,
        client_req_id,
    )


async def get_post(npub: str, post_id: str) -> dict[str, Any] | None:
    """Full post row, scoped to the owner."""
    return await fetchrow(
        f"SELECT {_FULL_COLS} FROM posts WHERE id = $2::uuid AND npub = $1",
        npub,
        post_id,
    )


async def current_req_id(npub: str, post_id: str) -> str | None:
    """The last-applied client_req_id for a post (update idempotency)."""
    row = await fetchrow(
        "SELECT client_req_id FROM posts WHERE id = $2::uuid AND npub = $1",
        npub,
        post_id,
    )
    return (row or {}).get("client_req_id")


async def list_posts(
    npub: str,
    status: str | None = None,
    sort_col: str = "created",
    sort_dir: str = "desc",
    page: int = 0,
    page_size: int = 25,
    search: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    date_field: str = "created",
    template_id: str | None = None,
) -> dict[str, Any]:
    """Server-side sorted, offset-paginated, optionally filtered list for the owner.

    Sorting runs in SQL so each page is a slice of the fully-ordered dataset.
    ORDER BY comes from the fixed ``_SORT_MAP`` whitelist; ``created_at DESC``
    is a stable tiebreak. ``search`` is a case-insensitive regex matched against
    ``text_cache`` (``~*``); ``date_from``/``date_to`` bound the ``date_field``
    column (``_DATE_FIELDS`` whitelist, default ``created_at``), end-inclusive.
    All user input is parameterized. The same WHERE drives the COUNT and the
    page. Returns ``{posts, total, page, page_size}``.
    """
    psize = max(1, min(100, page_size))
    pg = max(0, page)
    offset = pg * psize

    sort_expr = _SORT_MAP.get(sort_col, "created_at")
    row_dir = "DESC" if str(sort_dir).lower() == "desc" else "ASC"
    date_col = _DATE_FIELDS.get(date_field, "created_at")

    params: list[Any] = [npub]
    where = "npub = $1"
    if status:
        # Accept a single status or a comma-separated set (the FE's toggle-chiclet
        # include filter). An empty selection never reaches here — the FE renders
        # the empty state without querying. `status = ANY(...)` collapses to plain
        # equality for the single-status case.
        statuses = [s.strip() for s in status.split(",") if s.strip()]
        if statuses:
            params.append(statuses)
            where += f" AND status = ANY(${len(params)}::text[])"
    if search:
        params.append(search)
        where += f" AND text_cache ~* ${len(params)}"
    if date_from:
        params.append(date_from)
        where += f" AND {date_col} >= ${len(params)}::date"
    if date_to:
        params.append(date_to)
        where += f" AND {date_col} < (${len(params)}::date + interval '1 day')"
    if template_id:
        # "Occurrences of this template" — the sent snapshots a recurring post fired.
        params.append(template_id)
        where += f" AND template_id = ${len(params)}::uuid"

    total_row = await fetchrow(
        f"SELECT COUNT(*) AS n FROM posts WHERE {where}", *params
    )
    total = int(total_row["n"]) if total_row and total_row.get("n") is not None else 0

    params.append(psize)
    limit_idx = len(params)
    params.append(offset)
    offset_idx = len(params)

    rows = await fetch(
        f"""
        SELECT id::text AS post_id, status, title, left(text_cache, 120) AS excerpt,
               publish_at, updated_at, created_at, tweet_url, last_sent_at,
               last_attempt_at, last_attempt_reason, last_attempt_detail,
               template_id::text AS template_id,
               (recurrence IS NOT NULL) AS is_recurring,
               COALESCE(doc->'blocks' @> '[{{"dynamic":true}}]'::jsonb, false) AS has_dynamic
        FROM posts
        WHERE {where}
        ORDER BY {sort_expr} {row_dir}, created_at DESC
        LIMIT ${limit_idx} OFFSET ${offset_idx}
        """,
        *params,
    )

    posts = [
        {
            "post_id": r["post_id"],
            "status": r["status"],
            "title": r.get("title") or "",
            "excerpt": r.get("excerpt") or "",
            "publish_at": str(r["publish_at"]) if r.get("publish_at") else None,
            "updated_at": str(r.get("updated_at") or ""),
            "tweet_url": r.get("tweet_url") or None,
            "last_sent_at": str(r["last_sent_at"]) if r.get("last_sent_at") else None,
            "last_attempt_at": str(r["last_attempt_at"]) if r.get("last_attempt_at") else None,
            "last_attempt_reason": r.get("last_attempt_reason") or None,
            "last_attempt_detail": r.get("last_attempt_detail") or None,
            "template_id": r.get("template_id") or None,
            "is_recurring": bool(r.get("is_recurring")),
            "has_dynamic": bool(r.get("has_dynamic")),
        }
        for r in rows
    ]
    return {"posts": posts, "total": total, "page": pg, "page_size": psize}


async def summaries_for_ids(npub: str, post_ids: list[str]) -> dict[str, dict[str, Any]]:
    """Identity fields for a set of owned posts, keyed by post_id.

    Used by performance views that already have metric rows and only need the
    human-facing title/excerpt and when the post went out. Empty input → {}.
    Unknown or foreign ids are simply absent from the result.
    """
    ids = [str(pid) for pid in post_ids if pid]
    if not ids:
        return {}
    rows = await fetch(
        """
        SELECT id::text AS post_id, title, left(text_cache, 120) AS excerpt,
               last_sent_at, publish_at
        FROM posts
        WHERE npub = $1 AND id = ANY($2::uuid[])
        """,
        npub,
        ids,
    )
    out: dict[str, dict[str, Any]] = {}
    for r in rows:
        pid = str(r.get("post_id") or "")
        if not pid:
            continue
        out[pid] = {
            "title": r.get("title") or "",
            "excerpt": r.get("excerpt") or "",
            "last_sent_at": str(r["last_sent_at"]) if r.get("last_sent_at") else None,
            "publish_at": str(r["publish_at"]) if r.get("publish_at") else None,
        }
    return out


async def update_post(
    npub: str,
    post_id: str,
    patch: dict[str, Any],
    text_cache: Any = None,
    client_req_id: str | None = None,
) -> dict[str, Any] | None:
    """Patch whitelisted fields; return ``{post_id, status, updated_at}``.

    ``text_cache`` is updated only when explicitly provided (``not None``) —
    the FE supplies it alongside a ``doc`` change. ``client_req_id`` is recorded
    as the last-applied request id (update idempotency lives in the tool layer).
    """
    set_parts: list[str] = []
    params: list[Any] = [npub, post_id]

    for key, cast in _PATCHABLE.items():
        if key not in patch:
            continue
        value = patch[key]
        if key == "doc":
            value = _authored(value)
        if key in _JSON_KEYS:
            value = json.dumps(value) if value is not None else None
        params.append(value)
        set_parts.append(f"{key} = ${len(params)}{cast}")

    if text_cache is not None:
        params.append(text_cache)
        set_parts.append(f"text_cache = ${len(params)}")

    # An edit to the authored doc invalidates whatever this firing had already
    # built from the OLD prompts. Dropping it costs the owner any partially-paid
    # blocks; keeping it would post text the author has just rewritten, which is
    # the worse of the two and silent besides.
    if "doc" in patch:
        set_parts.append("render = NULL")

    # Putting a post back in play clears THIS firing's bookkeeping — otherwise
    # Resume has no exit. `pause_exhausted_firings` pauses a post at the attempt
    # cap; the owner resumes; the very next tick sees the counter still at the
    # cap and pauses it again. An infinite loop with a button in it.
    #
    # `render` is deliberately NOT cleared here. The doc-edit branch above owns
    # that, and dropping it on a bare Resume would re-bill the owner for blocks
    # they have already paid for.
    if patch.get("status") in ("scheduled", "draft"):
        set_parts.append(
            "resolve_attempts = 0, resolved_at = NULL, x_call_at = NULL, "
            "last_attempt_reason = NULL, last_attempt_detail = NULL",
        )

    # Transitioning to "sent" (the FE's Post It) stamps the fire time server-side,
    # so every send records last_sent_at without the caller having to.
    if patch.get("status") == "sent":
        set_parts.append("last_sent_at = NOW()")

    params.append(client_req_id or None)
    set_parts.append(f"client_req_id = ${len(params)}")
    set_parts.append("updated_at = NOW()")

    row = await fetchrow(
        f"""
        UPDATE posts SET {', '.join(set_parts)}
        WHERE id = $2::uuid AND npub = $1
        RETURNING id::text AS post_id, status, updated_at
        """,
        *params,
    )
    return row


async def soft_delete(npub: str, post_id: str) -> dict[str, Any] | None:
    """Archive a post (soft delete); return ``{post_id, status}``."""
    return await fetchrow(
        """
        UPDATE posts SET status = 'archived', updated_at = NOW()
        WHERE id = $2::uuid AND npub = $1
        RETURNING id::text AS post_id, status
        """,
        npub,
        post_id,
    )


async def hard_delete(npub: str, post_id: str) -> bool:
    """Permanently delete a post; return ``True`` if a row was removed."""
    result = await execute(
        "DELETE FROM posts WHERE id = $2::uuid AND npub = $1",
        npub,
        post_id,
    )
    return (result.get("rowCount") or 0) > 0


# -- Scheduler queries (operator-side; not npub-scoped) ----------------------


# How long a publisher may hold a claim before the recovery sweep presumes it
# dead. This MUST exceed the cron period (every 30 minutes, see
# scheduler-worker/wrangler.toml) or the lease is guaranteed to be stale by the
# time the next tick looks — which is not "recovery after a crash", it is
# "re-fire everything still in flight". At 20 minutes against a 30-minute cron
# there was no margin at all, and on 2026-07-30 a publisher that had already
# tweeted was re-claimed 28 minutes later and tweeted the same post a second
# time.
#
# The margin argument is unchanged, but what the lease BOUNDS has changed. It no
# longer gates a reclaim — nothing re-fires a `sending` post on a timer. It gates
# ``recover_orphaned_sends``, which decides between resuming and pausing on
# EVIDENCE (`x_call_at`) rather than on elapsed time. Time only decides when it
# is safe to look.
_SEND_LEASE = "interval '45 minutes'"


# A resolve claim covers ONLY the slow half — building a body from its blocks.
# Bounded by the per-block runtimeLimit (900s ceiling) times a handful of
# blocks, not by anything that touches X. Deliberately far shorter than the old
# whole-publication lease: a worker that dies mid-resolve should hand its slot
# back in minutes, not three quarters of an hour.
_RESOLVE_LEASE = "interval '20 minutes'"

# How many times a body may fail to resolve before it stops being retried. A
# dynamic block costs a real LLM fare per attempt, so a permanently-broken
# prompt must not bill its owner every 30 minutes forever — one post did exactly
# that from 2026-07-27 onward.
MAX_RESOLVE_ATTEMPTS = 5


async def list_due_for_resolve(horizon_iso: str, limit: int = 100) -> list[dict[str, Any]]:
    """Templates to start BUILDING now: scheduled and due within the horizon,
    plus ``resolving`` rows whose lease expired (orphaned by a dead worker).

    The horizon is deliberately ahead of now. Resolution is the slow half, so
    starting it at publish_at guarantees the post is late by however long the
    LLM took; starting it a tick early lets the fast poster fire punctually.
    Posts with nothing dynamic resolve instantly and are unaffected either way.
    """
    lim = max(1, min(500, limit))
    return await fetch(
        f"""
        SELECT {_FULL_COLS} FROM posts
        WHERE publish_at IS NOT NULL AND publish_at <= $1::timestamptz
          AND resolve_attempts < {MAX_RESOLVE_ATTEMPTS}
          AND (status = 'scheduled'
               OR (status = 'resolving'
                   AND last_attempt_at < NOW() - {_RESOLVE_LEASE}))
        ORDER BY publish_at ASC
        LIMIT $2
        """,
        horizon_iso,
        lim,
    )


async def claim_for_resolve(post_id: str) -> dict[str, Any] | None:
    """Atomically take a template for resolution — ``scheduled`` → ``resolving``.

    Same fencing discipline as the old publish claim: ``last_attempt_at`` moves
    on every claim, so it identifies THIS worker's tenure. A worker presumed dead
    and re-claimed finds its later writes no longer match.

    ``resolve_attempts`` increments here rather than on failure, so a worker that
    dies without reporting still counts against the budget — otherwise a job that
    crashes the container retries forever and never trips the ceiling.
    """
    return await fetchrow(
        f"""
        UPDATE posts
        SET status = 'resolving',
            resolve_attempts = resolve_attempts + 1,
            last_attempt_at = NOW(), updated_at = NOW()
        WHERE id = $1::uuid
          AND resolve_attempts < {MAX_RESOLVE_ATTEMPTS}
          AND (status = 'scheduled'
               OR (status = 'resolving'
                   AND last_attempt_at < NOW() - {_RESOLVE_LEASE}))
        RETURNING {_FULL_COLS}
        """,
        post_id,
    )


async def save_render(
    post_id: str, render: dict[str, Any], claim_stamp: str | None,
) -> bool:
    """Persist partial resolution progress: THIS firing's blocks filled in so far.

    Called after EACH block completes, not once at the end. A block runs 90-210s
    and costs the owner a real fare; a worker that dies after three of four
    blocks must not make them pay for those three again. The fence keeps a
    superseded worker from writing over its replacement's progress.

    Writes `render`, never `doc`. It wrote `doc` until 2026-08-04, and since a
    dynamic block's prompt IS its `text`, every resolution overwrote the prompt
    it had just run — destroying the recurring template on its first firing. The
    two states now live in two columns precisely so this can't be reintroduced by
    a careless edit: nothing in the publishing path holds a write handle on `doc`.
    """
    r = await execute(
        """
        UPDATE posts SET render = $2::jsonb, updated_at = NOW()
        WHERE id = $1::uuid AND status = 'resolving'
          AND ($3::timestamptz IS NULL OR last_attempt_at = $3::timestamptz)
        """,
        post_id, json.dumps(render), claim_stamp,
    )
    return int(r.get("rowCount") or 0) > 0


async def mark_resolved(
    post_id: str, text_cache: str, claim_stamp: str | None,
) -> bool:
    """The body is complete — ``resolving`` → ``resolved``, ready for the poster.

    ``resolved_at`` is what a stale-body policy would read; nothing enforces one
    yet, so it is recorded and left for the poster to judge."""
    r = await execute(
        """
        UPDATE posts
        SET status = 'resolved', text_cache = $2,
            resolved_at = NOW(), last_attempt_reason = NULL,
            last_attempt_detail = NULL, updated_at = NOW()
        WHERE id = $1::uuid AND status = 'resolving'
          AND ($3::timestamptz IS NULL OR last_attempt_at = $3::timestamptz)
        """,
        post_id, text_cache, claim_stamp,
    )
    return int(r.get("rowCount") or 0) > 0


async def list_resolved_due(now_iso: str, limit: int = 100) -> list[dict[str, Any]]:
    """Bodies finished building whose moment has arrived. The poster's work-list.

    Every one of these is a plain text_cache and a fully-rendered doc — no LLM,
    no branching on content type. Posting them is milliseconds each.
    """
    lim = max(1, min(500, limit))
    return await fetch(
        f"""
        SELECT {_FULL_COLS} FROM posts
        WHERE status = 'resolved'
          AND publish_at IS NOT NULL AND publish_at <= $1::timestamptz
        ORDER BY publish_at ASC
        LIMIT $2
        """,
        now_iso,
        lim,
    )


async def claim_for_post(post_id: str) -> dict[str, Any] | None:
    """Atomically take a finished body for posting — ``resolved`` → ``sending``.

    Accepts only ``resolved``: the two phases take different states, and
    conflating them is a silent no-op rather than an error. A claim that matched
    only ``scheduled`` once skipped every finished body forever, and two posts
    sat resolved-but-unsent for hours that way.

    Still no lease clause, and no timer ever re-fires a ``sending`` post. That
    rule is what keeps a publisher which already tweeted from being re-claimed
    and tweeting again, as one was on 2026-07-30. What changed is that
    ``sending`` is no longer a dead end: ``recover_orphaned_sends`` looks at
    stale claims and decides on EVIDENCE, resuming only where ``x_call_at``
    proves the publisher died before reaching X.

    ``x_call_at`` is cleared here so the marker is scoped to THIS firing. Without
    that, a recurrence would inherit the previous occurrence's mark and be paused
    for a send that completed days ago.
    """
    return await fetchrow(
        f"""
        UPDATE posts
        SET status = 'sending', x_call_at = NULL,
            last_attempt_at = NOW(), updated_at = NOW()
        WHERE id = $1::uuid AND status = 'resolved'
        RETURNING {_FULL_COLS}
        """,
        post_id,
    )


async def mark_x_call_started(post_id: str, claim_stamp: str | None) -> bool:
    """Authorize the irreversible call. **A ``False`` return means DO NOT POST.**

    This is not a log line, it is the gate. It must be the last thing that
    happens before ``post_tweet``, and its answer is what grants permission,
    because recovery later reads exactly this column to decide whether a tweet
    might be live.

    A plain stamp would not do. If the write's outcome is unknown — a Neon
    hiccup, a timeout — and we post anyway, the row still reads ``x_call_at IS
    NULL`` and the sweep concludes nothing was sent. That is the 2026-07-30
    double-post rebuilt out of new parts. Making the write a compare-and-set that
    GATES the call removes the case by construction: no confirmed write, no call.

    The same statement also stops a superseded publisher. A worker that stalled
    in OAuth or billing while a sweep handed its row to someone else finds
    ``last_attempt_at`` moved, matches zero rows, and stands down before touching
    X. An exception is treated exactly like ``False`` by the caller.
    """
    r = await execute(
        """
        UPDATE posts SET x_call_at = NOW(), updated_at = NOW()
        WHERE id = $1::uuid AND status = 'sending' AND x_call_at IS NULL
          AND ($2::timestamptz IS NULL OR last_attempt_at = $2::timestamptz)
        """,
        post_id, claim_stamp,
    )
    return int(r.get("rowCount") or 0) > 0


async def recover_orphaned_sends(limit: int = 100) -> dict[str, list[dict[str, Any]]]:
    """Repair ``sending`` rows whose publisher never came back.

    Before this existed a publisher that died left its post in ``sending``
    forever: no lease covered it, no work-list accepted it, and the only queries
    that did (``list_due``/``claim_due_post``) had lost their callers in the
    resolve/post split. One post sat there from 2026-08-02 to 08-04, in a state
    that looked active and was simply unreachable.

    Three branches, exhaustive and mutually exclusive over a stale claim:

    * ``x_call_at IS NOT NULL`` — we were cleared to call X and may have done so.
      **Pause.** A tweet may be live; only a human looking at the timeline can
      say. Never retried, on the same principle that pauses an unanswered send.
    * ``x_call_at IS NULL AND resolved_at IS NOT NULL`` — provably before the
      call, and provably a row this code wrote: ``claim_for_post`` only accepts
      ``resolved``, and only ``mark_resolved`` sets both. **Resume** by returning
      it to ``resolved``, where the poster picks it up on the same tick.
    * ``x_call_at IS NULL AND resolved_at IS NULL`` — a row that predates the
      marker. Its NULL is an absence of instrumentation, not evidence. **Pause**
      rather than guess; this branch empties itself and never refills.

    Each is one bulk statement, never a read-then-write: the race against a live
    publisher must be settled by row locking. Both orders are safe — if the CAS
    lands first the predicate here no longer matches, and if this lands first the
    CAS matches nothing and that publisher never calls X.

    Known gap: a publisher that died between billing and the CAS leaves a fare
    charged for a tweet that never went out, and resuming does not refund it.
    Reversing it safely needs a ``billed_at`` column and a refund keyed to the
    original debit — ``rollback_debit`` takes no debit reference, so calling it
    from here could reverse something unrelated. The window is one statement
    wide, which is why the gap is accepted rather than papered over.
    """
    lim = max(1, min(500, limit))
    out: dict[str, list[dict[str, Any]]] = {}
    stale = (
        f"status = 'sending' AND last_attempt_at IS NOT NULL "
        f"AND last_attempt_at < NOW() - {_SEND_LEASE}"
    )

    out["paused_unknown"] = await fetch(
        f"""
        UPDATE posts SET status = 'paused',
            last_attempt_reason = 'x_post_outcome_unknown',
            last_attempt_detail = 'The publisher was cleared to post and never '
                'confirmed. A tweet may already be live — check your timeline '
                'before resuming.',
            updated_at = NOW()
        WHERE id IN (SELECT id FROM posts WHERE {stale}
                     AND x_call_at IS NOT NULL LIMIT {lim})
        RETURNING id::text AS post_id, npub
        """,
    )
    out["resumed"] = await fetch(
        f"""
        UPDATE posts SET status = 'resolved', updated_at = NOW()
        WHERE id IN (SELECT id FROM posts WHERE {stale}
                     AND x_call_at IS NULL AND resolved_at IS NOT NULL LIMIT {lim})
        RETURNING id::text AS post_id, npub
        """,
    )
    out["paused_legacy"] = await fetch(
        f"""
        UPDATE posts SET status = 'paused',
            last_attempt_reason = 'sending_orphaned_pre_split',
            last_attempt_detail = 'Stranded before send-tracking existed, so '
                'whether it posted is unrecorded. Check your timeline, then '
                'resume or return it to draft.',
            updated_at = NOW()
        WHERE id IN (SELECT id FROM posts WHERE {stale}
                     AND x_call_at IS NULL AND resolved_at IS NULL LIMIT {lim})
        RETURNING id::text AS post_id, npub
        """,
    )
    return out


async def pause_exhausted_firings(horizon_iso: str, limit: int = 100) -> list[dict[str, Any]]:
    """Stop a post that has run out of firing attempts from LOOKING healthy.

    ``resolve_attempts`` reads like a resolution counter and is really a firing
    counter: a publisher hold releases the post, the next tick claims it for
    resolve, and the claim increments. So a handful of post-phase failures — a
    weekend without credits, a run of upstream 401s — walks a perfectly good post
    to the cap.

    At the cap both ``list_due_for_resolve`` and ``claim_for_resolve`` drop it.
    Two statuses land there:

    * ``scheduled`` — looks queued, is unreachable. The original #339 case.
    * ``resolving`` — the claim that walks the counter to the cap is the same
      claim that leaves the row here. From that instant no work-list and no
      other sweep can reach it, while it still reads as work in progress. That
      is #344: the same dead-end shape as orphaned ``sending``, one state left.

    Pausing puts either in a state the owner can actually see and resume, and
    Resume clears the counter (see ``update_post``). A live resolve still inside
    its lease is left alone — if it finishes it advances; if it dies the lease
    expires and the next tick pauses it.

    The prior reason is carried into the detail because it is the real story;
    ``firing_attempts_exhausted`` alone would say only that a number ran out.
    """
    lim = max(1, min(500, limit))
    return await fetch(
        f"""
        UPDATE posts SET status = 'paused',
            last_attempt_reason = 'firing_attempts_exhausted',
            last_attempt_detail = 'Gave up after {MAX_RESOLVE_ATTEMPTS} attempts. '
                'Last reason: ' || COALESCE(last_attempt_reason, 'not recorded')
                || '. Fix that, then resume.',
            updated_at = NOW()
        WHERE id IN (
            SELECT id FROM posts
            WHERE publish_at IS NOT NULL
              AND publish_at <= $1::timestamptz
              AND resolve_attempts >= {MAX_RESOLVE_ATTEMPTS}
              AND (status = 'scheduled'
                   OR (status = 'resolving'
                       AND last_attempt_at < NOW() - {_RESOLVE_LEASE}))
            LIMIT {lim})
        RETURNING id::text AS post_id, npub
        """,
        horizon_iso,
    )


async def upcoming_by_owner(now_iso: str) -> list[dict[str, Any]]:
    """What the scheduler expects next, grouped by owner:
    ``[{npub, count, next_at}]`` over the posts still ahead of it.

    A tick that reports only "nothing due" is a line you learn to skim. How many
    posts are waiting and when the soonest lands turns the same heartbeat into a
    forecast — and makes a queue that has quietly emptied visible at a glance.

    Grouped rather than totalled because the log is owner-scoped: a patron may
    be told about their own queue, never the size of anyone else's.
    """
    return await fetch(
        """
        SELECT npub, COUNT(*) AS count, MIN(publish_at) AS next_at FROM posts
        WHERE status = 'scheduled' AND publish_at IS NOT NULL
          AND publish_at > $1::timestamptz
        GROUP BY npub
        """,
        now_iso,
    )


async def get_claimed(post_id: str) -> dict[str, Any] | None:
    """The full row for a post a publisher owns — operator-side, not npub-scoped.

    A publisher is handed only an id; it reads its own row rather than having the
    scheduler carry post content through job parameters.
    """
    return await fetchrow(f"SELECT {_FULL_COLS} FROM posts WHERE id = $1::uuid", post_id)


async def release_to_resolved(post_id: str, claim_stamp: str | None = None) -> bool:
    """Hand a claimed post back to the POSTER's queue, not the resolver's.

    A post-phase failure — no credits, an upstream 401, a rate limit — says
    nothing about the body, which is finished and paid for. Sending it back to
    ``scheduled`` throws it into the resolve queue instead, and the next claim
    increments ``resolve_attempts``. Five such holds retire a healthy post at the
    cap, which is how a weekend without credits could silence a daily post
    permanently. Returning it to ``resolved`` retries the only part that failed.
    """
    r = await execute(
        """
        UPDATE posts SET status = 'resolved', updated_at = NOW()
        WHERE id = $1::uuid AND status = 'sending'
          AND ($2::timestamptz IS NULL OR last_attempt_at = $2::timestamptz)
        """,
        post_id, claim_stamp,
    )
    return int(r.get("rowCount") or 0) > 0


async def mark_sent(
    post_id: str,
    last_sent_at: str,
    next_status: str,
    next_publish_at: str | None,
    tweet_url: str | None = None,
    claim_stamp: str | None = None,
) -> bool:
    """Record a fire: stamp last_sent_at, set the next status/publish_at, and
    store the posted tweet's URL (COALESCE keeps a prior URL on recurrence).
    A successful fire clears any prior ``last_attempt_reason`` (the hold is over).

    Test-and-set on the caller's claim. ``claim_stamp`` is the ``last_attempt_at``
    the publisher read when it picked the post up — ``claim_for_post`` sets that to
    NOW() on every claim, so it doubles as a fencing token: if a later tick decided
    this publisher was dead and re-claimed the post, the stamp has moved and this
    write matches nothing. Returns whether the row was ours to advance; ``False``
    means we lost the claim and must not pretend otherwise.
    """
    row = await fetchrow(
        """
        UPDATE posts
        SET last_sent_at         = $2::timestamptz,
            status               = $3,
            publish_at           = $4::timestamptz,
            tweet_url            = COALESCE($5, tweet_url),
            last_attempt_at      = $2::timestamptz,
            last_attempt_reason  = NULL,
            last_attempt_detail  = NULL,
            updated_at           = NOW()
        WHERE id = $1::uuid
          AND ($6::timestamptz IS NULL OR
               (status = 'sending' AND last_attempt_at = $6::timestamptz))
        RETURNING id
        """,
        post_id,
        last_sent_at,
        next_status,
        next_publish_at,
        tweet_url or None,
        claim_stamp,
    )
    return row is not None


async def create_sent_occurrence(
    npub: str,
    doc: dict[str, Any],
    text_cache: str | None,
    tweet_url: str | None,
    sent_at: str,
    template_id: str,
    publish_at: str | None = None,
) -> None:
    """Record one fired occurrence of a recurring post as its own immutable Sent
    post (a snapshot of the text/doc that went out + that occurrence's X URL).

    A recurring post reschedules itself in place, so without this each posting
    would be invisible — collapsed into the template that just advances its date,
    with only the latest ``tweet_url`` retained. This leaves a permanent, viewable
    Sent record per posting instead. ``template_id`` back-links the snapshot to the
    recurring template it fired from, so the FE can connect a publication to the
    (still-dynamic) post that produced it."""
    await execute(
        """
        INSERT INTO posts
            (npub, status, doc, text_cache, publish_at, last_sent_at, tweet_url, template_id)
        VALUES ($1, 'sent', $2::jsonb, $3, $4::timestamptz, $5::timestamptz, $6, $7::uuid)
        """,
        npub,
        json.dumps(doc),
        text_cache,
        publish_at,
        sent_at,
        tweet_url or None,
        template_id,
    )


async def record_occurrence_and_advance(
    *,
    template_id: str,
    npub: str,
    doc: dict[str, Any],
    text_cache: str | None,
    tweet_url: str | None,
    sent_at: str,
    occurrence_publish_at: str | None,
    next_publish_at: str | None,
    claim_stamp: str | None,
) -> bool:
    """Snapshot this occurrence AND advance its template — in ONE statement.

    These used to be two awaits, and on 2026-07-30 a publisher died between them:
    the occurrence row was written, the template never advanced, so it stayed
    ``sending`` with a stale claim. The next tick re-claimed it and tweeted the
    same scheduled occurrence a second time. Two rows, two tweets, one slot — and
    invisible in the scheduler log, because the log row is written *after* both,
    so the death that causes the bug also erases its own evidence.

    One statement removes the window entirely: Postgres executes a data-modifying
    CTE and the INSERT that selects from it as a single atomic unit, so either the
    template advanced and the occurrence exists, or neither happened. There is no
    state in which the tweet is recorded but the template still looks unpublished.

    The UPDATE is also the test-and-set: it matches only while we still hold the
    claim we were handed (``claim_stamp`` is the ``last_attempt_at`` stamped by
    ``claim_for_post``). If a later tick re-claimed this post, the stamp moved, the
    CTE yields no row, the INSERT selects from an empty relation, and we return
    ``False`` rather than writing a second occurrence over someone else's work.

    Advancing also RESETS this firing's derived state — ``render``, ``resolved_at``,
    ``resolve_attempts`` — because the template is now due for a *different*
    occurrence and none of that describes it any more. Two bugs lived in the gap:

    * ``render`` (formerly written straight into ``doc``) left the finished text
      standing where the next firing looked for prompts, so a recurring template
      reposted its first firing's words forever.
    * ``resolve_attempts`` increments on every claim, including successful ones,
      and is capped at ``MAX_RESOLVE_ATTEMPTS``. Never resetting it meant a
      healthy recurring template stopped resolving after its 5th firing and
      dropped out of ``list_due_for_resolve`` — silently, since falling off a
      work-list raises nothing. A permanently-broken template still trips the cap:
      it never reaches this statement, because this only runs after a live tweet.

    Returns whether this publisher was still the owner. ``False`` means the tweet
    went out but the claim was lost — the caller must say so loudly, never silently.
    """
    row = await fetchrow(
        """
        WITH advanced AS (
            UPDATE posts
            SET last_sent_at         = $6::timestamptz,
                status               = 'scheduled',
                publish_at           = $8::timestamptz,
                last_attempt_at      = $6::timestamptz,
                last_attempt_reason  = NULL,
                last_attempt_detail  = NULL,
                render               = NULL,
                resolve_attempts     = 0,
                resolved_at          = NULL,
                x_call_at            = NULL,
                updated_at           = NOW()
            WHERE id = $1::uuid
              AND ($9::timestamptz IS NULL OR
                   (status = 'sending' AND last_attempt_at = $9::timestamptz))
            RETURNING id
        )
        INSERT INTO posts
            (npub, status, doc, text_cache, publish_at, last_sent_at, tweet_url, template_id)
        SELECT $2, 'sent', $3::jsonb, $4, $7::timestamptz, $6::timestamptz, $5, advanced.id
        FROM advanced
        RETURNING id
        """,
        template_id,
        npub,
        json.dumps(doc),
        text_cache,
        tweet_url or None,
        sent_at,
        occurrence_publish_at,
        next_publish_at,
        claim_stamp,
    )
    return row is not None


async def mark_attempt(
    post_id: str, at_iso: str, reason: str, detail: str | None = None,
    claim_stamp: str | None = None,
) -> None:
    """Stamp a post the scheduler TRIED to fire but held back.

    Records when and why (the skip/error reason — access/finance/network/content)
    so the post visibly shows it was attempted, and the FE can surface the hold
    instead of it silently sitting ``scheduled``. Reverts a claimed ('sending')
    post back to ``scheduled`` so the next due tick retries it — though the post
    phase now prefers ``release_to_resolved``, which retries the half that
    actually failed.

    Fenced when a ``claim_stamp`` is given, like ``mark_sent``. Unfenced it will
    stamp whoever owns the row now: a resolver presumed dead at its 20-minute
    lease, waking to report a hold, would flip its REPLACEMENT's ``resolving``
    row to ``scheduled`` mid-build. ``None`` keeps the old unfenced behaviour for
    callers that hold no claim.
    """
    await execute(
        """
        UPDATE posts
        SET last_attempt_at     = $2::timestamptz,
            last_attempt_reason = $3,
            last_attempt_detail = $4,
            status              = CASE WHEN status = 'sending' THEN 'scheduled' ELSE status END,
            updated_at          = NOW()
        WHERE id = $1::uuid
          AND ($5::timestamptz IS NULL OR last_attempt_at = $5::timestamptz)
        """,
        post_id,
        at_iso,
        reason,
        detail,
        claim_stamp,
    )


async def mark_paused(
    post_id: str, at_iso: str, reason: str, detail: str | None = None,
    claim_stamp: str | None = None,
) -> None:
    """Pause a post the scheduler can't fire without human action.

    For non-transient situations no later tick can resolve — the owner's upstream
    X subscription lapsed (HTTP 402), a send whose outcome is unknown, a prompt
    destroyed before the doc/render split. Sets ``status='paused'`` so the
    work-lists stop returning it (ending the every-tick refire loop) and stamps
    the attempt so the FE can surface why. The owner resumes from the FE, which
    patches ``status`` back to ``scheduled`` and clears the firing counters.

    Fenced on ``claim_stamp`` for the same reason as ``mark_attempt``.
    """
    await execute(
        """
        UPDATE posts
        SET status              = 'paused',
            last_attempt_at     = $2::timestamptz,
            last_attempt_reason = $3,
            last_attempt_detail = $4,
            updated_at          = NOW()
        WHERE id = $1::uuid
          AND ($5::timestamptz IS NULL OR last_attempt_at = $5::timestamptz)
        """,
        post_id,
        at_iso,
        reason,
        detail,
        claim_stamp,
    )
