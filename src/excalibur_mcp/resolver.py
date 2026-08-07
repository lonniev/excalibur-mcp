"""Building one post's body — the slow half, and the only half that is slow.

A post is two jobs wearing one name. Turning an author's template into finished
text can take minutes: each dynamic block is a prompt the model runs, with web
lookups, bounded by the author's own ``runtimeLimit`` (itself bounded by the
operator's configured block ceiling — see the budget rings in
``excalibur_mcp.config``). Handing that text to X is one HTTPS call — tens of
milliseconds.

Carrying both under one claim made every publication a long-runner. It forced a
45-minute lease over work that is mostly instantaneous, made a container recycle
able to kill a post mid-flight, and meant one algorithm had to reason about two
unrelated kinds of work. Splitting them puts each stage on the footing it needs:

* **Resolve** (here) — slow, LLM-bound, retryable, costs a fare per block. Its
  output is a fully-rendered body persisted to the row. Nothing here touches X,
  the patron's OAuth token, or the ledger's post fare.
* **Post** (``publisher.py``) — fast, synchronous, irreversible. Its input is a
  finished body, so it never branches on whether the post was dynamic.

The static/dynamic fork disappears rather than being handled better: a post with
no dynamic blocks simply has nothing to resolve, completes instantly, and enters
the poster's queue by the same path as one that took four minutes.

**Progress is persisted per block, not once at the end.** A block costs the owner
a real fare; a worker that dies after three of four must not make them buy those
three again. The claim stamp fences every write, so a worker presumed dead and
replaced cannot overwrite its successor's progress.

**It is persisted to ``render``, never to ``doc``.** A dynamic block's prompt IS
its ``text``, so writing an answer back into the authored doc overwrites the
question that produced it. Until 2026-08-04 that is exactly what happened: the
first firing of a recurring template replaced every prompt with that firing's
output — or, when the model was unreachable, with the block's fallback — and
marked it ``resolved``. Advancing the recurrence never put it back, and ``doc``
has no history, so the template was destroyed by its own first success and
nothing said so: later firings found no pending blocks, called no model, charged
no fare, and reposted the same frozen words on schedule.

So the two states are two columns. ``doc`` is authored and changes only under a
human edit. ``render`` is derived, rebuilt from ``doc`` on every firing, and
cleared the moment the recurrence advances.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from excalibur_mcp.config import get_settings
from excalibur_mcp.db import posts as posts_db
from excalibur_mcp.db import scheduler_runs

logger = logging.getLogger(__name__)

# Failures where the request was PROVABLY never delivered: the connection was
# never established, so no tokens were spent, no generation started, and a second
# attempt has no side effect to duplicate. These and only these are safe to retry.
#
# Deliberately NOT retried: a read/protocol/write error interrupted a request the
# provider had already accepted and may be part-way through answering, and an
# auth/funding refusal will refuse identically. Retrying either spends the owner's
# budget to reach the same fallback one attempt later.
#
# Earned on 2026-08-06. A single `ConnectError` cost post 844c6b64 its content
# 135s into a 480s budget — 72% of the author's time unspent — and the identical
# request (same URL, same 8 fetches) reproduced cleanly minutes afterwards.
_RETRYABLE_CONNECT = (httpx.ConnectError, httpx.ConnectTimeout)

# Floor for a second attempt. Below this the retry cannot plausibly finish, so it
# would burn the remainder and fall back anyway — later, and having spent more.
_MIN_RETRY_BUDGET_S = 20.0


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _record(outcome: dict[str, Any]) -> dict[str, Any]:
    """Append this resolution to the audit ring and hand the outcome back.

    Every exit from ``resolve_one`` goes through here, so a build cannot finish
    without leaving a trace. Best-effort: an audit-write failure must never undo
    the work it was describing.
    """
    try:
        await scheduler_runs.record_run({"kind": "resolution", **outcome})
    except Exception:  # noqa: BLE001 — audit is never worth failing the build over
        logger.exception("resolver: failed to record outcome for %s", outcome.get("post_id"))
    return outcome


def _as_dict(value: Any) -> dict[str, Any] | None:
    """Neon may hand JSONB back parsed or raw — normalize."""
    import json

    if value is None:
        return None
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            return None
    return None


def _blocks(doc: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(doc, dict):
        return []
    blocks = doc.get("blocks")
    return [b for b in blocks if isinstance(b, dict)] if isinstance(blocks, list) else []


def _body_text(blocks: list[dict[str, Any]]) -> str:
    """The posted text: every block's text, blank-line joined.

    Nostr companion blocks are excluded — they are published alongside the post,
    not inside it.
    """
    return "\n\n".join(
        str(b.get("text", "")) for b in blocks if not b.get("nostr")
    ).strip()


def _domains(b: dict[str, Any]) -> list[str]:
    """The author's web-lookup allow-list for one block, however they typed it."""
    raw = b.get("domains")
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    if isinstance(raw, str):
        return [x.strip() for x in raw.replace(",", "\n").split("\n") if x.strip()]
    return []


def _billing_reason(billing: dict[str, Any], fallback: str) -> str:
    """The reason a billing call refused, as IT stated it.

    ``_apply_billing`` distinguishes a patron genuinely short of sats from a
    ledger it could not read, and flattening the two is how an owner holding 844
    sats was told to top up.
    """
    return str(billing.get("error_code") or fallback)


def _is_unresolved(b: dict[str, Any]) -> bool:
    """A dynamic block this firing has not yet bought an answer for.

    Read against a ``render`` block, never an authored one: ``resolved`` is
    per-firing bookkeeping this module writes as each block completes, and it is
    how a resumed worker knows what the owner has already paid for. In ``doc`` it
    would be a lie that outlives the firing that set it.
    """
    return bool(b.get("dynamic")) and not b.get("resolved")


def _start_render(doc: dict[str, Any], row: Any) -> dict[str, Any]:
    """This firing's working copy: the render already in flight, or a fresh one.

    A render survives only within one firing. Resuming after a dead worker means
    picking up the blocks the owner already bought; a new firing means starting
    from the authored doc again, which is what makes a recurring template
    reusable rather than single-use.

    A render is only resumable while it still describes the same post. An edit
    clears it (``update_post``), but a render whose block count no longer matches
    the authored doc is stale by some path that didn't — and resuming it would
    pair block N's answer with block N's *new* prompt. Rebuild instead: the cost
    is re-buying this firing's blocks, against posting a body nobody wrote.
    """
    import copy

    existing = _as_dict(row.get("render"))
    if existing and len(_blocks(existing)) == len(_blocks(doc)) and _blocks(existing):
        return existing

    # A fresh firing starts from the authored doc with every per-firing mark
    # dropped. `resolved` is this module's own bookkeeping and has no business in
    # `doc` — but it IS there on templates flattened before the split, and
    # honouring it would make them skip resolution forever, which is the exact
    # symptom. Authored state cannot tell us a block is already paid for; only a
    # live render can.
    from excalibur_mcp.db.posts import _PER_FIRING_BLOCK_KEYS

    fresh = copy.deepcopy(doc)
    fresh["blocks"] = [
        {k: v for k, v in b.items() if k not in _PER_FIRING_BLOCK_KEYS}
        for b in _blocks(fresh)
    ]
    return fresh


def _lost_prompts(authored: list[dict[str, Any]]) -> list[int]:
    """Blocks whose authored prompt was destroyed by the pre-fix resolver.

    ``resolved`` is written by this module and by nothing else, so a *dynamic*
    block carrying it in ``doc`` is proof that a firing once wrote its answer
    over the question. The prompt is not recoverable — ``doc`` has no history and
    the sent occurrences hold rendered text — so this cannot be repaired here.

    It must not be resolved through, either. What sits in ``text`` is last
    firing's output, usually the fallback; running THAT as the prompt yields
    fluent, on-topic, completely unauthored posts, and bills the owner for them.
    Frozen text was at least recognisable. Naming the loss and stopping is the
    only honest option.
    """
    return [i for i, b in enumerate(authored) if b.get("dynamic") and b.get("resolved")]


async def resolve_one(runtime: Any, post_id: str) -> dict[str, Any]:
    """Build one post's body and leave it ``resolved``, or say why it could not.

    Returns the outcome dict that is also written to the audit ring.
    """
    from tollbooth.llm_route import clamp_timeout
    from tollbooth.tool_identity import capability_uuid

    from excalibur_mcp.publisher import _fallback_reason, _owner_voice
    from excalibur_mcp.resolve import clamp_fetches, resolve_block

    resolve_id = capability_uuid("resolve_dynamic_block")

    row = await posts_db.get_claimed(post_id)
    if row is None:
        return await _record({"post_id": post_id, "outcome": "gone"})
    owner = row["npub"]
    claim_stamp = str(row.get("last_attempt_at")) if row.get("last_attempt_at") else None

    async def _hold(reason: str, *, detail: str = "", **extra: Any) -> dict[str, Any]:
        """Hand the template back to ``scheduled`` and say why.

        A held resolution never reaches the poster, so nothing half-built is ever
        posted — the whole point of separating the phases.
        """
        try:
            await posts_db.mark_attempt(
                post_id, _now().isoformat(), reason, detail or None,
                claim_stamp=claim_stamp,
            )
        except Exception:  # noqa: BLE001 — stamping is never worth failing over
            logger.exception("resolver: failed to stamp attempt on %s", post_id)
        return await _record({
            "post_id": post_id, "owner": owner,
            "outcome": "held", "reason": reason,
            **({"detail": detail} if detail else {}), **extra,
        })

    async def _pause(reason: str, *, detail: str = "", **extra: Any) -> dict[str, Any]:
        """Stop for something no later tick can fix — the owner must act.

        A hold means "try again"; using one here would re-bill the owner every
        half hour for a template that cannot be built until a human rewrites it.
        """
        try:
            await posts_db.mark_paused(
                post_id, _now().isoformat(), reason, detail or None,
                claim_stamp=claim_stamp,
            )
        except Exception:  # noqa: BLE001 — stamping is never worth failing over
            logger.exception("resolver: failed to pause %s", post_id)
        return await _record({
            "post_id": post_id, "owner": owner,
            "outcome": "paused", "reason": reason,
            **({"detail": detail} if detail else {}), **extra,
        })

    async def _finish(text: str, **extra: Any) -> dict[str, Any]:
        """Mark the body ready — the ONLY way this function reports success.

        Every exit runs the same fence. Two shorter paths (a legacy text_cache
        post, a body a previous worker had already finished) used to call
        mark_resolved and ignore its answer, so a superseded worker could report
        a build that its replacement actually owns.
        """
        if not await posts_db.mark_resolved(post_id, text, claim_stamp):
            logger.info("resolver: claim on %s was superseded; standing down", post_id)
            return await _record({
                "post_id": post_id, "owner": owner, "outcome": "superseded",
            })
        return await _record({
            "post_id": post_id, "owner": owner, "outcome": "resolved", **extra,
        })

    # `doc` is READ-ONLY here — it is what the author wrote, and every prompt is
    # taken from it. `blocks` is this firing's working copy, which is what gets
    # written back. Conflating the two is the bug this separation exists to make
    # unrepresentable.
    doc = _as_dict(row.get("doc")) or {}
    authored = _blocks(doc)
    render = _start_render(doc, row)
    blocks = _blocks(render)
    if not authored:
        # Nothing to build. A legacy post carrying only text_cache is already a
        # finished body; anything else is empty and must not reach X.
        text = (row.get("text_cache") or "").strip()
        if not text:
            return await _hold("empty_text_cache")
        return await _finish(text, blocks_resolved=0)

    # Damage from before the doc/render split: this template's prompts were
    # overwritten by their own answers. Unrecoverable, and not something a retry
    # reaches — say so once, on the row, and wait for the owner.
    lost = _lost_prompts(authored)
    if lost:
        return await _pause(
            "template_prompt_lost",
            detail=(
                f"block(s) {', '.join(str(i) for i in lost)}: the dynamic prompt was "
                "overwritten by an earlier firing's output (fixed 2026-08-04). What "
                "remains is that output, not the instruction — re-author the block, "
                "then Resume."
            ),
            blocks=lost,
        )

    pending = [i for i, b in enumerate(blocks) if _is_unresolved(b)]

    # A post with nothing dynamic — or one whose blocks a previous worker already
    # bought — is finished the moment we look at it. No fare, no LLM, no branch.
    if not pending:
        text = _body_text(blocks)
        if not text:
            return await _hold("empty_after_resolve")
        # Even an all-static post persists its render: the publisher snapshots
        # THAT into the occurrence row, and reading it from `doc` is how the
        # rendered and the authored kept getting confused for each other.
        await posts_db.save_render(post_id, {**render, "blocks": blocks}, claim_stamp)
        return await _finish(text, blocks_resolved=0, resumed=True)

    try:
        creds = await runtime.load_credentials(["llm_api_key"])
        api_key = creds.get("llm_api_key")
    except Exception:  # noqa: BLE001 — no key is a situation, not a crash
        api_key = None

    voice, bans = await _owner_voice(owner)
    degraded: list[dict[str, Any]] = []

    for i in pending:
        b = blocks[i]
        # The prompt comes from the AUTHORED block, never from the working copy.
        # Taking it from `blocks[i]` reads back whatever the last firing wrote
        # there — which is how a fallback, once substituted, became the "prompt"
        # every subsequent firing ran.
        src = authored[i]
        prompt = str(src.get("text", "")).strip()
        fallback = str(src.get("fallback", "")).strip()
        # The operator's configured ceiling governs, not the wheel's stalled-provider
        # fallback: without `maximum` an author's 1800s budget came back as 900s with
        # nothing anywhere recording that it had been halved.
        budget = clamp_timeout(
            src.get("runtimeLimit"),
            maximum=get_settings().resolve_block_budget_max_s,
        )

        if not prompt:
            # Nothing was asked for. Not a degradation, and not worth a fare.
            blocks[i] = {**b, "text": fallback, "resolved": True}
            await posts_db.save_render(post_id, {**render, "blocks": blocks}, claim_stamp)
            continue

        # Bill per block, at the moment that block's work is about to happen.
        # The old shape charged once up front for the whole post, so a failure on
        # the last of four blocks refunded work that had genuinely been done.
        cost, denial = await runtime._resolve_pricing(
            resolve_id, "resolve_dynamic_block", "heavy", {},
        )
        if denial is not None:
            return await _hold(
                denial.get("error_code") or "pricing_unavailable",
                detail=str(denial.get("error") or ""), block=i,
            )
        billing = await runtime._apply_billing(owner, "resolve_dynamic_block", cost, [])
        if isinstance(billing, dict):
            return await _hold(
                _billing_reason(billing, "insufficient_balance"),
                detail=str(billing.get("error") or ""), block=i, cost_sats=cost,
            )

        why = None
        resolved_text = ""
        if not api_key:
            why = "no_operator_llm_key"
        else:
            async def _attempt(seconds: float) -> str:
                return await resolve_block(
                    api_key=api_key, prompt=prompt,
                    context=_body_text(blocks[:i]),
                    voice=voice, bans=bans, allowed_domains=_domains(src),
                    max_fetches=clamp_fetches(src.get("maxFetches", 5)),
                    timeout_seconds=seconds,
                )

            started = time.monotonic()
            try:
                resolved_text = await _attempt(budget)
                if not resolved_text:
                    why = "empty_resolution"
            except _RETRYABLE_CONNECT as exc:
                # One retry, and only here. The fare was debited before this
                # block began, so the second attempt costs the owner nothing
                # extra — it is the same block resolution, not a new one.
                left = budget - (time.monotonic() - started)
                if left < _MIN_RETRY_BUDGET_S:
                    logger.warning(
                        "resolver: block %d could not reach the provider for %s (%s) "
                        "with %.0fs left — too little to retry", i, owner,
                        type(exc).__name__, left,
                    )
                    why = _fallback_reason(exc, budget)
                else:
                    logger.warning(
                        "resolver: block %d could not reach the provider for %s (%s); "
                        "retrying once within the block's remaining %.0fs",
                        i, owner, type(exc).__name__, left,
                    )
                    try:
                        resolved_text = await _attempt(left)
                        if not resolved_text:
                            why = "empty_resolution"
                    except Exception as retry_exc:  # noqa: BLE001 — now fall back
                        logger.warning(
                            "resolver: block %d retry failed for %s: %s",
                            i, owner, retry_exc,
                        )
                        # Report the RETRY's reason against the time it actually
                        # had. Naming the first failure would hide that a second
                        # attempt was made and also lost.
                        why = _fallback_reason(retry_exc, left)
            except Exception as exc:  # noqa: BLE001 — fall back, keep the reason
                logger.warning("resolver: block %d failed for %s: %s", i, owner, exc)
                why = _fallback_reason(exc, budget)

        if not resolved_text:
            # The fare bought nothing, so refund it before deciding what to do.
            await runtime.rollback_debit(resolve_id, owner)
            if not fallback:
                # No fallback means no body. Refuse rather than post a gap — and
                # name the block's own reason, which used to be computed here and
                # discarded on the way out.
                return await _hold(
                    f"dynamic_resolve_failed: {why}", detail=f"block {i}: {why}",
                    block=i, degraded=degraded,
                )
            resolved_text = fallback
            degraded.append({"block": i, "reason": why, "budget_s": round(budget, 1)})
            # Mark the BLOCK, not just this run's log line. The log row says a
            # resolve degraded; only the render can tell the publisher that the
            # words it is about to send are the author's consolation rather than
            # the post they asked for. Per-firing, so it is stripped on the next
            # firing and on any authored save (_PER_FIRING_BLOCK_KEYS).
            b = {**b, "fellBack": {"reason": why, "budget_s": round(budget, 1)}}

        blocks[i] = {**b, "text": resolved_text, "resolved": True}
        # Persist THIS block before starting the next. What the owner paid for is
        # now durable; a crash costs only the blocks still outstanding.
        await posts_db.save_render(post_id, {**render, "blocks": blocks}, claim_stamp)

    text = _body_text(blocks)
    if not text:
        return await _hold("empty_after_resolve", degraded=degraded)

    return await _finish(
        text, blocks_resolved=len(pending),
        **({"degraded": degraded} if degraded else {}),
    )
