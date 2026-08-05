"""Low-level posts SQL tests — cursor codec, npub-scoping, dynamic update.

The Neon layer (``execute``/``fetch``/``fetchrow``) is faked so we can assert on
the SQL and params the CRUD functions build — every statement must be
npub-scoped, and ``update_post`` must only touch the patched columns.
"""

import json
from unittest.mock import AsyncMock, patch

import pytest

from excalibur_mcp.db import posts as posts_db

NPUB = "npub1l94pd4qu4eszrl6ek032ftcnsu3tt9a7xvq2zp7eaxeklp6mrpzssmq8pf"
PID = "11111111-1111-1111-1111-111111111111"


@pytest.mark.asyncio
async def test_create_post_serializes_json_and_scopes_npub():
    captured = {}

    async def fake_fetchrow(query, *args):
        captured["query"] = query
        captured["args"] = args
        return {"post_id": PID, "status": "draft", "created_at": "2026-06-19T00:00:00+00:00"}

    with patch.object(posts_db, "fetchrow", fake_fetchrow):
        await posts_db.create_post(
            npub=NPUB, doc={"blocks": [1]}, text_cache="hi", publish_at=None,
            recurrence=None, cease_at=None, status="draft", client_req_id=None,
        )
    assert "INSERT INTO posts" in captured["query"]
    # Column order: npub, status, title, doc, text_cache, publish_at, recurrence, …
    # doc is json-encoded; recurrence None stays None (not the string "null")
    assert captured["args"][0] == NPUB
    assert captured["args"][2] is None  # title omitted → NULL
    assert json.loads(captured["args"][3]) == {"blocks": [1]}
    assert captured["args"][6] is None  # recurrence


@pytest.mark.asyncio
async def test_update_post_sets_only_patched_columns():
    captured = {}

    async def fake_fetchrow(query, *args):
        captured["query"] = query
        captured["args"] = args
        return {"post_id": PID, "status": "scheduled", "updated_at": "2026-06-19T01:00:00+00:00"}

    with patch.object(posts_db, "fetchrow", fake_fetchrow):
        await posts_db.update_post(
            NPUB, PID, {"status": "scheduled"}, text_cache="composed", client_req_id="r1",
        )
    q = captured["query"]
    assert "status = $3" in q
    assert "doc" not in q  # not patched → not in SET
    assert "text_cache = $4" in q
    assert "client_req_id = $5" in q
    assert "updated_at = NOW()" in q
    assert "WHERE id = $2::uuid AND npub = $1" in q
    assert "last_sent_at" not in q  # not sent → no fire stamp


@pytest.mark.asyncio
async def test_update_post_to_sent_stamps_last_sent_at_and_stores_tweet_url():
    captured = {}

    async def fake_fetchrow(query, *args):
        captured["query"] = query
        captured["args"] = args
        return {"post_id": PID, "status": "sent", "updated_at": "2026-06-21T03:20:00+00:00"}

    with patch.object(posts_db, "fetchrow", fake_fetchrow):
        await posts_db.update_post(
            NPUB, PID, {"status": "sent", "tweet_url": "https://x.com/i/status/123"},
            text_cache="composed", client_req_id="r2",
        )
    q = captured["query"]
    assert "last_sent_at = NOW()" in q  # transitioning to sent stamps the fire
    assert "tweet_url = $" in q  # url persisted as a patched column
    assert "https://x.com/i/status/123" in captured["args"]


@pytest.mark.asyncio
async def test_mark_sent_persists_tweet_url():
    captured = {}

    async def fake_fetchrow(query, *args):
        captured["query"] = query
        captured["args"] = args
        return {"id": PID}

    with patch.object(posts_db, "fetchrow", fake_fetchrow):
        held = await posts_db.mark_sent(
            PID, "2026-06-21T03:20:00+00:00", "sent", None,
            "https://x.com/i/status/456",
        )
    assert held is True
    assert "tweet_url            = COALESCE($5, tweet_url)" in captured["query"]
    assert "https://x.com/i/status/456" in captured["args"]
    # a successful fire clears any prior held-attempt reason
    assert "last_attempt_reason  = NULL" in captured["query"]


@pytest.mark.asyncio
async def test_mark_sent_is_fenced_by_the_claim_it_was_given():
    """A publisher may only advance the post it still owns.

    Without the fence a publisher that had been declared dead and re-claimed
    would happily overwrite the new owner's state — which is how one scheduled
    slot ended up with two tweets on 2026-07-30.
    """
    captured = {}

    async def fake_fetchrow(query, *args):
        captured["query"] = query
        captured["args"] = args
        return None  # the WHERE matched nothing: someone else owns it now

    with patch.object(posts_db, "fetchrow", fake_fetchrow):
        held = await posts_db.mark_sent(
            PID, "2026-06-21T03:20:00+00:00", "sent", None, "url",
            claim_stamp="2026-07-30 20:30:20+00",
        )
    assert held is False
    assert "status = 'sending' AND last_attempt_at = $6::timestamptz" in captured["query"]
    assert "2026-07-30 20:30:20+00" in captured["args"]


@pytest.mark.asyncio
async def test_occurrence_and_advance_are_one_statement():
    """The snapshot and the template advance must not be separable.

    They were two awaits, and a publisher died between them: the occurrence was
    written, the template stayed `sending`, and the next tick re-fired it. One
    data-modifying CTE means either both land or neither does.
    """
    captured = {}

    async def fake_fetchrow(query, *args):
        captured["query"] = query
        captured["args"] = args
        return {"id": "occ-1"}

    with patch.object(posts_db, "fetchrow", fake_fetchrow):
        held = await posts_db.record_occurrence_and_advance(
            template_id=PID, npub="npub1x", doc={"blocks": []}, text_cache="hi",
            tweet_url="https://x.com/i/status/9", sent_at="2026-07-30T20:32:22+00:00",
            occurrence_publish_at="2026-07-30T11:40:25+00:00",
            next_publish_at="2026-07-31T11:40:25+00:00",
            claim_stamp="2026-07-30 20:30:20+00",
        )
    assert held is True
    q = captured["query"]
    # ONE statement: the UPDATE is a CTE the INSERT selects from.
    assert q.count(";") == 0
    assert "WITH advanced AS (" in q and "INSERT INTO posts" in q
    assert "FROM advanced" in q
    # …and it is fenced on the claim, so a stolen post yields no row at all.
    assert "status = 'sending' AND last_attempt_at = $9::timestamptz" in q


@pytest.mark.asyncio
async def test_re_authoring_a_flattened_block_clears_the_per_firing_mark():
    """Repairing a destroyed prompt must actually repair it.

    `resolver._lost_prompts` refuses to build a template whose authored block is
    `dynamic` AND `resolved` — the signature of a prompt overwritten before the
    doc/render split. But an editing surface that loads a damaged block and
    PATCHes it back carries that flag along, so the owner rewrites the prompt,
    saves, and the template pauses as prompt-lost anyway. Forever, over a prompt
    that is now perfectly good.

    `resolved` is never authored state, so it is stripped at the column.
    """
    captured = {}

    async def fake_fetchrow(query, *args):
        captured["args"] = args
        return {"post_id": PID, "status": "scheduled", "updated_at": "now"}

    repaired = {"blocks": [
        {"text": "static", "flags": []},
        {"text": "the newly re-authored prompt", "dynamic": True,
         "fallback": "fb", "resolved": True},
    ]}
    with patch.object(posts_db, "fetchrow", fake_fetchrow):
        await posts_db.update_post("npub1x", PID, {"doc": repaired})

    saved = json.loads(next(a for a in captured["args"] if isinstance(a, str) and "blocks" in a))
    assert "resolved" not in saved["blocks"][1], "the stale mark must not survive the save"
    assert saved["blocks"][1]["text"] == "the newly re-authored prompt"
    assert saved["blocks"][1]["dynamic"] is True, "and the block is still dynamic"
    assert saved["blocks"][1]["fallback"] == "fb"

    # Same gate on the create path, so a duplicated damaged post is clean too.
    async def fake_create(query, *args):
        captured["args"] = args
        return {"post_id": PID, "status": "draft", "created_at": "now"}

    with patch.object(posts_db, "fetchrow", fake_create):
        await posts_db.create_post(
            "npub1x", repaired, None, None, None, None, "draft", None,
        )
    saved = json.loads(next(a for a in captured["args"] if isinstance(a, str) and "blocks" in a))
    assert "resolved" not in saved["blocks"][1]


class TestSendingIsNotADeadEnd:
    """A publisher that dies must not strand its post forever.

    Before the recovery sweep, `sending` had no lease, no work-list, and no exit:
    post 1972b2e0 sat there from 2026-08-02 to 08-04, looking active and being
    unreachable. The fix must not swing the other way — no timer may re-fire a
    send, because one did on 2026-07-30 and tweeted the same post twice. So
    recovery decides on evidence, and these pin which evidence means what.
    """

    @staticmethod
    def _capture():
        seen = []

        async def fake_fetch(query, *args):
            seen.append(query)
            return []

        return seen, fake_fetch

    @pytest.mark.asyncio
    async def test_the_call_mark_is_a_compare_and_set_not_a_stamp(self):
        """It authorizes the call. A plain stamp would let an unconfirmed write
        be followed by a post, leaving a row that reads 'nothing was sent'."""
        captured = {}

        async def fake_execute(query, *args):
            captured["query"], captured["args"] = query, args
            return {"rowCount": 0}

        with patch.object(posts_db, "execute", fake_execute):
            ok = await posts_db.mark_x_call_started(PID, "2026-08-02 01:30:20+00")

        assert ok is False, "no row matched — the caller must NOT post"
        q = captured["query"]
        assert "SET x_call_at = NOW()" in q
        assert "status = 'sending'" in q, "only a claimed post may be posted"
        assert "x_call_at IS NULL" in q, "one authorization per firing"
        assert "last_attempt_at = $2::timestamptz" in q, "and only by the current owner"

    @pytest.mark.asyncio
    async def test_a_send_that_may_have_reached_x_is_paused_never_resumed(self):
        seen, fake = self._capture()
        with patch.object(posts_db, "fetch", fake):
            await posts_db.recover_orphaned_sends()
        pause = next(q for q in seen if "x_post_outcome_unknown" in q)
        assert "x_call_at IS NOT NULL" in pause
        assert "status = 'paused'" in pause
        assert "'resolved'" not in pause, "a possible live tweet is never retried"

    @pytest.mark.asyncio
    async def test_a_send_that_never_reached_x_is_resumed(self):
        """The 1972b2e0 case. `resolved_at` is the co-discriminator: only a row
        this code claimed for posting can have one, so a NULL x_call_at beside it
        is proof of a pre-call death rather than proof of missing instrumentation.
        """
        seen, fake = self._capture()
        with patch.object(posts_db, "fetch", fake):
            await posts_db.recover_orphaned_sends()
        resume = next(q for q in seen if "'resolved'" in q and "paused" not in q)
        assert "x_call_at IS NULL" in resume
        assert "resolved_at IS NOT NULL" in resume

    @pytest.mark.asyncio
    async def test_a_row_predating_the_marker_is_paused_not_reposted(self):
        """The first sweep after deploy must not read 'no mark' as 'nothing sent'
        for every historical row and repost them all."""
        seen, fake = self._capture()
        with patch.object(posts_db, "fetch", fake):
            await posts_db.recover_orphaned_sends()
        legacy = next(q for q in seen if "sending_orphaned_pre_split" in q)
        assert "x_call_at IS NULL" in legacy and "resolved_at IS NULL" in legacy
        assert "status = 'paused'" in legacy

    @pytest.mark.asyncio
    async def test_every_stale_send_matches_exactly_one_branch(self):
        """Exhaustive and disjoint: `x_call_at` splits the first from the rest,
        `resolved_at` splits the other two. A row matching none would be back to
        being invisible, which is the whole defect."""
        seen, fake = self._capture()
        with patch.object(posts_db, "fetch", fake):
            await posts_db.recover_orphaned_sends()
        assert len(seen) == 3
        assert all("status = 'sending'" in q for q in seen)
        assert all("last_attempt_at <" in q for q in seen), "only stale claims"
        assert sum("x_call_at IS NOT NULL" in q for q in seen) == 1
        assert sum("x_call_at IS NULL" in q for q in seen) == 2
        assert sum("resolved_at IS NOT NULL" in q for q in seen) == 1
        assert sum("resolved_at IS NULL" in q for q in seen) == 1

    @pytest.mark.asyncio
    async def test_claiming_for_post_clears_the_previous_firings_mark(self):
        """Otherwise a recurrence inherits the last occurrence's mark and is
        paused for a send that completed days ago."""
        captured = {}

        async def fake_fetchrow(query, *args):
            captured["query"] = query
            return None

        with patch.object(posts_db, "fetchrow", fake_fetchrow):
            await posts_db.claim_for_post(PID)
        assert "x_call_at = NULL" in captured["query"]

    @pytest.mark.asyncio
    async def test_a_post_phase_hold_returns_to_the_poster_not_the_resolver(self):
        """`release_to_resolved` exists because `sending → scheduled` sent a
        finished, paid-for body back to the resolve queue, burning one of five
        lifetime firing attempts every time the publisher merely had a bad day."""
        captured = {}

        async def fake_execute(query, *args):
            captured["query"] = query
            return {"rowCount": 1}

        with patch.object(posts_db, "execute", fake_execute):
            ok = await posts_db.release_to_resolved(PID, "2026-08-02 01:30:20+00")
        assert ok is True
        assert "SET status = 'resolved'" in captured["query"]
        assert "status = 'sending'" in captured["query"]
        assert "last_attempt_at = $2::timestamptz" in captured["query"]


@pytest.mark.asyncio
async def test_a_post_at_the_firing_cap_is_paused_not_silently_dropped():
    """At the cap both work-lists drop the row while it still reads `scheduled`.
    It looks queued, is unreachable, and the only counter reset is a successful
    advance that can now never happen. Pausing makes it visible and resumable."""
    captured = {}

    async def fake_fetch(query, *args):
        captured["query"] = query
        return []

    with patch.object(posts_db, "fetch", fake_fetch):
        await posts_db.pause_exhausted_firings("2026-08-05T00:00:00+00:00")
    q = captured["query"]
    assert "status = 'paused'" in q
    assert "firing_attempts_exhausted" in q
    assert f"resolve_attempts >= {posts_db.MAX_RESOLVE_ATTEMPTS}" in q
    assert "COALESCE(last_attempt_reason" in q, "the real reason must survive"
    # The claim that walks a row to the cap leaves it `resolving`, not
    # `scheduled`. If the sweep only matched `scheduled`, that claim would
    # strand the post with no work-list and no exit (#344).
    assert "'resolving'" in q


@pytest.mark.asyncio
async def test_resolving_at_the_firing_cap_has_an_automatic_exit():
    """#344: claim_for_resolve admits a row at 4 and increments to 5, leaving
    status='resolving'. list_due_for_resolve and claim_for_resolve both reject
    it on the counter; recover_orphaned_sends only scans sending. Without this
    sweep branch the row is permanently invisible while looking in-progress.

    A pause needs an exit (#339). Pausing lands on the same Resume path that
    already zeroes resolve_attempts.
    """
    captured = {}

    async def fake_fetch(query, *args):
        captured["query"] = query
        return []

    with patch.object(posts_db, "fetch", fake_fetch):
        await posts_db.pause_exhausted_firings("2026-08-05T00:00:00+00:00")
    q = captured["query"]
    assert "status = 'paused'" in q
    assert f"resolve_attempts >= {posts_db.MAX_RESOLVE_ATTEMPTS}" in q
    # Must match the stranded resolving-at-cap shape, not only scheduled.
    assert "'resolving'" in q
    # Do not yank a live resolve still inside its lease — only orphaned ones.
    # The resolve lease is interval '20 minutes' (_RESOLVE_LEASE).
    assert "last_attempt_at" in q
    assert "20 minutes" in q


@pytest.mark.asyncio
async def test_resuming_a_post_clears_the_firing_counters():
    """Without this the pause has no exit: the sweep pauses a post at the cap,
    the owner clicks Resume, and the next tick pauses it again on the same
    counter. An infinite loop with a button in it."""
    captured = {}

    async def fake_fetchrow(query, *args):
        captured["query"] = query
        return {"post_id": PID, "status": "scheduled", "updated_at": "now"}

    with patch.object(posts_db, "fetchrow", fake_fetchrow):
        await posts_db.update_post("npub1x", PID, {"status": "scheduled"})
    q = captured["query"]
    assert "resolve_attempts = 0" in q
    assert "x_call_at = NULL" in q and "resolved_at = NULL" in q
    assert "last_attempt_reason = NULL" in q
    assert "render = NULL" not in q, "Resume must not re-bill blocks already paid for"


@pytest.mark.asyncio
async def test_the_single_phase_publish_queries_are_gone():
    """They carried the only `sending` recovery clause in the codebase and had no
    callers, so the file read as though recovery existed while nothing ran it."""
    for name in ("list_due", "claim_due_post", "release_claim"):
        assert not hasattr(posts_db, name), f"{name} is dead and must not return"


@pytest.mark.asyncio
async def test_save_render_writes_render_and_never_doc():
    """The column boundary, asserted in SQL — the layer where it is real.

    Resolution wrote its output into `doc` until 2026-08-04. Since a dynamic
    block's prompt IS its `text`, that consumed the authored template on the
    first firing. Nothing in the publishing path may hold a write handle on
    `doc`; assertions about in-memory dicts do not establish that, because the
    block list is rebuilt on every read and the damage was only ever durable.
    """
    captured = {}

    async def fake_execute(query, *args):
        captured["query"] = query
        return {"rowCount": 1}

    with patch.object(posts_db, "execute", fake_execute):
        ok = await posts_db.save_render(
            PID, {"blocks": [{"text": "answer"}]}, "2026-07-30 20:30:20+00",
        )

    assert ok is True
    q = captured["query"]
    assert "SET render = $2::jsonb" in q
    assert "doc" not in q, "the authored doc is not writable from the resolve path"
    # Still fenced: a superseded worker must not overwrite its replacement.
    assert "last_attempt_at = $3::timestamptz" in q


@pytest.mark.asyncio
async def test_advancing_a_recurrence_clears_this_firings_state():
    """A template advancing to its next occurrence must carry nothing forward.

    `render` left standing is last firing's finished text sitting where the next
    firing looks for work — the post freezes and reposts it forever.
    `resolve_attempts` left standing is subtler: it increments on every claim,
    including successful ones, and is capped, so a healthy recurring template
    silently stopped resolving after its 5th firing by dropping off the
    work-list.
    """
    captured = {}

    async def fake_fetchrow(query, *args):
        captured["query"] = query
        return {"id": "occ-1"}

    with patch.object(posts_db, "fetchrow", fake_fetchrow):
        await posts_db.record_occurrence_and_advance(
            template_id=PID, npub="npub1x", doc={"blocks": []}, text_cache="hi",
            tweet_url="u", sent_at="2026-07-30T20:32:22+00:00",
            occurrence_publish_at=None, next_publish_at="2026-07-31T11:40:25+00:00",
            claim_stamp="2026-07-30 20:30:20+00",
        )

    advanced = captured["query"].split("INSERT INTO posts")[0]
    assert "render               = NULL" in advanced
    assert "resolve_attempts     = 0" in advanced
    assert "resolved_at          = NULL" in advanced


@pytest.mark.asyncio
async def test_editing_the_doc_drops_a_stale_render():
    """An edit invalidates whatever this firing built from the OLD prompts.
    Keeping it would publish text the author has just rewritten."""
    captured = {}

    async def fake_fetchrow(query, *args):
        captured["query"] = query
        return {"post_id": PID, "status": "scheduled", "updated_at": "now"}

    with patch.object(posts_db, "fetchrow", fake_fetchrow):
        await posts_db.update_post("npub1x", PID, {"doc": {"blocks": []}})
    assert "render = NULL" in captured["query"]

    with patch.object(posts_db, "fetchrow", fake_fetchrow):
        await posts_db.update_post("npub1x", PID, {"title": "just a rename"})
    assert "render = NULL" not in captured["query"], "an unrelated patch keeps progress"


@pytest.mark.asyncio
async def test_occurrence_and_advance_reports_a_lost_claim():
    with patch.object(posts_db, "fetchrow", AsyncMock(return_value=None)):
        held = await posts_db.record_occurrence_and_advance(
            template_id=PID, npub="npub1x", doc={}, text_cache=None,
            tweet_url="u", sent_at="2026-07-30T20:32:22+00:00",
            occurrence_publish_at=None, next_publish_at=None,
            claim_stamp="2026-07-30 20:30:20+00",
        )
    assert held is False


@pytest.mark.asyncio
async def test_mark_attempt_stamps_reason_and_time():
    captured = {}

    async def fake_execute(query, *args):
        captured["query"] = query
        captured["args"] = args
        return {"rowCount": 1}

    with patch.object(posts_db, "execute", fake_execute):
        await posts_db.mark_attempt(PID, "2026-06-21T20:00:00+00:00", "insufficient_balance")
    q = captured["query"]
    assert "last_attempt_at     = $2::timestamptz" in q
    assert "last_attempt_reason = $3" in q
    assert "last_attempt_detail = $4" in q
    assert "WHERE id = $1::uuid" in q
    assert captured["args"] == (
        PID, "2026-06-21T20:00:00+00:00", "insufficient_balance", None, None,
    )


@pytest.mark.asyncio
async def test_mark_attempt_hands_a_claimed_post_back():
    """The transition nothing covered, and it is not a small one.

    `sending → scheduled` puts a post back in the RESOLVE queue, and the next
    claim there increments `resolve_attempts`. So this one CASE clause is why a
    run of publisher holds — a weekend without credits — walks a healthy post to
    the attempt cap and retires it.
    """
    captured = {}

    async def fake_execute(query, *args):
        captured["query"] = query
        return {"rowCount": 1}

    with patch.object(posts_db, "execute", fake_execute):
        await posts_db.mark_attempt(PID, "2026-06-21T20:00:00+00:00", "x_api_error")
    assert "CASE WHEN status = 'sending' THEN 'scheduled' ELSE status END" in captured["query"]


@pytest.mark.asyncio
async def test_mark_paused_stops_the_post():
    """Also previously untested: that pausing actually pauses. Every non-transient
    situation — a 402, an unconfirmed send, a destroyed prompt — depends on this
    single SET reaching the column."""
    captured = {}

    async def fake_execute(query, *args):
        captured["query"] = query
        captured["args"] = args
        return {"rowCount": 1}

    with patch.object(posts_db, "execute", fake_execute):
        await posts_db.mark_paused(
            PID, "2026-06-21T20:00:00+00:00", "x_api_error: 402", "lapsed",
        )
    assert "status              = 'paused'" in captured["query"]
    assert captured["args"][2] == "x_api_error: 402"


@pytest.mark.asyncio
async def test_the_state_stamps_are_fenced_by_the_claim_they_were_given():
    """A worker presumed dead must not stamp its replacement's row.

    Live today in the resolve phase: the lease is 20 minutes, so a slow resolver
    wakes, reports a hold, and flips the REPLACEMENT's `resolving` row back to
    `scheduled` mid-build. `None` stays unfenced for callers holding no claim.
    """
    captured = {}

    async def fake_execute(query, *args):
        captured["query"] = query
        captured["args"] = args
        return {"rowCount": 1}

    for fn in (posts_db.mark_attempt, posts_db.mark_paused):
        with patch.object(posts_db, "execute", fake_execute):
            await fn(PID, "2026-06-21T20:00:00+00:00", "r", None,
                     claim_stamp="2026-06-21 19:30:00+00")
        assert "last_attempt_at = $5::timestamptz" in captured["query"], fn.__name__
        assert captured["args"][4] == "2026-06-21 19:30:00+00", fn.__name__


@pytest.mark.asyncio
async def test_list_posts_offset_sort_and_total():
    captured = {}

    async def fake_fetchrow(query, *args):  # COUNT(*)
        captured["count_query"] = query
        captured["count_args"] = args
        return {"n": 7}

    async def fake_fetch(query, *args):  # paged rows
        captured["query"] = query
        captured["args"] = args
        return [
            {"post_id": "id0", "status": "scheduled", "excerpt": "e0",
             "publish_at": None, "updated_at": "t", "created_at": "c", "tweet_url": None,
             "last_sent_at": "2026-06-21T14:39:00+00:00",
             "last_attempt_at": "2026-06-21T20:00:00+00:00",
             "last_attempt_reason": "insufficient_balance"},
        ]

    with patch.object(posts_db, "fetchrow", fake_fetchrow), \
         patch.object(posts_db, "fetch", fake_fetch):
        out = await posts_db.list_posts(
            NPUB, status="draft", sort_col="updated", sort_dir="asc",
            page=2, page_size=5,
        )
    q = captured["query"]
    assert "ORDER BY updated_at ASC, created_at DESC" in q
    assert "LIMIT $3 OFFSET $4" in q
    assert captured["args"][0] == NPUB
    # `status` is matched as set membership; a single status becomes a 1-element list.
    assert "status = ANY($2::text[])" in q
    assert captured["args"][1] == ["draft"]
    assert captured["args"][2] == 5  # page_size
    assert captured["args"][3] == 10  # page 2 * size 5
    assert "last_sent_at" in q
    assert "last_attempt_at, last_attempt_reason" in q
    assert out["total"] == 7
    assert out["page"] == 2 and out["page_size"] == 5
    assert out["posts"][0]["excerpt"] == "e0"
    assert out["posts"][0]["last_sent_at"] == "2026-06-21T14:39:00+00:00"
    assert out["posts"][0]["last_attempt_reason"] == "insufficient_balance"
    assert out["posts"][0]["last_attempt_at"] == "2026-06-21T20:00:00+00:00"


@pytest.mark.asyncio
async def test_list_posts_surfaces_recurring_dynamic_and_template_id():
    """Each row carries the FE badges' data: is_recurring, has_dynamic, and the
    template_id back-link on a sent occurrence."""
    captured = {}

    async def fake_fetchrow(query, *args):
        return {"n": 1}

    async def fake_fetch(query, *args):
        captured["query"] = query
        return [
            {"post_id": "occ1", "status": "sent", "excerpt": "e", "publish_at": None,
             "updated_at": "t", "created_at": "c", "tweet_url": "u", "last_sent_at": None,
             "last_attempt_at": None, "last_attempt_reason": None,
             "template_id": "tmpl1", "is_recurring": False, "has_dynamic": False},
        ]

    with patch.object(posts_db, "fetchrow", fake_fetchrow), \
         patch.object(posts_db, "fetch", fake_fetch):
        out = await posts_db.list_posts(NPUB)

    q = captured["query"]
    assert "(recurrence IS NOT NULL) AS is_recurring" in q
    assert '''doc->'blocks' @> '[{"dynamic":true}]'::jsonb''' in q
    assert "template_id::text AS template_id" in q
    row = out["posts"][0]
    assert row["template_id"] == "tmpl1"
    assert row["is_recurring"] is False and row["has_dynamic"] is False


@pytest.mark.asyncio
async def test_list_posts_template_id_filter():
    """A template_id filter scopes the list to that template's sent occurrences."""
    captured = {}

    async def fake_fetchrow(query, *args):
        return {"n": 0}

    async def fake_fetch(query, *args):
        captured["query"] = query
        captured["args"] = args
        return []

    with patch.object(posts_db, "fetchrow", fake_fetchrow), \
         patch.object(posts_db, "fetch", fake_fetch):
        await posts_db.list_posts(NPUB, template_id="tmpl-uuid")

    assert "template_id = $2::uuid" in captured["query"]
    assert captured["args"][1] == "tmpl-uuid"


@pytest.mark.asyncio
async def test_create_sent_occurrence_backlinks_template():
    """The sent snapshot INSERT carries template_id → its recurring template."""
    captured = {}

    async def fake_execute(query, *args):
        captured["query"] = query
        captured["args"] = args
        return {}

    with patch.object(posts_db, "execute", fake_execute):
        await posts_db.create_sent_occurrence(
            npub=NPUB, doc={"blocks": []}, text_cache="t", tweet_url="u",
            sent_at="2026-07-10T01:34:53+00:00", template_id="tmpl1",
            publish_at="2026-07-10T01:33:00+00:00",
        )
    assert "template_id" in captured["query"]
    assert captured["args"][-1] == "tmpl1"


@pytest.mark.asyncio
async def test_list_posts_multi_status_set_membership():
    """A comma-separated status filter (the FE's include chiclets) matches any of
    the listed statuses via a single ``status = ANY(...)`` predicate."""
    captured = {}

    async def fake_fetchrow(query, *args):
        captured["count_query"] = query
        return {"n": 3}

    async def fake_fetch(query, *args):
        captured["query"] = query
        captured["args"] = args
        return []

    with patch.object(posts_db, "fetchrow", fake_fetchrow), \
         patch.object(posts_db, "fetch", fake_fetch):
        await posts_db.list_posts(NPUB, status="draft, scheduled ,paused")

    assert "status = ANY($2::text[])" in captured["query"]
    # Whitespace around each comma-separated status is trimmed.
    assert captured["args"][1] == ["draft", "scheduled", "paused"]
    # A single ANY predicate, not one per status.
    assert captured["query"].count("status = ANY") == 1


@pytest.mark.asyncio
async def test_list_posts_search_and_date_filter_build_where():
    captured = {}

    async def fake_fetchrow(query, *args):  # COUNT(*)
        captured["count_query"] = query
        captured["count_args"] = args
        return {"n": 3}

    async def fake_fetch(query, *args):
        captured["query"] = query
        captured["args"] = args
        return []

    with patch.object(posts_db, "fetchrow", fake_fetchrow), \
         patch.object(posts_db, "fetch", fake_fetch):
        await posts_db.list_posts(
            NPUB, search="hel+o", date_from="2026-06-01", date_to="2026-06-30",
            date_field="scheduled", page=0, page_size=10,
        )
    q = captured["query"]
    assert "text_cache ~* $2" in q  # regex content match
    assert "publish_at >= $3::date" in q  # date_field=scheduled → publish_at
    assert "publish_at < ($4::date + interval '1 day')" in q  # end-inclusive
    # COUNT shares the same filter params (npub, search, from, to)
    assert captured["count_args"] == (NPUB, "hel+o", "2026-06-01", "2026-06-30")
    # page params come after the filter params
    assert captured["args"][:5] == (NPUB, "hel+o", "2026-06-01", "2026-06-30", 10)


@pytest.mark.asyncio
async def test_list_posts_unknown_date_field_falls_back_to_created():
    with patch.object(posts_db, "fetchrow", AsyncMock(return_value={"n": 0})), \
         patch.object(posts_db, "fetch", AsyncMock(return_value=[])) as f:
        await posts_db.list_posts(NPUB, date_from="2026-01-01", date_field="; DROP")
    q = f.await_args.args[0]
    assert "created_at >= $2::date" in q  # unknown field → created_at, no raw SQL
    assert "DROP" not in q


@pytest.mark.asyncio
async def test_list_posts_unknown_sort_falls_back_to_created():
    async def fake_fetchrow(query, *args):
        return {"n": 0}

    captured = {}

    async def fake_fetch(query, *args):
        captured["query"] = query
        return []

    with patch.object(posts_db, "fetchrow", fake_fetchrow), \
         patch.object(posts_db, "fetch", fake_fetch):
        await posts_db.list_posts(NPUB, sort_col="; DROP TABLE posts; --")
    # Unknown key never reaches the query as raw SQL — falls back to created_at.
    assert "ORDER BY created_at DESC, created_at DESC" in captured["query"]
    assert "DROP TABLE" not in captured["query"]


@pytest.mark.asyncio
async def test_hard_delete_uses_rowcount_camelcase():
    with patch.object(posts_db, "execute", AsyncMock(return_value={"rowCount": 1})):
        assert await posts_db.hard_delete(NPUB, PID) is True
    with patch.object(posts_db, "execute", AsyncMock(return_value={"rowCount": 0})):
        assert await posts_db.hard_delete(NPUB, PID) is False
