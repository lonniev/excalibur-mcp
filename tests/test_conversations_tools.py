"""Conversation-lead handlers: adversarial input, the refund discipline of
``find`` (refund only when X was never read), X paging, own-post exclusion,
per-conversation dedupe, and the since_id watermark. The DB and X client are
faked; proof and billing are the decorator's and are not disabled here."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from excalibur_mcp.tools import conversations as tools
from excalibur_mcp.x_client import XAPIError

NPUB = "npub1l94pd4qu4eszrl6ek032ftcnsu3tt9a7xvq2zp7eaxeklp6mrpzssmq8pf"
QID = "11111111-1111-1111-1111-111111111111"
RID = "22222222-2222-2222-2222-222222222222"
TOOL = "tool-uuid"
OWN = "777"


def _tweet(tid, *, author="a1", text="how do I do this", cid=None, replies=0):
    return {
        "id": tid, "conversation_id": cid or tid, "author_id": author, "text": text,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "public_metrics": {"reply_count": replies, "like_count": 0},
    }


def _page(tweets, *, next_token=None, users=None):
    return {
        "tweets": tweets,
        "users": users or {"a1": {"id": "a1", "username": "ann", "location": "Town",
                                  "public_metrics": {"followers_count": 500}}},
        "next_token": next_token,
        "result_count": len(tweets),
        "newest_id": tweets[0]["id"] if tweets else None,
    }


class FakeClient:
    def __init__(self, pages=None, *, me_error=None, search_error=None, fail_after=None):
        self.pages = list(pages or [])
        self.me_error = me_error
        self.search_error = search_error
        self.fail_after = fail_after
        self.calls: list[dict] = []

    async def get_me(self):
        if self.me_error:
            raise self.me_error
        return {"id": OWN, "username": "me"}

    async def search_recent(self, query, **kw):
        self.calls.append({"query": query, **kw})
        if self.search_error and (self.fail_after is None or len(self.calls) > self.fail_after):
            raise self.search_error
        return self.pages.pop(0) if self.pages else _page([])


def _harness(client, *, saved=None):
    runtime = SimpleNamespace(rollback_debit=AsyncMock())

    async def prepare(tool_id, npub):
        if isinstance(client, dict):
            await runtime.rollback_debit(tool_id, npub)
            return client
        return (client, "")

    async def x_err(exc, npub):
        return {"success": False, "error_code": f"x_{exc.status_code}", "error": str(exc)}

    dbm = SimpleNamespace(
        get_query=AsyncMock(return_value=saved),
        purge_stale=AsyncMock(return_value=0),
        upsert_conversations=AsyncMock(return_value=(1, 0)),
        mark_query_run=AsyncMock(),
        STATUSES=tools.db.STATUSES,
        QUERY_LIMIT_PER_NPUB=50,
    )
    return runtime, prepare, x_err, dbm


async def _find(client, **kw):
    runtime, prepare, x_err, dbm = _harness(client, saved=kw.pop("saved", None))
    with patch.object(tools, "db", dbm):
        out = await tools.find(
            NPUB, runtime=runtime, tool_id=TOOL, prepare_client=prepare,
            x_error_to_response=x_err, **kw,
        )
    return out, runtime, dbm


# -- find: input ------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.parametrize("kw", [{}, {"query": "a", "query_id": QID}])
async def test_find_requires_exactly_one_selector(kw):
    with pytest.raises(ValueError):
        await _find(FakeClient(), **kw)


@pytest.mark.asyncio
async def test_find_rejects_question_mark_and_control_chars():
    with pytest.raises(ValueError, match="'\\?'"):
        await _find(FakeClient(), query="mcp ?")
    with pytest.raises(ValueError):
        await _find(FakeClient(), query="mcp\x00")


@pytest.mark.asyncio
async def test_find_rejects_bad_weights_before_touching_x():
    client = FakeClient()
    with pytest.raises(ValueError):
        await _find(client, query="mcp", weights={"nope": 1})
    assert client.calls == []


# -- find: refund discipline ------------------------------------------------

@pytest.mark.asyncio
async def test_find_unknown_saved_query_refunds():
    out, runtime, _ = await _find(FakeClient(), query_id=QID, saved=None)
    assert out["error_code"] == "conversation_query_not_found"
    runtime.rollback_debit.assert_awaited_once_with(TOOL, NPUB)


@pytest.mark.asyncio
async def test_find_oauth_situation_passes_through_already_refunded():
    situation = {"success": False, "error_code": "oauth_no_credentials"}
    out, runtime, _ = await _find(situation, query="mcp")
    assert out is situation
    runtime.rollback_debit.assert_awaited_once()


@pytest.mark.asyncio
async def test_find_get_me_failure_refunds_once():
    out, runtime, _ = await _find(FakeClient(me_error=XAPIError(401, "bad")), query="mcp")
    assert out["error_code"] == "x_401"
    runtime.rollback_debit.assert_awaited_once_with(TOOL, NPUB)


@pytest.mark.asyncio
async def test_find_x_400_on_first_page_refunds_and_returns_input_error():
    client = FakeClient(search_error=XAPIError(400, "Reference to invalid operator"))
    out, runtime, _ = await _find(client, query="mcp")
    assert out["error_code"] == "tool_input_invalid"
    assert "invalid operator" in out["message"]
    runtime.rollback_debit.assert_awaited_once()


@pytest.mark.asyncio
async def test_find_429_on_first_page_refunds():
    out, runtime, _ = await _find(FakeClient(search_error=XAPIError(429, "slow")), query="mcp")
    assert out["error_code"] == "x_429"
    runtime.rollback_debit.assert_awaited_once()


@pytest.mark.asyncio
async def test_find_429_mid_run_keeps_rows_and_does_not_refund():
    client = FakeClient(
        [_page([_tweet("1")], next_token="n2")],
        search_error=XAPIError(429, "slow"), fail_after=1,
    )
    out, runtime, dbm = await _find(client, query="mcp", max_posts=200)
    assert out["success"] and out["truncated_reason"] == "rate_limited"
    assert out["posts_read"] == 1 and out["pages"] == 1
    runtime.rollback_debit.assert_not_awaited()
    dbm.upsert_conversations.assert_awaited_once()


# -- find: paging, filtering, scoring ----------------------------------------

@pytest.mark.asyncio
async def test_find_composes_query_excludes_self_and_pages_to_cap():
    client = FakeClient([
        _page([_tweet(str(i)) for i in range(100)], next_token="n2"),
        _page([_tweet(str(i)) for i in range(100, 200)], next_token="n3"),
        _page([_tweet(str(i)) for i in range(200, 300)], next_token="n4"),
    ])
    out, runtime, dbm = await _find(client, query="mcp", max_posts=250)
    assert client.calls[0]["query"] == f"(mcp) -is:retweet -has:links -has:cashtags lang:en -from:{OWN}"
    assert [c["max_results"] for c in client.calls] == [100, 100, 50]
    assert client.calls[1]["next_token"] == "n2"
    assert out["posts_read"] == 300 and out["pages"] == 3
    assert out["truncated_reason"] == "max_posts"
    assert len(dbm.upsert_conversations.await_args.args[1]) == 300
    runtime.rollback_debit.assert_not_awaited()


@pytest.mark.asyncio
async def test_find_stops_when_x_runs_dry():
    client = FakeClient([_page([_tweet("1")])])
    out, _, _ = await _find(client, query="mcp", max_posts=300)
    assert out["pages"] == 1 and out["truncated_reason"] is None


@pytest.mark.asyncio
async def test_find_drops_own_posts_and_dedupes_by_conversation_keeping_best():
    tweets = [
        _tweet("1", author=OWN),                                # own → skipped
        _tweet("2", text="plain", cid="2"),                     # score band only
        _tweet("3", text="how do I", cid="2", replies=5),       # same thread, better
    ]
    client = FakeClient([_page(tweets)])
    out, _, dbm = await _find(client, query="mcp")
    assert out["skipped_own"] == 1 and out["skipped_dupe"] == 1
    rows = dbm.upsert_conversations.await_args.args[1]
    assert len(rows) == 1 and rows[0]["tweet_id"] == "3"
    assert rows[0]["author_username"] == "ann" and rows[0]["author_location"] == "Town"
    assert rows[0]["is_reply"] is True  # id != conversation_id
    assert out["top"][0]["url"] == "https://x.com/ann/status/3"


@pytest.mark.asyncio
async def test_find_text_and_location_are_bounded():
    t = _tweet("1", text="x" * 5000)
    users = {"a1": {"id": "a1", "username": "ann", "location": "L" * 500, "public_metrics": {}}}
    client = FakeClient([_page([t], users=users)])
    _, _, dbm = await _find(client, query="mcp")
    row = dbm.upsert_conversations.await_args.args[1][0]
    assert len(row["text"]) == 1000 and len(row["author_location"]) == 64


@pytest.mark.asyncio
async def test_find_safe_defaults_off_and_call_weights_merge():
    client = FakeClient([_page([_tweet("1", text="plain")])])
    out, _, dbm = await _find(client, query="mcp", safe_defaults=False, weights={"band": 60})
    assert out["effective_query"] == f"(mcp) -from:{OWN}"
    assert dbm.upsert_conversations.await_args.args[1][0]["score"] == 60


# -- find: saved queries ----------------------------------------------------

def _saved(**over):
    base = {"id": QID, "query": "mcp", "safe_defaults": True, "weights": {"need": 10},
            "since_id": "500", "last_run_at": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()}
    base.update(over)
    return base


@pytest.mark.asyncio
async def test_find_saved_query_threads_since_id_and_marks_run():
    client = FakeClient([_page([_tweet("9")])])
    out, _, dbm = await _find(client, query_id=QID, saved=_saved())
    assert client.calls[0]["since_id"] == "500"
    assert out["since_id"] == "500" and out["query_id"] == QID
    dbm.mark_query_run.assert_awaited_once_with(NPUB, QID, since_id="9", posts_read=1)
    assert dbm.upsert_conversations.await_args.args[1][0]["query_id"] == QID


@pytest.mark.asyncio
async def test_find_saved_query_stale_watermark_is_dropped():
    old = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
    client = FakeClient([_page([_tweet("9")])])
    out, _, _ = await _find(client, query_id=QID, saved=_saved(last_run_at=old))
    assert client.calls[0]["since_id"] is None and out["since_id"] is None


@pytest.mark.asyncio
async def test_find_saved_weights_apply_under_call_overrides():
    client = FakeClient([_page([_tweet("9", text="how do I")])])
    _, _, dbm = await _find(client, query_id=QID, saved=_saved(), weights={"band": 0})
    # need overridden to 10 by the saved query, band zeroed by the call
    assert dbm.upsert_conversations.await_args.args[1][0]["score"] == 10


@pytest.mark.asyncio
async def test_find_adhoc_never_marks_a_run():
    _, _, dbm = await _find(FakeClient([_page([_tweet("1")])]), query="mcp")
    dbm.mark_query_run.assert_not_awaited()


# -- list / status / catalog -------------------------------------------------

@pytest.mark.asyncio
async def test_list_threads_filters_and_adds_url():
    paged = {"conversations": [{"author_username": "ann", "tweet_id": "5"}], "total": 1,
             "page": 0, "page_size": 25}
    with patch.object(tools.db, "list_conversations", new=AsyncMock(return_value=paged)) as lst:
        out = await tools.list_(NPUB, query_id=QID, status="new, seen", min_score=150, search="x")
    lst.assert_awaited_once()
    kw = lst.await_args.kwargs
    assert kw["query_id"] == QID and kw["statuses"] == ["new", "seen"] and kw["min_score"] == 100
    assert out["conversations"][0]["url"] == "https://x.com/ann/status/5"


@pytest.mark.asyncio
async def test_list_adhoc_and_bad_status():
    with patch.object(tools.db, "list_conversations", new=AsyncMock(return_value={"conversations": []})) as lst:
        await tools.list_(NPUB, query_id="adhoc")
    assert lst.await_args.kwargs["adhoc_only"] is True
    with pytest.raises(ValueError):
        await tools.list_(NPUB, status="bogus")


@pytest.mark.asyncio
async def test_set_status_enum_and_not_found():
    with pytest.raises(ValueError):
        await tools.set_status(NPUB, conversation_id=RID, status="archived")
    with patch.object(tools.db, "set_status", new=AsyncMock(return_value=None)):
        out = await tools.set_status(NPUB, conversation_id=RID, status="seen")
    assert out["error_code"] == "conversation_not_found"


@pytest.mark.asyncio
async def test_save_query_create_checks_name_and_limit():
    with patch.object(tools.db, "find_query_by_name", new=AsyncMock(return_value={"id": "x"})):
        out = await tools.save_query(NPUB, name="Mine", query="mcp")
    assert out["error_code"] == "conversation_query_name_taken"
    with patch.object(tools.db, "find_query_by_name", new=AsyncMock(return_value=None)), \
         patch.object(tools.db, "count_queries", new=AsyncMock(return_value=50)):
        out = await tools.save_query(NPUB, name="Mine", query="mcp")
    assert out["error_code"] == "conversation_query_limit"
    with patch.object(tools.db, "find_query_by_name", new=AsyncMock(return_value=None)), \
         patch.object(tools.db, "count_queries", new=AsyncMock(return_value=0)), \
         patch.object(tools.db, "create_query", new=AsyncMock(return_value={"id": QID})) as cq:
        out = await tools.save_query(NPUB, name=" Mine ", query="mcp", weights={"need": 5})
    assert out == {"success": True, "query": {"id": QID}}
    assert cq.await_args.kwargs == {"name": "Mine", "query": "mcp", "weights": {"need": 5},
                                    "safe_defaults": True}


@pytest.mark.asyncio
async def test_save_query_update_patches_only_given_fields():
    with patch.object(tools.db, "update_query", new=AsyncMock(return_value={"id": QID})) as uq:
        await tools.save_query(NPUB, query_id=QID, safe_defaults=False)
    assert uq.await_args.kwargs == {"name": None, "query": None, "weights": None, "safe_defaults": False}


@pytest.mark.asyncio
async def test_delete_query_not_found_and_uuid_guard():
    with pytest.raises(ValueError):
        await tools.delete_query(NPUB, query_id="nope")
    with patch.object(tools.db, "delete_query", new=AsyncMock(return_value=False)):
        out = await tools.delete_query(NPUB, query_id=QID)
    assert out["error_code"] == "conversation_query_not_found"


# -- registry ---------------------------------------------------------------

def test_conversation_tools_are_in_domain_tool_registry():
    """Every handler above is reached through ``paid_tool``; without a
    ToolIdentity row the dispatch layer answers tool_not_registered. The search
    is `heavy` (X bills the operator per post returned); the rest are free."""
    from tollbooth.tool_identity import capability_uuid

    from excalibur_mcp.server import _DOMAIN_TOOLS, TOOL_REGISTRY

    expected = {
        "find_conversations": "heavy",
        "list_conversations": "free",
        "set_conversation_status": "free",
        "list_conversation_queries": "free",
        "save_conversation_query": "free",
        "delete_conversation_query": "free",
    }
    by_cap = {ti.capability: ti for ti in _DOMAIN_TOOLS}
    for capability, category in expected.items():
        uid = capability_uuid(capability)
        assert uid in TOOL_REGISTRY, f"{capability} missing from TOOL_REGISTRY"
        assert by_cap[capability].category == category
        assert uid[14] == "5"  # UUIDv5 nibble — capability_uuid, not a hand-typed id
    assert by_cap["find_conversations"].pricing_hint_value > 0


@pytest.mark.asyncio
async def test_x_api_error_429_maps_to_upstream_rate_limited():
    from excalibur_mcp import server as srv

    out = await srv._x_api_error_to_response(XAPIError(429, "Too Many Requests"), "")
    assert out["error_code"] == "upstream_rate_limited" and out["success"] is False


@pytest.mark.asyncio
async def test_find_accepts_a_clause_up_to_x_budget_and_refuses_beyond():
    from excalibur_mcp import conversation_scoring as sc
    client = FakeClient([_page([])])
    out, _, _ = await _find(client, query="x" * sc.MAX_CLAUSE)
    assert out["success"] and len(client.calls[0]["query"]) <= 512
    with pytest.raises(ValueError, match="512"):
        await _find(FakeClient(), query="x" * (sc.MAX_CLAUSE + 1))
