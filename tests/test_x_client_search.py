"""``XClient.search_recent`` — fixed field set, cursor/since threading, X's own
words on a 400, and nothing kept beyond what the scorer reads."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from excalibur_mcp.x_client import XAPIError, XClient, XCredentials


def _resp(status: int, body: dict):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = body
    r.text = json.dumps(body)
    return r


def _stub(resp):
    mock = patch("excalibur_mcp.x_client.httpx.AsyncClient")
    MockClient = mock.start()
    inst = AsyncMock()
    inst.get = AsyncMock(return_value=resp)
    inst.__aenter__ = AsyncMock(return_value=inst)
    inst.__aexit__ = AsyncMock(return_value=False)
    MockClient.return_value = inst
    return mock, inst


@pytest.mark.asyncio
async def test_search_recent_params_and_shape():
    client = XClient(XCredentials(bearer_token="tok"))
    body = {
        "data": [{"id": "1", "conversation_id": "1", "author_id": "a", "text": "hi"}],
        "includes": {"users": [{"id": "a", "username": "ann"}]},
        "meta": {"result_count": 1, "next_token": "n2", "newest_id": "1"},
    }
    mock, inst = _stub(_resp(200, body))
    try:
        out = await client.search_recent("mcp", max_results=7, next_token="n1", since_id="9")
    finally:
        mock.stop()

    params = inst.get.await_args.kwargs["params"]
    assert params["query"] == "mcp"
    assert params["max_results"] == 10  # floor
    assert params["next_token"] == "n1" and params["since_id"] == "9"
    assert params["expansions"] == "author_id"
    assert "conversation_id" in params["tweet.fields"]
    assert "in_reply_to_user_id" in params["tweet.fields"]
    assert "location" in params["user.fields"]
    assert inst.get.await_args.kwargs["headers"]["Authorization"] == "Bearer tok"

    assert out["tweets"] == body["data"]
    assert out["users"] == {"a": {"id": "a", "username": "ann"}}
    assert out["next_token"] == "n2" and out["newest_id"] == "1"
    assert out["result_count"] == 1
    assert "raw" not in out


@pytest.mark.asyncio
async def test_search_recent_caps_at_100_and_omits_optional_params():
    client = XClient(XCredentials(bearer_token="tok"))
    mock, inst = _stub(_resp(200, {"data": [], "meta": {"result_count": 0}}))
    try:
        out = await client.search_recent("mcp", max_results=500)
    finally:
        mock.stop()
    params = inst.get.await_args.kwargs["params"]
    assert params["max_results"] == 100
    assert "next_token" not in params and "since_id" not in params
    assert out["tweets"] == [] and out["next_token"] is None


@pytest.mark.asyncio
async def test_search_recent_400_carries_x_message():
    client = XClient(XCredentials(bearer_token="tok"))
    body = {"errors": [{"message": "Reference to invalid operator 'community_id'"}]}
    mock, _ = _stub(_resp(400, body))
    try:
        with pytest.raises(XAPIError) as exc:
            await client.search_recent("community_id:1")
    finally:
        mock.stop()
    assert exc.value.status_code == 400
    assert "invalid operator" in exc.value.detail


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403, 429, 500])
async def test_search_recent_raises_on_other_statuses(status):
    client = XClient(XCredentials(bearer_token="tok"))
    mock, _ = _stub(_resp(status, {"title": "nope"}))
    try:
        with pytest.raises(XAPIError) as exc:
            await client.search_recent("mcp")
    finally:
        mock.stop()
    assert exc.value.status_code == status


@pytest.mark.asyncio
async def test_search_recent_rejects_empty_query_without_a_request():
    client = XClient(XCredentials(bearer_token="tok"))
    with pytest.raises(XAPIError):
        await client.search_recent("   ")


@pytest.mark.asyncio
async def test_post_tweet_in_reply_to_sets_reply_payload():
    client = XClient(XCredentials(bearer_token="tok"))
    resp = _resp(201, {"data": {"id": "999", "text": "hi"}})
    with patch.object(client, "_post_retrying_connect", new=AsyncMock(return_value=resp)) as post:
        out = await client.post_tweet("hi", in_reply_to="123")
    payload = post.await_args.args[1]
    assert payload == {"text": "hi", "reply": {"in_reply_to_tweet_id": "123"}}
    assert out["tweet_id"] == "999" and out["in_reply_to"] == "123"
    assert out["tweet_url"] == "https://x.com/i/status/999"


@pytest.mark.asyncio
async def test_post_tweet_without_reply_keeps_old_payload_and_rejects_bad_id():
    client = XClient(XCredentials(bearer_token="tok"))
    resp = _resp(201, {"data": {"id": "1", "text": "hi"}})
    with patch.object(client, "_post_retrying_connect", new=AsyncMock(return_value=resp)) as post:
        out = await client.post_tweet("hi")
    assert post.await_args.args[1] == {"text": "hi"} and "in_reply_to" not in out
    with pytest.raises(XAPIError):
        await client.post_tweet("hi", in_reply_to="not-an-id")
