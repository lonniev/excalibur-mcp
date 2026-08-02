"""Post-metrics harvest subsystem — schema, cadence, derived scores, X fetch.

These tests establish the feature gap (#321) and prove the fix: they fail
when the subsystem is absent and pass once schema/harvest/tools land.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

NPUB = "npub1l94pd4qu4eszrl6ek032ftcnsu3tt9a7xvq2zp7eaxeklp6mrpzssmq8pf"
PID = "11111111-1111-1111-1111-111111111111"
TWEET_ID = "1234567890123456789"


# ---------------------------------------------------------------------------
# Cadence constants & scheduling
# ---------------------------------------------------------------------------


def test_harvest_cadence_offsets_cover_window_before_30d_cliff():
    """Decaying cadence ends at day 28 — margin against X's 30-day metrics cliff."""
    from excalibur_mcp.metrics_harvest import HARVEST_CADENCE, MAX_HARVEST_AGE_DAYS

    keys = [c[0] for c in HARVEST_CADENCE]
    assert keys == ["15m", "1h", "6h", "24h", "72h", "7d", "28d"]
    assert MAX_HARVEST_AGE_DAYS == 28
    # Last slot is day 28 in seconds
    assert HARVEST_CADENCE[-1][1] == 28 * 24 * 3600
    # First slot is 15 minutes
    assert HARVEST_CADENCE[0][1] == 15 * 60


def test_schedule_jobs_after_send_creates_one_row_per_cadence():
    """After a successful post, seven harvest jobs are due at decaying offsets."""
    from excalibur_mcp.metrics_harvest import jobs_for_send

    sent_at = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
    jobs = jobs_for_send(
        post_id=PID,
        tweet_id=TWEET_ID,
        npub=NPUB,
        sent_at=sent_at,
        link_placement="body",
        snippet_ids=["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"],
        voice_id=NPUB,
    )
    assert len(jobs) == 7
    assert jobs[0]["cadence_key"] == "15m"
    assert jobs[0]["due_at"] == sent_at + timedelta(minutes=15)
    assert jobs[-1]["cadence_key"] == "28d"
    assert jobs[-1]["due_at"] == sent_at + timedelta(days=28)
    assert all(j["tweet_id"] == TWEET_ID for j in jobs)
    assert all(j["link_placement"] == "body" for j in jobs)


# ---------------------------------------------------------------------------
# DB layer — append-only snapshots
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_insert_snapshot_is_append_only_never_upsert():
    """Snapshots are INSERT-only; no ON CONFLICT upsert path."""
    from excalibur_mcp.db import metrics as metrics_db

    captured: dict = {}

    async def fake_fetchrow(query, *args):
        captured["query"] = query
        captured["args"] = args
        return {
            "snapshot_id": "22222222-2222-2222-2222-222222222222",
            "captured_at": "2026-08-01T12:15:00+00:00",
        }

    with patch.object(metrics_db, "fetchrow", fake_fetchrow):
        row = await metrics_db.insert_snapshot(
            post_id=PID,
            tweet_id=TWEET_ID,
            npub=NPUB,
            t_offset=900,
            impressions=120,
            likes=3,
            replies=1,
            reposts=0,
            quotes=0,
            bookmarks=2,
            url_link_clicks=5,
            user_profile_clicks=1,
            link_placement="body",
            snippet_ids=["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"],
            voice_id=NPUB,
            cadence_key="15m",
            raw={"data": {}},
        )
    assert "INSERT INTO post_metrics_snapshot" in captured["query"]
    assert "ON CONFLICT" not in captured["query"].upper()
    assert "UPDATE" not in captured["query"].upper().split("INSERT")[0]
    assert captured["args"][0] == PID
    assert captured["args"][1] == TWEET_ID
    assert row["snapshot_id"]


@pytest.mark.asyncio
async def test_list_snapshots_for_post_is_npub_scoped():
    from excalibur_mcp.db import metrics as metrics_db

    captured: dict = {}

    async def fake_fetch(query, *args):
        captured["query"] = query
        captured["args"] = args
        return []

    with patch.object(metrics_db, "fetch", fake_fetch):
        await metrics_db.list_snapshots(NPUB, PID)
    assert "npub = $1" in captured["query"]
    assert "post_id" in captured["query"]
    assert captured["args"][0] == NPUB
    assert captured["args"][1] == PID


@pytest.mark.asyncio
async def test_claim_due_harvest_jobs_fences_concurrent_ticks():
    """Due jobs move pending → harvesting atomically; dead-letter after max attempts."""
    from excalibur_mcp.db import metrics as metrics_db
    from excalibur_mcp.metrics_harvest import MAX_HARVEST_ATTEMPTS

    assert MAX_HARVEST_ATTEMPTS >= 3
    listed: dict = {}
    claimed_q: dict = {}

    async def fake_fetch(query, *args):
        listed["query"] = query
        listed["args"] = args
        return [{"job_id": "33333333-3333-3333-3333-333333333333"}]

    async def fake_fetchrow(query, *args):
        claimed_q["query"] = query
        claimed_q["args"] = args
        return {
            "job_id": "33333333-3333-3333-3333-333333333333",
            "status": "harvesting",
            "attempts": 1,
        }

    with (
        patch.object(metrics_db, "fetch", fake_fetch),
        patch.object(metrics_db, "fetchrow", fake_fetchrow),
    ):
        rows = await metrics_db.claim_due_jobs("2026-08-01T13:00:00+00:00", limit=10)
    assert "pending" in listed["query"]
    assert "due_at" in listed["query"]
    assert "status = 'harvesting'" in claimed_q["query"]
    assert "RETURNING" in claimed_q["query"].upper()
    assert len(rows) == 1
    assert rows[0]["status"] == "harvesting"


# ---------------------------------------------------------------------------
# X client — tweet metrics under user context
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_xclient_get_tweet_metrics_requests_non_public_and_organic():
    from excalibur_mcp.x_client import XClient, XCredentials

    client = XClient(XCredentials(bearer_token="tok"))
    body = {
        "data": {
            "id": TWEET_ID,
            "public_metrics": {
                "like_count": 3,
                "reply_count": 1,
                "retweet_count": 0,
                "quote_count": 0,
                "bookmark_count": 2,
                "impression_count": 100,
            },
            "non_public_metrics": {
                "impression_count": 120,
                "url_link_clicks": 5,
                "user_profile_clicks": 1,
            },
            "organic_metrics": {
                "impression_count": 120,
                "like_count": 3,
                "reply_count": 1,
                "retweet_count": 0,
                "url_link_clicks": 5,
                "user_profile_clicks": 1,
            },
        }
    }
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = body
    mock_resp.text = json.dumps(body)

    with patch("excalibur_mcp.x_client.httpx.AsyncClient") as MockClient:
        inst = AsyncMock()
        inst.get = AsyncMock(return_value=mock_resp)
        inst.__aenter__ = AsyncMock(return_value=inst)
        inst.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = inst
        out = await client.get_tweet_metrics(TWEET_ID)

    assert out["impressions"] == 120
    assert out["likes"] == 3
    assert out["url_link_clicks"] == 5
    assert out["user_profile_clicks"] == 1
    call_kwargs = inst.get.await_args
    params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params")
    fields = params.get("tweet.fields", "")
    assert "non_public_metrics" in fields
    assert "organic_metrics" in fields or "public_metrics" in fields


# ---------------------------------------------------------------------------
# Derived metrics (computed, not fetched)
# ---------------------------------------------------------------------------


def test_escape_velocity_compares_t15_to_rolling_median():
    from excalibur_mcp.metrics_harvest import escape_velocity

    # Patron's recent t+15m impressions medians: 100. This post got 250 → 2.5x
    score = escape_velocity(impressions_t15=250, rolling_median_t15=100)
    assert score == pytest.approx(2.5)
    assert escape_velocity(impressions_t15=50, rolling_median_t15=0) is None
    assert escape_velocity(impressions_t15=None, rolling_median_t15=100) is None


def test_breakout_ratio_is_impressions_over_followers():
    from excalibur_mcp.metrics_harvest import breakout_ratio

    assert breakout_ratio(impressions=5000, follower_count=1000) == pytest.approx(5.0)
    assert breakout_ratio(impressions=800, follower_count=1000) == pytest.approx(0.8)
    assert breakout_ratio(impressions=100, follower_count=0) is None


def test_link_placement_cohort_medians():
    from excalibur_mcp.metrics_harvest import link_placement_cohort

    rows = [
        {"link_placement": "body", "impressions": 100},
        {"link_placement": "body", "impressions": 200},
        {"link_placement": "first_reply", "impressions": 400},
        {"link_placement": "first_reply", "impressions": 600},
        {"link_placement": "none", "impressions": 50},
    ]
    cohort = link_placement_cohort(rows)
    assert cohort["body"] == 150  # median of 100,200
    assert cohort["first_reply"] == 500
    assert cohort["none"] == 50


def test_tweet_id_from_url():
    from excalibur_mcp.metrics_harvest import tweet_id_from_url

    assert tweet_id_from_url("https://x.com/i/status/1234567890") == "1234567890"
    assert tweet_id_from_url("https://twitter.com/foo/status/999") == "999"
    assert tweet_id_from_url(None) is None
    assert tweet_id_from_url("not-a-url") is None


# ---------------------------------------------------------------------------
# Domain schema registers the new table
# ---------------------------------------------------------------------------


def test_domain_tables_include_metrics_snapshot():
    from excalibur_mcp.db.neon import _DOMAIN_TABLES

    assert "post_metrics_snapshot" in _DOMAIN_TABLES
    assert "metrics_harvest_job" in _DOMAIN_TABLES


# ---------------------------------------------------------------------------
# Harvest one job end-to-end (mocked X + DB)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_harvest_one_job_writes_snapshot_and_marks_done():
    from excalibur_mcp import metrics_harvest

    job = {
        "job_id": "33333333-3333-3333-3333-333333333333",
        "post_id": PID,
        "tweet_id": TWEET_ID,
        "npub": NPUB,
        "cadence_key": "15m",
        "due_at": "2026-08-01T12:15:00+00:00",
        "link_placement": "body",
        "snippet_ids": [],
        "voice_id": NPUB,
        "attempts": 1,
        "sent_at": "2026-08-01T12:00:00+00:00",
    }
    x_metrics = {
        "impressions": 120,
        "likes": 3,
        "replies": 1,
        "reposts": 0,
        "quotes": 0,
        "bookmarks": 2,
        "url_link_clicks": 5,
        "user_profile_clicks": 1,
        "raw": {"data": {}},
    }
    client = SimpleNamespace(get_tweet_metrics=AsyncMock(return_value=x_metrics))
    insert = AsyncMock(return_value={"snapshot_id": "s1", "captured_at": "t"})
    mark_done = AsyncMock()

    with (
        patch.object(metrics_harvest.metrics_db, "insert_snapshot", insert),
        patch.object(metrics_harvest.metrics_db, "mark_job_done", mark_done),
    ):
        out = await metrics_harvest.harvest_one(client, job)

    assert out["outcome"] == "captured"
    insert.assert_awaited_once()
    mark_done.assert_awaited_once_with(job["job_id"])
    kwargs = insert.await_args.kwargs
    assert kwargs["impressions"] == 120
    assert kwargs["cadence_key"] == "15m"
    assert kwargs["t_offset"] == 15 * 60


# ---------------------------------------------------------------------------
# Canonical identity registry — #321 tools must be seeded (#323)
# ---------------------------------------------------------------------------


def test_metrics_tools_are_in_domain_tool_registry():
    """#321 handlers are paid_tool-wrapped; without ToolIdentity rows the
    tollbooth dispatch layer returns tool_not_registered before the body runs.

    Categories match neighboring tools: read for patron analytics, restricted
    for the operator-only harvest sweep (mirrors process_scheduled_posts).
    """
    from tollbooth.tool_identity import capability_uuid

    from excalibur_mcp.server import _DOMAIN_TOOLS, TOOL_REGISTRY

    expected = {
        "get_post_metrics": "read",
        "post_performance": "read",
        "post_performance_infographic": "read",
        "harvest_metrics": "restricted",
    }
    by_cap = {ti.capability: ti for ti in _DOMAIN_TOOLS}
    for capability, category in expected.items():
        uid = capability_uuid(capability)
        assert uid in TOOL_REGISTRY, (
            f"{capability} ({uid}) missing from TOOL_REGISTRY — "
            "paid dispatch will return tool_not_registered"
        )
        ti = by_cap[capability]
        assert ti.tool_id == uid
        assert ti.category == category, f"{capability}: category {ti.category!r} != {category!r}"
        # Stable UUIDv5 derivation (version nibble 5) — never a hand-rolled v4.
        assert uid[14] == "5", f"{capability} tool_id is not UUIDv5: {uid}"
