"""Follower trend + reach ratios on the Performance payload.

X reports only today's follower count, so eXcalibur writes one reading a day
and derives growth from that history. Views-per-follower and the pooled
engagement rate ride on the corpus block.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

NPUB = "npub1l94pd4qu4eszrl6ek032ftcnsu3tt9a7xvq2zp7eaxeklp6mrpzssmq8pf"
PID_A = "11111111-1111-1111-1111-111111111111"
PID_B = "22222222-2222-2222-2222-222222222222"


def _h(date: str, followers: int) -> dict:
    return {"date": date, "followers": followers, "following": 148}


# ---------------------------------------------------------------------------
# follower_growth
# ---------------------------------------------------------------------------


def test_growth_needs_two_readings():
    from excalibur_mcp.metrics_harvest import follower_growth

    assert follower_growth([]) is None
    assert follower_growth([_h("2026-11-27", 373)]) is None


def test_growth_reports_the_real_span_it_covers():
    from excalibur_mcp.metrics_harvest import follower_growth

    g = follower_growth([_h("2026-11-20", 360), _h("2026-11-24", 365), _h("2026-11-27", 373)])
    assert g == {
        "from_date": "2026-11-20",
        "to_date": "2026-11-27",
        "days": 7,
        "delta": 13,
        "percent": pytest.approx(13 / 360),
    }


def test_growth_reports_a_loss_signed():
    from excalibur_mcp.metrics_harvest import follower_growth

    g = follower_growth([_h("2026-11-25", 400), _h("2026-11-27", 390)])
    assert g["delta"] == -10
    assert g["percent"] == pytest.approx(-0.025)


def test_growth_starts_at_the_oldest_reading_inside_the_window():
    from excalibur_mcp.metrics_harvest import follower_growth

    hist = [_h("2026-08-01", 100), _h("2026-11-01", 300), _h("2026-11-27", 330)]
    g = follower_growth(hist, window_days=30)
    assert g["from_date"] == "2026-11-01"
    assert g["delta"] == 30


# ---------------------------------------------------------------------------
# Ratios
# ---------------------------------------------------------------------------


def test_engagement_rate_is_pooled_over_posts():
    """Two silent posts and one that landed: pooled rate is not a zero median."""
    from excalibur_mcp.metrics_harvest import engagement_rate

    rows = [
        {"impressions": 100, "likes": 0, "replies": 0, "reposts": 0, "quotes": 0},
        {"impressions": 100, "likes": 0, "replies": 0, "reposts": 0, "quotes": 0},
        {"impressions": 200, "likes": 2, "replies": 1, "reposts": 0, "quotes": 1},
        {"impressions": None, "likes": 9},
    ]
    assert engagement_rate(rows) == pytest.approx(4 / 400)


def test_engagement_rate_without_views_is_unknown():
    from excalibur_mcp.metrics_harvest import engagement_rate

    assert engagement_rate([]) is None
    assert engagement_rate([{"impressions": 0, "likes": 0}]) is None


def test_views_per_follower():
    from excalibur_mcp.metrics_harvest import views_per_follower

    assert views_per_follower(47, 373) == pytest.approx(47 / 373)
    assert views_per_follower(None, 373) is None
    assert views_per_follower(47, None) is None


# ---------------------------------------------------------------------------
# compute_post_performance payload
# ---------------------------------------------------------------------------


def _snap(pid: str, imp: int, likes: int = 0) -> dict:
    return {
        "post_id": pid,
        "tweet_id": "1",
        "cadence_key": "24h",
        "t_offset": 86400,
        "impressions": imp,
        "likes": likes,
        "replies": 0,
        "reposts": 0,
        "quotes": 0,
        "bookmarks": 0,
        "url_link_clicks": 0,
        "user_profile_clicks": 0,
        "link_placement": "body",
        "snippet_ids": [],
        "voice_id": NPUB,
        "captured_at": "2026-11-27T12:00:00+00:00",
    }


async def test_performance_carries_follower_trend_and_ratios():
    from excalibur_mcp import metrics_harvest
    from excalibur_mcp.db import posts as posts_db

    history = [_h("2026-11-20", 360), _h("2026-11-27", 373)]
    snaps = [_snap(PID_A, 100, likes=1), _snap(PID_B, 300, likes=3)]
    with (
        patch.object(metrics_harvest.followers_db, "list_history", AsyncMock(return_value=history)),
        patch.object(metrics_harvest.metrics_db, "list_all_for_npub", AsyncMock(return_value=snaps)),
        patch.object(posts_db, "summaries_for_ids", AsyncMock(return_value={})),
        patch.object(metrics_harvest, "BREAKOUT_MIN_SAMPLE", 2),
    ):
        out = await metrics_harvest.compute_post_performance(
            NPUB, follower_count=373, following_count=148
        )

    assert out["follower_count"] == 373
    assert out["following_count"] == 148
    assert out["follower_history"] == history
    assert out["follower_growth_30d"]["delta"] == 13
    corpus = out["corpus"]
    assert corpus["rolling_median_final"] == 200
    assert corpus["views_per_follower"] == pytest.approx(200 / 373)
    assert corpus["engagement_rate"] == pytest.approx(4 / 400)


async def test_performance_without_posts_still_shows_followers():
    from excalibur_mcp import metrics_harvest

    history = [_h("2026-11-26", 370), _h("2026-11-27", 373)]
    with (
        patch.object(metrics_harvest.followers_db, "list_history", AsyncMock(return_value=history)),
        patch.object(metrics_harvest.metrics_db, "list_all_for_npub", AsyncMock(return_value=[])),
    ):
        out = await metrics_harvest.compute_post_performance(NPUB, follower_count=373)

    assert out["posts"] == []
    assert out["follower_history"] == history
    assert out["follower_growth_30d"]["delta"] == 3


async def test_performance_survives_a_history_read_failure():
    from excalibur_mcp import metrics_harvest

    with (
        patch.object(
            metrics_harvest.followers_db, "list_history", AsyncMock(side_effect=RuntimeError("db"))
        ),
        patch.object(metrics_harvest.metrics_db, "list_all_for_npub", AsyncMock(return_value=[])),
    ):
        out = await metrics_harvest.compute_post_performance(NPUB, follower_count=373)

    assert out["follower_history"] == []
    assert out["follower_growth_30d"] is None


# ---------------------------------------------------------------------------
# Daily capture
# ---------------------------------------------------------------------------


async def test_daily_capture_skips_the_x_call_once_today_is_recorded():
    from excalibur_mcp import metrics_harvest

    client = MagicMock()
    client.get_me_with_metrics = AsyncMock()
    record = AsyncMock()
    with (
        patch.object(metrics_harvest.followers_db, "has_reading_today", AsyncMock(return_value=True)),
        patch.object(metrics_harvest.followers_db, "record_daily", record),
    ):
        await metrics_harvest.capture_daily_followers(NPUB, client)

    client.get_me_with_metrics.assert_not_awaited()
    record.assert_not_awaited()


async def test_daily_capture_records_followers_and_following():
    from excalibur_mcp import metrics_harvest

    client = MagicMock()
    client.get_me_with_metrics = AsyncMock(
        return_value={"followers_count": 373, "following_count": 148}
    )
    record = AsyncMock()
    with (
        patch.object(metrics_harvest.followers_db, "has_reading_today", AsyncMock(return_value=False)),
        patch.object(metrics_harvest.followers_db, "record_daily", record),
    ):
        await metrics_harvest.capture_daily_followers(NPUB, client)

    record.assert_awaited_once_with(NPUB, followers=373, following=148)


async def test_daily_capture_never_fails_the_sweep():
    from excalibur_mcp import metrics_harvest

    client = MagicMock()
    client.get_me_with_metrics = AsyncMock(side_effect=RuntimeError("x down"))
    with patch.object(
        metrics_harvest.followers_db, "has_reading_today", AsyncMock(return_value=False)
    ):
        await metrics_harvest.capture_daily_followers(NPUB, client)  # no raise


async def test_harvest_sweep_captures_followers_per_owner():
    from excalibur_mcp import metrics_harvest

    job = {"job_id": "j1", "npub": NPUB, "attempts": 1}
    client = MagicMock()
    capture = AsyncMock()
    with (
        patch.object(metrics_harvest.metrics_db, "claim_due_jobs", AsyncMock(return_value=[job])),
        patch("excalibur_mcp.server._resolve_x_client", AsyncMock(return_value=(client, None))),
        patch.object(metrics_harvest, "harvest_one", AsyncMock(return_value={"outcome": "captured"})),
        patch.object(metrics_harvest, "capture_daily_followers", capture),
    ):
        await metrics_harvest.process_due_harvests(MagicMock())

    capture.assert_awaited_once_with(NPUB, client)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


async def test_schema_creates_one_follower_row_per_day():
    from excalibur_mcp.db import neon

    assert "follower_snapshot" in neon._DOMAIN_TABLES
    vault = MagicMock()
    vault._t = lambda name: f"s.{name}"
    vault._execute = AsyncMock(return_value={"rows": []})
    await neon._ensure_domain_schema(vault)
    ddl = " ".join(c.args[0] for c in vault._execute.await_args_list)
    assert "CREATE TABLE IF NOT EXISTS s.follower_snapshot" in ddl
    assert "PRIMARY KEY (npub, captured_on)" in ddl
