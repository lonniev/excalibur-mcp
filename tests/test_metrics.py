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


def test_breakout_ratio_is_impressions_over_rolling_median():
    """#359 — breakout is final reach vs the patron's own baseline, not followers.

    Follower-count denominators structurally cap small accounts below 1.0 and
    never meant 'out-of-network pickup'. Same shape as escape velocity, later
    horizon. Thin / missing baselines suppress rather than invent a ratio.
    """
    from excalibur_mcp.metrics_harvest import breakout_ratio

    # Observed-scale discrimination: top post ~119 vs median ~40 → ~3× (>1);
    # bottom post ~18 vs same median → ~0.45× (<1).
    assert breakout_ratio(impressions=119, rolling_median_impressions=40) == pytest.approx(2.975)
    assert breakout_ratio(impressions=18, rolling_median_impressions=40) == pytest.approx(0.45)
    assert breakout_ratio(impressions=100, rolling_median_impressions=0) is None
    assert breakout_ratio(impressions=None, rolling_median_impressions=40) is None
    assert breakout_ratio(impressions=100, rolling_median_impressions=None) is None


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
    # #364 — each bucket carries median + sample size so the FE can dim n<3.
    assert cohort["body"]["median"] == 150  # median of 100,200
    assert cohort["body"]["n"] == 2
    assert cohort["first_reply"]["median"] == 500
    assert cohort["first_reply"]["n"] == 2
    assert cohort["none"]["median"] == 50
    assert cohort["none"]["n"] == 1


def test_tier1_engagement_rates_are_pure_ratios():
    """#361 Tier 1 — profile/bookmark/reply rates and quote-to-repost from payload fields.

    These are already harvested (bookmarks, user_profile_clicks, replies, quotes,
    reposts, impressions) but were never turned into rates the Performance view
    can rank on. Pure helpers so a zero denominator stays None, not ZeroDivision.
    """
    from excalibur_mcp.metrics_harvest import (
        bookmark_rate,
        profile_click_rate,
        quote_to_repost_ratio,
        reply_rate,
    )

    assert profile_click_rate(user_profile_clicks=5, impressions=100) == pytest.approx(0.05)
    assert bookmark_rate(bookmarks=2, impressions=100) == pytest.approx(0.02)
    assert reply_rate(replies=4, impressions=200) == pytest.approx(0.02)
    assert quote_to_repost_ratio(quotes=3, reposts=6) == pytest.approx(0.5)

    # Zero / missing denominators must not invent a rate.
    assert profile_click_rate(user_profile_clicks=1, impressions=0) is None
    assert bookmark_rate(bookmarks=1, impressions=None) is None
    assert reply_rate(replies=None, impressions=100) is None
    assert quote_to_repost_ratio(quotes=2, reposts=0) is None
    assert quote_to_repost_ratio(quotes=None, reposts=4) is None


def test_time_of_day_cohort_medians_by_send_hour():
    """#361 Tier 3 — median impressions bucketed by hour-of-day the post went out."""
    from excalibur_mcp.metrics_harvest import time_of_day_cohort

    rows = [
        {"last_sent_at": "2026-08-01T05:10:00+00:00", "impressions": 40},
        {"last_sent_at": "2026-08-02T05:40:00+00:00", "impressions": 60},
        {"last_sent_at": "2026-08-01T14:00:00+00:00", "impressions": 200},
        {"last_sent_at": "2026-08-03T14:30:00+00:00", "impressions": 100},
        {"last_sent_at": "not-a-date", "impressions": 999},  # ignored
        {"last_sent_at": None, "impressions": 1},  # ignored
    ]
    cohort = time_of_day_cohort(rows)
    # Keys are zero-padded UTC hours so FE sort is lexical == chronological.
    # #364 — structured {median, n} so charts can encode sample size.
    assert cohort["05"]["median"] == 50  # median of 40, 60
    assert cohort["05"]["n"] == 2
    assert cohort["14"]["median"] == 150  # median of 200, 100
    assert cohort["14"]["n"] == 2
    assert "not-a-date" not in cohort


@pytest.mark.asyncio
async def test_compute_post_performance_surfaces_tier1_rates_and_tod_cohort():
    """#361 — performance payload carries Tier 1 rates + time-of-day cohort.

    Before: bookmarks/quotes omitted from posts_out; no rates; no hour cohort.
    After: latest counts + derived rates on each row; cohorts.time_of_day filled.
    """
    from excalibur_mcp import metrics_harvest
    from excalibur_mcp.db import posts as posts_db

    snaps = [
        {
            "post_id": PID,
            "tweet_id": TWEET_ID,
            "cadence_key": "15m",
            "t_offset": 900,
            "impressions": 100,
            "likes": 4,
            "replies": 2,
            "reposts": 4,
            "quotes": 1,
            "bookmarks": 5,
            "url_link_clicks": 3,
            "user_profile_clicks": 10,
            "link_placement": "body",
            "snippet_ids": [],
            "voice_id": NPUB,
            "captured_at": "2026-08-01T12:15:00+00:00",
        },
        {
            "post_id": PID,
            "tweet_id": TWEET_ID,
            "cadence_key": "1h",
            "t_offset": 3600,
            "impressions": 200,
            "likes": 10,
            "replies": 4,
            "reposts": 8,
            "quotes": 2,
            "bookmarks": 10,
            "url_link_clicks": 7,
            "user_profile_clicks": 20,
            "link_placement": "body",
            "snippet_ids": [],
            "voice_id": NPUB,
            "captured_at": "2026-08-01T13:00:00+00:00",
        },
    ]
    identity = {
        PID: {
            "title": "Morning dispatch",
            "excerpt": "The market opened soft…",
            "last_sent_at": "2026-08-01T14:05:00+00:00",
            "publish_at": "2026-08-01T14:05:00+00:00",
        }
    }

    with (
        patch.object(metrics_harvest.metrics_db, "list_all_for_npub", AsyncMock(return_value=snaps)),
        patch.object(posts_db, "summaries_for_ids", AsyncMock(return_value=identity)),
    ):
        out = await metrics_harvest.compute_post_performance(NPUB, follower_count=1000)

    assert len(out["posts"]) == 1
    row = out["posts"][0]
    # Latest counts that were already in the snapshot but not on the row.
    assert row["bookmarks"] == 10
    assert row["quotes"] == 2
    assert row["user_profile_clicks"] == 20
    # Rates use latest snapshot over latest impressions.
    assert row["profile_click_rate"] == pytest.approx(0.10)  # 20/200
    assert row["bookmark_rate"] == pytest.approx(0.05)  # 10/200
    assert row["reply_rate"] == pytest.approx(0.02)  # 4/200
    assert row["quote_to_repost_ratio"] == pytest.approx(0.25)  # 2/8
    # Tier 3: send-hour cohort from last_sent_at + latest impressions.
    assert out["cohorts"]["time_of_day"]["14"]["median"] == 200
    assert out["cohorts"]["time_of_day"]["14"]["n"] == 1


def test_performance_page_surfaces_tier1_metric_columns():
    """#361 static contract: Performance FE shows Tier 1 free metrics, not only clicks."""
    from pathlib import Path

    src = (
        Path(__file__).resolve().parents[1]
        / "frontend"
        / "src"
        / "components"
        / "PerformancePage.tsx"
    )
    text = src.read_text(encoding="utf-8")

    # Columns / labels the backlog asked to surface.
    assert "Profile" in text  # profile clicks column
    assert "Bookmark" in text
    assert "Reply rate" in text or "reply_rate" in text
    assert "Quote" in text  # quote-to-repost
    # Derived rates come from the API payload, not recomputed ad-hoc in JSX.
    assert "profile_click_rate" in text
    assert "bookmark_rate" in text
    assert "reply_rate" in text
    assert "quote_to_repost_ratio" in text
    # Time-of-day cohort panel (Tier 3, free).
    assert "time_of_day" in text or "Time of day" in text


@pytest.mark.asyncio
async def test_compute_post_performance_includes_title_and_posted_date():
    """#327 — performance rows carry human identity, not just the post UUID.

    Before the fix, compute_post_performance emitted post_id alone and the FE
    rendered ``post_id.slice(0, 8)…``. After, each row includes title/excerpt
    and last_sent_at so a human can recognise their own writing.
    """
    from excalibur_mcp import metrics_harvest
    from excalibur_mcp.db import posts as posts_db

    snaps = [
        {
            "post_id": PID,
            "tweet_id": TWEET_ID,
            "cadence_key": "15m",
            "t_offset": 900,
            "impressions": 200,
            "likes": 4,
            "replies": 1,
            "reposts": 0,
            "url_link_clicks": 3,
            "user_profile_clicks": 1,
            "link_placement": "body",
            "snippet_ids": [],
            "voice_id": NPUB,
            "captured_at": "2026-08-01T12:15:00+00:00",
        },
        {
            "post_id": PID,
            "tweet_id": TWEET_ID,
            "cadence_key": "1h",
            "t_offset": 3600,
            "impressions": 500,
            "likes": 10,
            "replies": 2,
            "reposts": 1,
            "url_link_clicks": 7,
            "user_profile_clicks": 2,
            "link_placement": "body",
            "snippet_ids": [],
            "voice_id": NPUB,
            "captured_at": "2026-08-01T13:00:00+00:00",
        },
    ]
    identity = {
        PID: {
            "title": "Morning dispatch",
            "excerpt": "The market opened soft and the bid walked away…",
            "last_sent_at": "2026-08-01T12:00:00+00:00",
            "publish_at": "2026-08-01T12:00:00+00:00",
        }
    }

    with (
        patch.object(metrics_harvest.metrics_db, "list_all_for_npub", AsyncMock(return_value=snaps)),
        patch.object(posts_db, "summaries_for_ids", AsyncMock(return_value=identity)) as summaries,
    ):
        out = await metrics_harvest.compute_post_performance(NPUB, follower_count=1000)

    summaries.assert_awaited_once()
    assert len(out["posts"]) == 1
    row = out["posts"][0]
    assert row["post_id"] == PID
    assert row["title"] == "Morning dispatch"
    assert "market opened soft" in row["excerpt"]
    assert row["last_sent_at"] == "2026-08-01T12:00:00+00:00"
    # Derived scores: single t+15 sample → median is itself → EV 1×.
    assert row["escape_velocity"] == pytest.approx(1.0)  # 200 / median(200)
    # #359 — breakout needs ≥ BREAKOUT_MIN_SAMPLE posts; a one-post corpus
    # suppresses rather than reporting a self-ratio of 1.0 or a follower fraction.
    assert row["breakout_ratio"] is None
    assert out["corpus"]["breakout_sample_size"] == 1
    assert out["corpus"]["rolling_median_final"] is None
    # follower_count remains a display-only corpus stat, not a breakout input.
    assert out["follower_count"] == 1000


def test_performance_page_source_is_human_legible():
    """#327 static contract: the FE source must not lead with jargon or hashes.

    The page is React; full browser render is human-in-the-loop. This locks the
    copy/structure decisions the Code Owner asked for so a regression that
    reintroduces ``post_id.slice`` or the opaque cohort heading fails CI.
    """
    from pathlib import Path

    src = Path(__file__).resolve().parents[1] / "frontend" / "src" / "components" / "PerformancePage.tsx"
    text = src.read_text(encoding="utf-8")

    # Post identity is title/excerpt, not a truncated UUID.
    assert "post_id.slice" not in text
    assert "postLabel" in text
    assert "last_sent_at" in text

    # Show-don't-tell: reader-focused subtitle, not a jargon laundry list.
    assert "How your recent posts are travelling" in text
    assert "escape velocity, breakout ratio,\n            link-placement cohorts" not in text

    # Item 11: rename the opaque heading; keep a precise tooltip. The question
    # form ("Where should the link go?") went with it — the page answers with a
    # median, so a heading that asks is a promise the panel does not keep.
    assert "Link placement and reach" in text
    assert "Where should the link go?" not in text
    assert "Link-placement cohort" not in text

    # The panel needs two cohorts to compare. One median compares to nothing,
    # and _detect_link_placement only ever emits `body` or `none`, so a corpus
    # of all-linked posts would otherwise render a lone row forever.
    assert "cohortEntries.length > 1" in text

    # Unified Tip treatment (not bare title= on EV/BR alone) + Material glyphs.
    assert "function Tip" in text
    assert "from \"lucide-react\"" in text
    assert "Users" in text  # followers crowd glyph
    assert "TIPS.escapeVelocity" in text
    assert "denominator of escape velocity" in text.lower() or "rolling median" in text.lower()

    # #359 — breakout tip must describe the personal-median baseline, not followers.
    assert "impressions ÷ follower" not in text.lower()
    assert "rolling median" in text.lower()
    assert "TIPS.breakoutRatio" in text
    # Missing breakout is a thin corpus, not a missing follower count.
    assert "follower count, which is unavailable" not in text

    # One concept, one icon: the lucide glyph says crowd, so the emoji may not
    # say it a second time.
    assert "👥" not in text

    # "Curve" named a shape without saying what was plotted; "Trend" carries the
    # page's Tip treatment like every other metric.
    assert ">Curve<" not in text
    assert "TIPS.trend" in text

    # EV/BR are spelled out in the columns they label, so the header legend that
    # existed to expand the abbreviations is gone.
    assert "Escape velocity" in text
    assert "Breakout ratio" in text
    assert ">EV<" not in text
    assert ">BR<" not in text

    # Refresh stays on the right of the header row.
    assert "ml-auto" in text
    assert "RefreshButton" in text


def test_performance_page_ux_chart_loader_sort_no_link_col():
    """#364 — ToD chart, quote loader, sortable date column, Link col removed.

    Browser render is human-in-the-loop; this locks the structure decisions so a
    regression that reverts to a ToD table, plain "Loading…", fixed-order rows,
    or a per-row Link column fails CI.
    """
    from pathlib import Path

    src = (
        Path(__file__).resolve().parents[1]
        / "frontend"
        / "src"
        / "components"
        / "PerformancePage.tsx"
    )
    text = src.read_text(encoding="utf-8")

    # 1. Time of day is a continuous 24h chart (local), not a sparse UTC table.
    assert "TimeOfDayChart" in text or "time-of-day-chart" in text
    assert "fmtHour" not in text  # old "14:00 UTC" table helper
    assert "local" in text.lower()
    # Sample count must be visible somehow (n= / sample / provisional).
    assert "provisional" in text.lower() or 'n=' in text.lower() or "sample" in text.lower()

    # 2. Site-standard quote-rotation loader, not bare "Loading…".
    assert "QuoteScroller" in text
    assert '"Loading…"' not in text and "'Loading…'" not in text

    # 3. Sortable Posts-by-reach columns + date as its own column.
    assert "sortKey" in text or "sortCol" in text
    assert "Posted" in text  # date column header
    # Date is a column, not only a subtitle under the title.
    assert "Posted {posted}" not in text

    # 4. Link placement leaves the row table; aggregate panel stays.
    # Per-row Link header gone; clicks retained; cohort panel retained.
    assert ">Link<" not in text and "\nLink\n" not in text
    assert "link_placement" in text  # still captured / aggregated
    assert "Link placement and reach" in text
    assert "Clicks" in text
    assert "url_link_clicks" in text


@pytest.mark.asyncio
async def test_compute_post_performance_breakout_uses_final_median_and_min_sample():
    """#359 — breakout discriminates above/below 1× once the baseline is thick enough.

    Five posts with distinct final impressions: median is the middle value, so
    the top post lands >1× and the bottom <1×. With only four posts the ratio is
    suppressed entirely.
    """
    from excalibur_mcp import metrics_harvest
    from excalibur_mcp.db import posts as posts_db
    from excalibur_mcp.metrics_harvest import BREAKOUT_MIN_SAMPLE

    assert BREAKOUT_MIN_SAMPLE == 5

    def _snap(post_id: str, cadence: str, t_offset: int, impressions: int) -> dict:
        return {
            "post_id": post_id,
            "tweet_id": f"t-{post_id[-4:]}",
            "cadence_key": cadence,
            "t_offset": t_offset,
            "impressions": impressions,
            "likes": 0,
            "replies": 0,
            "reposts": 0,
            "url_link_clicks": 0,
            "user_profile_clicks": 0,
            "link_placement": "none",
            "snippet_ids": [],
            "voice_id": NPUB,
            "captured_at": "2026-08-01T12:00:00+00:00",
        }

    # Five posts. Prefer cadence_key=28d when present; otherwise latest.
    # Final impressions: 20, 30, 40, 50, 120 → median 40.
    posts_final = {
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1": 20,
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa2": 30,
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa3": 40,
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa4": 50,
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa5": 120,
    }
    snaps = []
    for pid, final_imp in posts_final.items():
        snaps.append(_snap(pid, "15m", 900, max(1, final_imp // 3)))
        snaps.append(_snap(pid, "28d", 28 * 24 * 3600, final_imp))

    identity = {
        pid: {
            "title": f"Post {pid[-1]}",
            "excerpt": "",
            "last_sent_at": "2026-08-01T12:00:00+00:00",
            "publish_at": "2026-08-01T12:00:00+00:00",
        }
        for pid in posts_final
    }

    with (
        patch.object(metrics_harvest.metrics_db, "list_all_for_npub", AsyncMock(return_value=snaps)),
        patch.object(posts_db, "summaries_for_ids", AsyncMock(return_value=identity)),
    ):
        out = await metrics_harvest.compute_post_performance(NPUB)

    assert out["corpus"]["breakout_sample_size"] == 5
    assert out["corpus"]["rolling_median_final"] == pytest.approx(40.0)
    by_id = {p["post_id"]: p for p in out["posts"]}
    assert by_id["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa5"]["breakout_ratio"] == pytest.approx(3.0)
    assert by_id["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa1"]["breakout_ratio"] == pytest.approx(0.5)
    assert by_id["aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa3"]["breakout_ratio"] == pytest.approx(1.0)
    # Values both above and below 1.0 — the acceptance criterion from #359.
    ratios = [p["breakout_ratio"] for p in out["posts"]]
    assert any(r is not None and r > 1.0 for r in ratios)
    assert any(r is not None and r < 1.0 for r in ratios)

    # Thin corpus: drop one post → sample 4 < min 5 → every breakout is None.
    thin_snaps = [s for s in snaps if s["post_id"] != "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa5"]
    thin_identity = {k: v for k, v in identity.items() if k != "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaa5"}
    with (
        patch.object(metrics_harvest.metrics_db, "list_all_for_npub", AsyncMock(return_value=thin_snaps)),
        patch.object(posts_db, "summaries_for_ids", AsyncMock(return_value=thin_identity)),
    ):
        thin = await metrics_harvest.compute_post_performance(NPUB)
    assert thin["corpus"]["breakout_sample_size"] == 4
    assert thin["corpus"]["rolling_median_final"] is None
    assert all(p["breakout_ratio"] is None for p in thin["posts"])


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
