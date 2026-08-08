"""Post-metrics harvest — decaying cadence, derived scores, scheduler hook.

X only exposes ``non_public_metrics`` / ``organic_metrics`` for 30 days after a
post is authored. Whatever is not snapshotted inside that window is gone. This
module owns:

* the cadence table (t+15m … t+28d),
* scheduling jobs when a post is sent,
* draining due jobs on each scheduler tick,
* pure derived scores (escape velocity, breakout ratio, link-placement cohort).

The X API client and the DB layer stay thin; composition lives here.
"""

from __future__ import annotations

import logging
import re
import statistics
from datetime import datetime, timedelta, timezone
from typing import Any
from xml.sax.saxutils import escape

from excalibur_mcp.db import metrics as metrics_db

logger = logging.getLogger(__name__)

# Decaying cadence: (key, offset_seconds). Hard stop at day 28 for margin
# against X's 30-day metrics cliff — after day 30 the fields are gone forever.
HARVEST_CADENCE: tuple[tuple[str, int], ...] = (
    ("15m", 15 * 60),
    ("1h", 60 * 60),
    ("6h", 6 * 60 * 60),
    ("24h", 24 * 60 * 60),
    ("72h", 72 * 60 * 60),
    ("7d", 7 * 24 * 60 * 60),
    ("28d", 28 * 24 * 60 * 60),
)
MAX_HARVEST_AGE_DAYS = 28
MAX_HARVEST_ATTEMPTS = 5

_TWEET_ID_RE = re.compile(
    r"(?:x\.com|twitter\.com)/\S*?status(?:es)?/(\d+)", re.IGNORECASE
)

CADENCE_OFFSETS: dict[str, int] = {k: s for k, s in HARVEST_CADENCE}


def tweet_id_from_url(url: str | None) -> str | None:
    """Extract a numeric tweet id from an x.com / twitter.com status URL."""
    if not url:
        return None
    m = _TWEET_ID_RE.search(str(url))
    return m.group(1) if m else None


def jobs_for_send(
    *,
    post_id: str,
    tweet_id: str,
    npub: str,
    sent_at: datetime,
    link_placement: str | None = None,
    snippet_ids: list[str] | None = None,
    voice_id: str | None = None,
) -> list[dict[str, Any]]:
    """Build the seven decaying-cadence harvest jobs for a newly-sent post."""
    if sent_at.tzinfo is None:
        sent_at = sent_at.replace(tzinfo=timezone.utc)
    jobs: list[dict[str, Any]] = []
    for key, offset_s in HARVEST_CADENCE:
        jobs.append(
            {
                "post_id": post_id,
                "tweet_id": tweet_id,
                "npub": npub,
                "cadence_key": key,
                "due_at": sent_at + timedelta(seconds=offset_s),
                "sent_at": sent_at,
                "link_placement": link_placement,
                "snippet_ids": list(snippet_ids or []),
                "voice_id": voice_id,
            }
        )
    return jobs


def _parse_snippet_ids(doc: Any) -> list[str]:
    """Collect snippet ids referenced by a post doc (best-effort)."""
    if not isinstance(doc, dict):
        return []
    out: list[str] = []
    for b in doc.get("blocks") or []:
        if not isinstance(b, dict):
            continue
        sid = b.get("snippet_id") or b.get("snippetId")
        if sid and str(sid) not in out:
            out.append(str(sid))
    return out


def _detect_link_placement(text: str | None) -> str:
    """Heuristic: body has a URL → ``body``; otherwise ``none``.

    First-reply placement is a composition-time choice the FE can stamp later;
    at harvest schedule time we only see the body that went out.
    """
    if not text:
        return "none"
    if re.search(r"https?://\S+", text):
        return "body"
    return "none"


async def schedule_after_send(
    *,
    post_id: str,
    tweet_id: str | None,
    tweet_url: str | None,
    npub: str,
    sent_at: datetime | None = None,
    doc: Any = None,
    text: str | None = None,
    voice_id: str | None = None,
) -> int:
    """Schedule harvest jobs after a successful publication. Best-effort."""
    tid = tweet_id or tweet_id_from_url(tweet_url)
    if not tid:
        logger.warning("schedule_after_send: no tweet_id for post %s", post_id)
        return 0
    when = sent_at or datetime.now(timezone.utc)
    jobs = jobs_for_send(
        post_id=post_id,
        tweet_id=tid,
        npub=npub,
        sent_at=when,
        link_placement=_detect_link_placement(text),
        snippet_ids=_parse_snippet_ids(doc),
        voice_id=voice_id or npub,
    )
    try:
        n = await metrics_db.schedule_jobs(jobs)
        logger.info("metrics: scheduled %d harvest jobs for post %s tweet %s", n, post_id, tid)
        return n
    except Exception:  # noqa: BLE001 — never fail a publication over harvest setup
        logger.exception("metrics: failed to schedule harvest for %s", post_id)
        return 0


async def harvest_one(client: Any, job: dict[str, Any]) -> dict[str, Any]:
    """Fetch metrics for one claimed job and append a snapshot."""
    job_id = job["job_id"]
    tweet_id = job["tweet_id"]
    cadence = job.get("cadence_key") or ""
    t_offset = CADENCE_OFFSETS.get(cadence, 0)
    try:
        metrics = await client.get_tweet_metrics(tweet_id)
    except Exception as exc:  # noqa: BLE001
        attempts = int(job.get("attempts") or 1)
        dead = attempts >= MAX_HARVEST_ATTEMPTS
        await metrics_db.mark_job_failed(job_id, str(exc) or type(exc).__name__, dead=dead)
        return {
            "job_id": job_id,
            "outcome": "dead" if dead else "retry",
            "reason": str(exc) or type(exc).__name__,
        }

    await metrics_db.insert_snapshot(
        post_id=job["post_id"],
        tweet_id=tweet_id,
        npub=job["npub"],
        t_offset=t_offset,
        impressions=metrics.get("impressions"),
        likes=metrics.get("likes"),
        replies=metrics.get("replies"),
        reposts=metrics.get("reposts"),
        quotes=metrics.get("quotes"),
        bookmarks=metrics.get("bookmarks"),
        url_link_clicks=metrics.get("url_link_clicks"),
        user_profile_clicks=metrics.get("user_profile_clicks"),
        link_placement=job.get("link_placement"),
        snippet_ids=job.get("snippet_ids") or [],
        voice_id=job.get("voice_id"),
        cadence_key=cadence,
        raw=metrics.get("raw"),
    )
    await metrics_db.mark_job_done(job_id)
    return {
        "job_id": job_id,
        "post_id": job["post_id"],
        "tweet_id": tweet_id,
        "cadence_key": cadence,
        "outcome": "captured",
        "impressions": metrics.get("impressions"),
    }


async def process_due_harvests(runtime: Any) -> dict[str, Any]:
    """One harvest sweep: claim due jobs, fetch metrics per owner, append snapshots.

    Hooked from the scheduler tick. Groups jobs by npub so each patron's OAuth
    session is restored once per sweep.
    """
    now = datetime.now(timezone.utc)
    try:
        jobs = await metrics_db.claim_due_jobs(now.isoformat())
    except Exception:  # noqa: BLE001
        logger.exception("metrics: claim_due_jobs failed")
        return {"kind": "harvest", "captured": [], "failed": [], "processed": 0}

    if not jobs:
        return {"kind": "harvest", "captured": [], "failed": [], "processed": 0}

    by_owner: dict[str, list[dict[str, Any]]] = {}
    for j in jobs:
        by_owner.setdefault(str(j.get("npub") or ""), []).append(j)

    captured: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []

    # Lazy import — same reason the post phase imports publish_one only when needed.
    from excalibur_mcp.server import _resolve_x_client

    for owner, owner_jobs in by_owner.items():
        if not owner:
            for j in owner_jobs:
                await metrics_db.mark_job_failed(j["job_id"], "missing_npub", dead=True)
                failed.append({"job_id": j["job_id"], "outcome": "dead", "reason": "missing_npub"})
            continue
        client, situation = await _resolve_x_client(owner)
        if client is None:
            reason = (
                (situation or {}).get("error_code")
                or (situation or {}).get("error")
                or "oauth_unavailable"
            )
            for j in owner_jobs:
                attempts = int(j.get("attempts") or 1)
                dead = attempts >= MAX_HARVEST_ATTEMPTS
                await metrics_db.mark_job_failed(j["job_id"], str(reason), dead=dead)
                failed.append({
                    "job_id": j["job_id"],
                    "owner": owner,
                    "outcome": "dead" if dead else "retry",
                    "reason": str(reason),
                })
            continue
        for j in owner_jobs:
            try:
                out = await harvest_one(client, j)
            except Exception as exc:  # noqa: BLE001
                logger.exception("metrics: harvest_one failed for %s", j.get("job_id"))
                attempts = int(j.get("attempts") or 1)
                dead = attempts >= MAX_HARVEST_ATTEMPTS
                await metrics_db.mark_job_failed(
                    j["job_id"], str(exc) or type(exc).__name__, dead=dead
                )
                out = {
                    "job_id": j["job_id"],
                    "outcome": "dead" if dead else "retry",
                    "reason": str(exc) or type(exc).__name__,
                }
            if out.get("outcome") == "captured":
                captured.append(out)
            else:
                failed.append(out)

    summary = {
        "kind": "harvest",
        "captured": captured,
        "failed": failed,
        "processed": len(captured) + len(failed),
    }
    logger.info(
        "metrics harvest: captured=%d failed=%d", len(captured), len(failed)
    )
    return summary


# -- Derived metrics (computed on the patron's own corpus) -------------------


def escape_velocity(
    impressions_t15: int | float | None,
    rolling_median_t15: int | float | None,
) -> float | None:
    """t+15m impressions ÷ patron rolling median. Actionable while the window is open."""
    if impressions_t15 is None or rolling_median_t15 is None:
        return None
    med = float(rolling_median_t15)
    if med <= 0:
        return None
    return float(impressions_t15) / med


def breakout_ratio(
    impressions: int | float | None, follower_count: int | float | None
) -> float | None:
    """Impressions ÷ followers. >>1 implies For You pickup; ~1 stayed on home timeline."""
    if impressions is None or follower_count is None:
        return None
    followers = float(follower_count)
    if followers <= 0:
        return None
    return float(impressions) / followers


def link_placement_cohort(rows: list[dict[str, Any]]) -> dict[str, float]:
    """Median impressions by ``link_placement`` over the patron's corpus."""
    buckets: dict[str, list[float]] = {}
    for r in rows:
        place = str(r.get("link_placement") or "none")
        imp = r.get("impressions")
        if imp is None:
            continue
        try:
            buckets.setdefault(place, []).append(float(imp))
        except (TypeError, ValueError):
            continue
    return {
        k: float(statistics.median(v)) for k, v in buckets.items() if v
    }


def _as_nonneg_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    if n < 0:
        return None
    return n


def _rate(numerator: Any, denominator: Any) -> float | None:
    """num ÷ den when both are present and den > 0; else None (never invent 0)."""
    num = _as_nonneg_float(numerator)
    den = _as_nonneg_float(denominator)
    if num is None or den is None or den <= 0:
        return None
    return num / den


def profile_click_rate(
    user_profile_clicks: int | float | None, impressions: int | float | None
) -> float | None:
    """Profile clicks ÷ impressions — strongest free intent proxy on X."""
    return _rate(user_profile_clicks, impressions)


def bookmark_rate(
    bookmarks: int | float | None, impressions: int | float | None
) -> float | None:
    """Bookmarks ÷ impressions — save-for-later intent / evergreen separator."""
    return _rate(bookmarks, impressions)


def reply_rate(
    replies: int | float | None, impressions: int | float | None
) -> float | None:
    """Replies ÷ impressions — isolated from the blended engagement mix."""
    return _rate(replies, impressions)


def quote_to_repost_ratio(
    quotes: int | float | None, reposts: int | float | None
) -> float | None:
    """Quotes ÷ reposts — commentary/out-of-network vs mere agreement."""
    return _rate(quotes, reposts)


def time_of_day_cohort(rows: list[dict[str, Any]]) -> dict[str, float]:
    """Median impressions by UTC send hour (``HH`` keys) over the corpus.

    Each row needs ``last_sent_at`` (ISO) and ``impressions``. Bad timestamps
    and missing impressions are skipped — underpowered cohorts still accumulate.
    """
    buckets: dict[str, list[float]] = {}
    for r in rows:
        sent = r.get("last_sent_at")
        imp = r.get("impressions")
        if not sent or imp is None:
            continue
        try:
            val = float(imp)
        except (TypeError, ValueError):
            continue
        try:
            raw = str(sent).replace("Z", "+00:00")
            dt = datetime.fromisoformat(raw)
        except (TypeError, ValueError):
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        hour = dt.astimezone(timezone.utc).strftime("%H")
        buckets.setdefault(hour, []).append(val)
    return {k: float(statistics.median(v)) for k, v in buckets.items() if v}


def _median(values: list[int | float]) -> float | None:
    if not values:
        return None
    return float(statistics.median(values))


async def compute_post_performance(npub: str, *, follower_count: int | None = None) -> dict[str, Any]:
    """Derived scores across a patron's harvested corpus."""
    snaps = await metrics_db.list_all_for_npub(npub)
    if not snaps:
        return {
            "npub": npub,
            "posts": [],
            "cohorts": {"link_placement": {}, "time_of_day": {}},
            "corpus": {"snapshot_count": 0, "post_count": 0},
        }

    by_post: dict[str, list[dict[str, Any]]] = {}
    for s in snaps:
        by_post.setdefault(str(s["post_id"]), []).append(s)

    # Human identity (title / opening words / posted date) lives on posts, not
    # on the metric snapshots. One batch lookup so the FE never has to show a
    # bare hash as the row's visible name.
    from excalibur_mcp.db import posts as posts_db

    identity = await posts_db.summaries_for_ids(npub, list(by_post.keys()))

    t15_all = [
        int(s["impressions"])
        for s in snaps
        if s.get("cadence_key") == "15m" and s.get("impressions") is not None
    ]
    rolling_med = _median(t15_all)

    # Latest snapshot per post for breakout / sparkline tip.
    posts_out: list[dict[str, Any]] = []
    for post_id, series in by_post.items():
        series_sorted = sorted(series, key=lambda r: (r.get("t_offset") or 0, str(r.get("captured_at") or "")))
        latest = series_sorted[-1]
        t15 = next((s for s in series_sorted if s.get("cadence_key") == "15m"), None)
        imp_t15 = int(t15["impressions"]) if t15 and t15.get("impressions") is not None else None
        latest_imp = int(latest["impressions"]) if latest.get("impressions") is not None else None
        sparkline = [
            {
                "t_offset": s.get("t_offset"),
                "cadence_key": s.get("cadence_key"),
                "impressions": s.get("impressions"),
                "likes": s.get("likes"),
                "captured_at": str(s.get("captured_at") or ""),
            }
            for s in series_sorted
        ]
        ident = identity.get(post_id) or {}
        latest_replies = latest.get("replies")
        latest_reposts = latest.get("reposts")
        latest_quotes = latest.get("quotes")
        latest_bookmarks = latest.get("bookmarks")
        latest_profile_clicks = latest.get("user_profile_clicks")
        posts_out.append(
            {
                "post_id": post_id,
                "tweet_id": latest.get("tweet_id"),
                "title": ident.get("title") or "",
                "excerpt": ident.get("excerpt") or "",
                "last_sent_at": ident.get("last_sent_at"),
                "link_placement": latest.get("link_placement"),
                "voice_id": latest.get("voice_id"),
                "snippet_ids": latest.get("snippet_ids") or [],
                "latest_impressions": latest_imp,
                "latest_likes": latest.get("likes"),
                "latest_replies": latest_replies,
                "latest_reposts": latest_reposts,
                "quotes": latest_quotes,
                "bookmarks": latest_bookmarks,
                "url_link_clicks": latest.get("url_link_clicks"),
                "user_profile_clicks": latest_profile_clicks,
                "profile_click_rate": profile_click_rate(latest_profile_clicks, latest_imp),
                "bookmark_rate": bookmark_rate(latest_bookmarks, latest_imp),
                "reply_rate": reply_rate(latest_replies, latest_imp),
                "quote_to_repost_ratio": quote_to_repost_ratio(latest_quotes, latest_reposts),
                "escape_velocity": escape_velocity(imp_t15, rolling_med),
                "breakout_ratio": breakout_ratio(latest_imp, follower_count),
                "sparkline": sparkline,
            }
        )

    # Sort by latest impressions desc so the FE gets a natural ranking.
    posts_out.sort(key=lambda p: (p.get("latest_impressions") or 0), reverse=True)

    # Cohort on the *latest* snapshot per post (one row per post, not every tick).
    latest_rows = []
    for series in by_post.values():
        series_sorted = sorted(series, key=lambda r: (r.get("t_offset") or 0))
        latest_rows.append(series_sorted[-1])

    # Snippet / voice attribution: median latest impressions by voice_id and by snippet.
    voice_buckets: dict[str, list[float]] = {}
    snippet_buckets: dict[str, list[float]] = {}
    for r in latest_rows:
        imp = r.get("impressions")
        if imp is None:
            continue
        try:
            val = float(imp)
        except (TypeError, ValueError):
            continue
        vid = str(r.get("voice_id") or "") or "_default"
        voice_buckets.setdefault(vid, []).append(val)
        sids = r.get("snippet_ids") or []
        if isinstance(sids, str):
            try:
                sids = json_loads(sids)
            except Exception:  # noqa: BLE001
                sids = []
        if isinstance(sids, list):
            for sid in sids:
                snippet_buckets.setdefault(str(sid), []).append(val)

    # Time-of-day cohort needs send time from posts + latest impressions.
    tod_rows = []
    for p in posts_out:
        tod_rows.append(
            {
                "last_sent_at": p.get("last_sent_at"),
                "impressions": p.get("latest_impressions"),
            }
        )

    return {
        "npub": npub,
        "follower_count": follower_count,
        "posts": posts_out,
        "cohorts": {
            "link_placement": link_placement_cohort(latest_rows),
            "voice": {k: float(statistics.median(v)) for k, v in voice_buckets.items() if v},
            "snippet": {k: float(statistics.median(v)) for k, v in snippet_buckets.items() if v},
            "time_of_day": time_of_day_cohort(tod_rows),
        },
        "corpus": {
            "snapshot_count": len(snaps),
            "post_count": len(by_post),
            "rolling_median_t15": rolling_med,
        },
    }


def json_loads(raw: str) -> Any:
    import json

    return json.loads(raw)


def render_performance_infographic(data: dict[str, Any]) -> str:
    """Dark gold-steel SVG summarizing post performance (mirrors account statement style)."""
    from tollbooth.infographic import (
        CARD_W,
        CARD_X,
        THEME_GOLD_STEEL,
        WIDTH,
        _card,
        _text,
    )

    theme = THEME_GOLD_STEEL
    theme = theme.with_name("eXcalibur")
    corpus = data.get("corpus") or {}
    posts = data.get("posts") or []
    cohorts = (data.get("cohorts") or {}).get("link_placement") or {}
    generated_at = datetime.now(timezone.utc).isoformat()

    parts: list[str] = []
    cy = 16

    # Header
    header_h = 80
    parts.append(_card(cy, header_h, theme))
    parts.append(
        _text(
            CARD_X + 48, cy + 38, "eXcalibur",
            size=22, weight="bold", family="sans-serif", fill=theme.text_white,
        )
    )
    parts.append(
        _text(
            CARD_X + 48, cy + 60, "Post Performance",
            size=14, fill=theme.accent_primary, family="sans-serif",
        )
    )
    parts.append(
        _text(
            CARD_X + 20, cy + 46, "⚔",
            size=28, fill=theme.accent_primary, family="sans-serif",
        )
    )
    ts_short = generated_at[:19].replace("T", " ") + " UTC"
    parts.append(
        _text(WIDTH - CARD_X - 16, cy + 64, ts_short, size=9, fill=theme.text_dim, anchor="end")
    )
    cy += header_h + 12

    # Hero metrics
    hero_h = 100
    parts.append(_card(cy, hero_h, theme))
    post_count = int(corpus.get("post_count") or len(posts))
    snap_count = int(corpus.get("snapshot_count") or 0)
    med = corpus.get("rolling_median_t15")
    parts.append(
        _text(
            WIDTH // 2, cy + 30, "C O R P U S",
            size=10, fill=theme.text_gray, weight="bold", anchor="middle", family="sans-serif",
        )
    )
    parts.append(
        _text(
            WIDTH // 2, cy + 72, f"{post_count}",
            size=48, fill=theme.accent_positive, weight="bold", anchor="middle",
        )
    )
    parts.append(
        _text(
            WIDTH // 2 + 60, cy + 72, "posts",
            size=13, fill=theme.text_gray, anchor="start", family="sans-serif",
        )
    )
    cy += hero_h + 12

    # Three metric cards
    metric_w = (CARD_W - 24) // 3
    metric_h = 80
    metrics_row = [
        ("📷", snap_count, "SNAPSHOTS", theme.accent_secondary),
        ("⚡", f"{med:.1f}" if isinstance(med, (int, float)) else "—", "MEDIAN t+15m", theme.accent_primary),
        ("🔗", len(cohorts), "LINK COHORTS", theme.accent_positive),
    ]
    for i, (icon, value, label, colour) in enumerate(metrics_row):
        mx = CARD_X + 8 + i * (metric_w + 8)
        parts.append(
            f'<rect x="{mx}" y="{cy}" width="{metric_w}" height="{metric_h}" '
            f'rx="8" fill="{theme.bg_card_alt}" stroke="{theme.border}" stroke-width="0.8"/>'
        )
        parts.append(_text(mx + metric_w // 2, cy + 24, icon, size=16, fill=colour, anchor="middle", family="sans-serif"))
        parts.append(_text(mx + metric_w // 2, cy + 50, str(value), size=20, fill=colour, weight="bold", anchor="middle"))
        parts.append(_text(mx + metric_w // 2, cy + 68, label, size=8, fill=theme.text_gray, weight="bold", anchor="middle", family="sans-serif"))
    cy += metric_h + 12

    # Top posts by impressions
    top = posts[:8]
    row_h = 28
    table_h = 40 + max(1, len(top)) * row_h
    parts.append(_card(cy, table_h, theme))
    parts.append(
        _text(CARD_X + 16, cy + 24, "TOP POSTS BY IMPRESSIONS", size=11, fill=theme.text_gray, weight="bold", family="sans-serif")
    )
    if not top:
        parts.append(
            _text(CARD_X + 16, cy + 52, "No harvested metrics yet.", size=12, fill=theme.text_dim, family="sans-serif")
        )
    else:
        y = cy + 48
        for p in top:
            label = (p.get("title") or p.get("excerpt") or str(p.get("post_id") or ""))[:40]
            if len(str(p.get("title") or p.get("excerpt") or str(p.get("post_id") or ""))) > 40:
                label = label.rstrip() + "…"
            # SVG text must not carry raw <>&
            label = escape(label)
            imp = p.get("latest_impressions")
            ev = p.get("escape_velocity")
            br = p.get("breakout_ratio")
            bits = [label, f"imp={imp if imp is not None else '—'}"]
            if isinstance(ev, (int, float)):
                bits.append(f"ev={ev:.2f}×")
            if isinstance(br, (int, float)):
                bits.append(f"br={br:.2f}×")
            place = p.get("link_placement")
            if place:
                bits.append(str(place))
            parts.append(
                _text(
                    CARD_X + 16, y, "  ".join(bits),
                    size=11, fill=theme.text_white, family="sans-serif",
                )
            )
            y += row_h
    cy += table_h + 12

    # Where should the link go? (link-placement cohort)
    if cohorts:
        ch = 40 + len(cohorts) * 28
        parts.append(_card(cy, ch, theme))
        parts.append(
            _text(
                CARD_X + 16, cy + 24, "WHERE SHOULD THE LINK GO? (median impressions)",
                size=11, fill=theme.text_gray, weight="bold", family="sans-serif",
            )
        )
        y = cy + 48
        for place, med_imp in sorted(cohorts.items(), key=lambda kv: -kv[1]):
            parts.append(
                _text(
                    CARD_X + 16, y,
                    f"{place}: {med_imp:.0f}",
                    size=12, fill=theme.text_white, family="monospace",
                )
            )
            y += 28
        cy += ch + 12

    # Footer
    parts.append(
        _text(
            WIDTH // 2, cy + 10, escape(theme.footer_brand),
            size=10, fill=theme.text_dim, anchor="middle", family="sans-serif",
        )
    )
    total_h = cy + 30
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{total_h}" '
        f'viewBox="0 0 {WIDTH} {total_h}">'
        f'<rect width="{WIDTH}" height="{total_h}" fill="{theme.bg_dark}"/>'
        + "".join(parts)
        + "</svg>"
    )
