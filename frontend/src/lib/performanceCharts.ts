// Pure helpers behind the Performance page's charts and ratio tiles:
// last posts against your typical post, format mix, and the daily trend.

import { getZonedParts } from "@tollbooth-dpyc/web";
import { medianOf } from "./timezone.ts";
import type { CohortBucket, FollowerReading, PerformancePost } from "./mcp.ts";

// ── Last posts against your typical post ────────────────────────────────────

export type LastPostBar = {
  post: PerformancePost;
  views: number;
  /** Drawn height in views: the cap when the bar is clipped. */
  drawn: number;
  clipped: boolean;
};

export type LastPostsChart = {
  bars: LastPostBar[];
  /** Where the dashed "typical" line sits, in views. */
  typical: number | null;
  /** Top of the axis, in views. */
  top: number;
  /** The best post's views when its bar runs past the top. */
  clippedBest: number | null;
};

/** A bar taller than this many typical posts is cut so the rest stay readable. */
export const CLIP_AT_TYPICAL = 3;

/**
 * The newest `count` sent posts, oldest first, with each bar's height against
 * your typical post. `typical` is the corpus rolling median of final reach;
 * with no corpus median yet, the median of the bars shown stands in.
 */
export function lastPostsChart(
  posts: readonly PerformancePost[],
  typicalFromCorpus: number | null | undefined,
  count = 20,
): LastPostsChart {
  const sent = posts
    .filter((p) => p.last_sent_at && !Number.isNaN(Date.parse(p.last_sent_at)) && p.latest_impressions != null)
    .slice()
    .sort((a, b) => Date.parse(a.last_sent_at!) - Date.parse(b.last_sent_at!))
    .slice(-count);
  const views = sent.map((p) => Number(p.latest_impressions));
  const typical =
    typicalFromCorpus != null && !Number.isNaN(typicalFromCorpus)
      ? typicalFromCorpus
      : views.length
        ? medianOf(views)
        : null;
  const max = Math.max(0, ...views);
  const cap = typical != null && typical > 0 ? typical * CLIP_AT_TYPICAL : max;
  const top = Math.max(1, Math.min(max, cap), typical ?? 0);
  const bars = sent.map((post, i) => {
    const v = views[i]!;
    return { post, views: v, drawn: Math.min(v, top), clipped: v > top };
  });
  return { bars, typical, top, clippedBest: max > top ? max : null };
}

// ── Format mix ──────────────────────────────────────────────────────────────

export type FormatMixRow = {
  placement: string;
  /** Share of posts in this format, 0–1. */
  share: number;
  median: number;
  n: number;
};

/** Where the link sat, as a mix: how often you use each format and how it travels. */
export function formatMix(cohorts: Record<string, CohortBucket>): FormatMixRow[] {
  const total = Object.values(cohorts).reduce((s, b) => s + (b.n || 0), 0);
  return Object.entries(cohorts)
    .map(([placement, b]) => ({
      placement,
      share: total > 0 ? (b.n || 0) / total : 0,
      median: b.median,
      n: b.n,
    }))
    .sort((a, b) => b.share - a.share || b.median - a.median);
}

// ── Daily trend ─────────────────────────────────────────────────────────────

export type TrendPoint = { date: string; value: number };

function isoDay(d: Date): string {
  return d.toISOString().slice(0, 10);
}

/** The first day (YYYY-MM-DD, UTC) inside a `days`-long window ending `today`. */
export function windowStart(days: number, today: Date = new Date()): string {
  const d = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate()));
  d.setUTCDate(d.getUTCDate() - (days - 1));
  return isoDay(d);
}

/** Daily follower (or following) readings inside the window, oldest first. */
export function followerTrend(
  history: readonly FollowerReading[],
  field: "followers" | "following",
  days: number,
  today: Date = new Date(),
): TrendPoint[] {
  const from = windowStart(days, today);
  return history
    .filter((h) => h.date >= from && h[field] != null)
    .map((h) => ({ date: h.date, value: Number(h[field]) }))
    .sort((a, b) => a.date.localeCompare(b.date));
}

/** Median views of the posts sent each local day inside the window, oldest first. */
export function dailyMedianViews(
  posts: readonly PerformancePost[],
  timeZone: string,
  days: number,
  today: Date = new Date(),
): (TrendPoint & { n: number })[] {
  const from = windowStart(days, today);
  const byDay = new Map<string, number[]>();
  for (const p of posts) {
    if (!p.last_sent_at || p.latest_impressions == null) continue;
    const t = Date.parse(p.last_sent_at);
    if (Number.isNaN(t)) continue;
    const z = getZonedParts(new Date(t), timeZone);
    const day = `${z.year}-${String(z.month).padStart(2, "0")}-${String(z.day).padStart(2, "0")}`;
    if (day < from) continue;
    const list = byDay.get(day) ?? [];
    list.push(Number(p.latest_impressions));
    byDay.set(day, list);
  }
  return [...byDay.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([date, vals]) => ({ date, value: medianOf(vals), n: vals.length }));
}

/** Followers per account you follow, shown as "N:1". */
export function followRatio(followers: number | null | undefined, following: number | null | undefined): number | null {
  if (followers == null || following == null || following <= 0) return null;
  return followers / following;
}
