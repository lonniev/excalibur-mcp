// Pure-logic tests for the Performance charts and ratio tiles.
// Run with: node --experimental-strip-types --test frontend/src/lib/performanceCharts.test.ts

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  CLIP_AT_TYPICAL,
  dailyMedianViews,
  followerTrend,
  followRatio,
  formatMix,
  lastPostsChart,
  windowStart,
} from "./performanceCharts.ts";
import type { PerformancePost } from "./mcp.ts";

function post(id: string, sent: string | null, views: number | null): PerformancePost {
  return { post_id: id, last_sent_at: sent, latest_impressions: views };
}

describe("lastPostsChart", () => {
  it("keeps the newest posts, oldest first", () => {
    const posts = [
      post("c", "2026-11-27T15:00:00Z", 30),
      post("a", "2026-11-27T13:00:00Z", 10),
      post("b", "2026-11-27T14:00:00Z", 20),
      post("unsent", null, 99),
    ];
    const chart = lastPostsChart(posts, 20, 2);
    assert.deepEqual(chart.bars.map((b) => b.post.post_id), ["b", "c"]);
  });

  it("draws the typical line at the corpus median", () => {
    const chart = lastPostsChart([post("a", "2026-11-27T13:00:00Z", 10)], 47);
    assert.equal(chart.typical, 47);
    assert.ok(chart.top >= 47, "the typical line stays on the axis");
  });

  it("falls back to the median of the bars without a corpus median", () => {
    const posts = [10, 20, 60].map((v, i) => post(String(i), `2026-11-27T1${i}:00:00Z`, v));
    assert.equal(lastPostsChart(posts, null).typical, 20);
  });

  it("cuts a breakout bar and names the best post", () => {
    const posts = [40, 50, 500].map((v, i) => post(String(i), `2026-11-27T1${i}:00:00Z`, v));
    const chart = lastPostsChart(posts, 50);
    assert.equal(chart.top, 50 * CLIP_AT_TYPICAL);
    assert.equal(chart.clippedBest, 500);
    const best = chart.bars[2]!;
    assert.equal(best.clipped, true);
    assert.equal(best.drawn, chart.top);
    assert.equal(best.views, 500);
    assert.equal(chart.bars[0]!.clipped, false);
  });

  it("leaves the axis alone when nothing breaks out", () => {
    const posts = [40, 60].map((v, i) => post(String(i), `2026-11-27T1${i}:00:00Z`, v));
    const chart = lastPostsChart(posts, 50);
    assert.equal(chart.top, 60);
    assert.equal(chart.clippedBest, null);
  });
});

describe("formatMix", () => {
  it("shares add up to one and the most used format leads", () => {
    const rows = formatMix({ body: { median: 49.5, n: 32 }, none: { median: 46, n: 3 } });
    assert.deepEqual(rows.map((r) => r.placement), ["body", "none"]);
    assert.equal(rows[0]!.share, 32 / 35);
    assert.equal(rows[1]!.share, 3 / 35);
  });

  it("an all-link corpus is one row at 100%", () => {
    const rows = formatMix({ body: { median: 40, n: 10 } });
    assert.equal(rows.length, 1);
    assert.equal(rows[0]!.share, 1);
  });
});

describe("daily trend", () => {
  const today = new Date("2026-11-27T18:00:00Z");

  it("a 30-day window starts 29 days back", () => {
    assert.equal(windowStart(30, today), "2026-10-29");
  });

  it("follower trend keeps the window, oldest first", () => {
    const hist = [
      { date: "2026-11-27", followers: 373, following: 148 },
      { date: "2026-08-01", followers: 300, following: 140 },
      { date: "2026-11-20", followers: 360, following: null },
    ];
    assert.deepEqual(followerTrend(hist, "followers", 30, today), [
      { date: "2026-11-20", value: 360 },
      { date: "2026-11-27", value: 373 },
    ]);
    assert.deepEqual(followerTrend(hist, "following", 30, today), [{ date: "2026-11-27", value: 148 }]);
    assert.equal(followerTrend(hist, "followers", 180, today).length, 3);
  });

  it("median views group by the local send day", () => {
    const posts = [
      // 00:31 UTC on the 28th is still the 27th in New York.
      post("a", "2026-11-28T00:31:00Z", 52),
      post("b", "2026-11-27T15:00:00Z", 229),
      post("c", "2026-11-27T14:00:00Z", 19),
      post("d", "2026-11-26T14:00:00Z", 80),
    ];
    const days = dailyMedianViews(posts, "America/New_York", 30, new Date("2026-11-28T02:00:00Z"));
    assert.deepEqual(days, [
      { date: "2026-11-26", value: 80, n: 1 },
      { date: "2026-11-27", value: 52, n: 3 },
    ]);
  });
});

describe("followRatio", () => {
  it("is followers per account followed", () => {
    assert.equal(followRatio(373, 148), 373 / 148);
    assert.equal(followRatio(373, 0), null);
    assert.equal(followRatio(null, 148), null);
  });
});
