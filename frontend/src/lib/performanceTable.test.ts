// Pure-logic tests for the Performance "Posts by reach" table helpers.
// Run with: node --experimental-strip-types --test frontend/src/lib/performanceTable.test.ts
//
// #373 — (1) column headers must sort numerically and toggle direction;
// (2) short header labels must fit fixed-width columns (no long phrases
// like "Escape velocity" that overflow and overlap neighbors).

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  PERF_HEADER_SHORT_MAX,
  PERF_SORT_COLUMNS,
  formatLinkClicks,
  formatLinkPlacement,
  nextPerfSort,
  normalizeLinkPlacement,
  sortPerformancePosts,
  sortValue,
  type PerfSortKey,
} from "./performanceTable.ts";
import type { PerformancePost } from "./mcp.ts";

function post(partial: Partial<PerformancePost> & { post_id: string }): PerformancePost {
  return partial;
}

describe("sortPerformancePosts — numeric, not lexical (#373)", () => {
  const rows = [
    post({ post_id: "a", latest_impressions: 9, escape_velocity: 0.5, reply_rate: 0.02 }),
    post({ post_id: "b", latest_impressions: 100, escape_velocity: 2.5, reply_rate: 0.1 }),
    post({ post_id: "c", latest_impressions: 50, escape_velocity: 1.2, reply_rate: 0.05 }),
    // Lexical trap: "9" > "100" as strings; numeric desc must put 100 first.
    post({ post_id: "d", latest_impressions: 1000, escape_velocity: null, reply_rate: null }),
  ];

  it("sorts impressions descending numerically (default reach order)", () => {
    const sorted = sortPerformancePosts(rows, "impressions", "desc");
    assert.deepEqual(
      sorted.map((p) => p.post_id),
      ["d", "b", "c", "a"],
    );
  });

  it("sorts impressions ascending when toggled", () => {
    const sorted = sortPerformancePosts(rows, "impressions", "asc");
    assert.deepEqual(
      sorted.map((p) => p.post_id),
      ["a", "c", "b", "d"],
    );
  });

  it("sorts escape_velocity numerically and parks nulls at the bottom on desc", () => {
    const sorted = sortPerformancePosts(rows, "escape_velocity", "desc");
    assert.deepEqual(
      sorted.map((p) => p.post_id),
      ["b", "c", "a", "d"],
    );
  });

  it("uses impressions as a stable secondary key on ties", () => {
    const tied = [
      post({ post_id: "lo", escape_velocity: 1, latest_impressions: 10 }),
      post({ post_id: "hi", escape_velocity: 1, latest_impressions: 99 }),
    ];
    const sorted = sortPerformancePosts(tied, "escape_velocity", "desc");
    assert.deepEqual(
      sorted.map((p) => p.post_id),
      ["hi", "lo"],
    );
  });

  it("sortValue reads posted as epoch ms", () => {
    const p = post({
      post_id: "t",
      last_sent_at: "2026-01-15T12:00:00.000Z",
    });
    assert.equal(sortValue(p, "posted"), Date.parse("2026-01-15T12:00:00.000Z"));
  });
});

describe("nextPerfSort — header click contract (#373)", () => {
  it("toggles direction on the active column", () => {
    assert.deepEqual(nextPerfSort("impressions", "desc", "impressions"), {
      col: "impressions",
      dir: "asc",
    });
    assert.deepEqual(nextPerfSort("impressions", "asc", "impressions"), {
      col: "impressions",
      dir: "desc",
    });
  });

  it("starts a new column descending", () => {
    assert.deepEqual(nextPerfSort("impressions", "asc", "escape_velocity"), {
      col: "escape_velocity",
      dir: "desc",
    });
  });
});

describe("link placement three-state + clicks (#360)", () => {
  it("normalizeLinkPlacement never invents body for null/blank/unknown", () => {
    assert.equal(normalizeLinkPlacement(null), "none");
    assert.equal(normalizeLinkPlacement(undefined), "none");
    assert.equal(normalizeLinkPlacement(""), "none");
    assert.equal(normalizeLinkPlacement("   "), "none");
    assert.equal(normalizeLinkPlacement("garbage"), "none");
    assert.equal(normalizeLinkPlacement("Body"), "body");
    assert.equal(normalizeLinkPlacement("first_reply"), "first_reply");
    assert.equal(normalizeLinkPlacement("reply"), "first_reply");
    assert.equal(normalizeLinkPlacement("no_link"), "none");
  });

  it("formatLinkPlacement labels the three states without defaulting to Body", () => {
    assert.equal(formatLinkPlacement(null), "None");
    assert.equal(formatLinkPlacement("none"), "None");
    assert.equal(formatLinkPlacement("body"), "Body");
    assert.equal(formatLinkPlacement("first_reply"), "First reply");
  });

  it("formatLinkClicks distinguishes none / uncaptured / zero", () => {
    // No link → always em-dash, even if a stale 0 leaked through.
    assert.equal(formatLinkClicks(0, "none"), "—");
    assert.equal(formatLinkClicks(0, null), "—");
    assert.equal(formatLinkClicks(null, "none"), "—");
    // Link present, not captured → em-dash.
    assert.equal(formatLinkClicks(null, "body"), "—");
    // Link present, measured zero → "0".
    assert.equal(formatLinkClicks(0, "body"), "0");
    assert.equal(formatLinkClicks(5, "first_reply"), "5");
  });

  it("sort by clicks parks no-link posts with nulls, not as zero", () => {
    const rows = [
      post({ post_id: "none", link_placement: "none", url_link_clicks: 0, latest_impressions: 1 }),
      post({ post_id: "zero", link_placement: "body", url_link_clicks: 0, latest_impressions: 2 }),
      post({ post_id: "hi", link_placement: "body", url_link_clicks: 9, latest_impressions: 3 }),
    ];
    const sorted = sortPerformancePosts(rows, "clicks", "desc");
    assert.deepEqual(
      sorted.map((p) => p.post_id),
      ["hi", "zero", "none"],
    );
  });
});

describe("PERF_SORT_COLUMNS — short labels fit fixed-width cols (#373)", () => {
  // The field report's overlapping headers used these full phrases as the
  // visible label. They must not reappear as `short`.
  const FORBIDDEN_VISIBLE = [
    "Escape velocity",
    "Breakout ratio",
    "Reply rate",
    "Quote/repost",
    "Bookmarks",
  ];

  it("every short label is at most PERF_HEADER_SHORT_MAX chars", () => {
    for (const [key, { short }] of Object.entries(PERF_SORT_COLUMNS)) {
      assert.ok(
        short.length <= PERF_HEADER_SHORT_MAX,
        `${key} short label "${short}" is ${short.length} chars (max ${PERF_HEADER_SHORT_MAX})`,
      );
    }
  });

  it("does not use the long phrases that overflowed adjacent headers", () => {
    const shorts = Object.values(PERF_SORT_COLUMNS).map((c) => c.short);
    for (const bad of FORBIDDEN_VISIBLE) {
      assert.ok(!shorts.includes(bad), `visible short label must not be "${bad}"`);
    }
  });

  it("keeps the full plain-language name for title/tooltip", () => {
    assert.equal(PERF_SORT_COLUMNS.escape_velocity.full, "Escape velocity");
    assert.equal(PERF_SORT_COLUMNS.breakout_ratio.full, "Breakout ratio");
    assert.equal(PERF_SORT_COLUMNS.quote_to_repost.full, "Quote / repost ratio");
    // Every column exposes a non-empty full label.
    for (const [key, { full }] of Object.entries(PERF_SORT_COLUMNS) as [
      PerfSortKey,
      { short: string; full: string },
    ][]) {
      assert.ok(full.length > 0, `${key} missing full label`);
    }
  });
});
