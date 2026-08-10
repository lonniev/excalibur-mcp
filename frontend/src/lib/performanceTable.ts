// Pure helpers for the Performance page "Posts by reach" table.
// Sort + short header labels live here so node:test can pin the #373
// contract without mounting React.
//
// #373 — fixed-width columns + long header text ("Escape velocity", …)
// overlapped adjacent headers and made sort targets ambiguous. Short
// labels carry the full name in `full` for title=/tooltip.

import type { PerformancePost } from "./mcp.ts";

export type PerfSortKey =
  | "posted"
  | "impressions"
  | "escape_velocity"
  | "breakout_ratio"
  | "clicks"
  | "profile"
  | "bookmarks"
  | "reply_rate"
  | "quote_to_repost";

export type PerfSortDir = "asc" | "desc";

/**
 * Visible header text must fit a ~6–10% table-fixed column (icon + tip +
 * sort chevron share the cell). Keep `short` to one tight token; put the
 * plain-language name in `full` for hover/title.
 */
export const PERF_SORT_COLUMNS: Record<
  PerfSortKey,
  { short: string; full: string }
> = {
  posted: { short: "Posted", full: "Posted" },
  impressions: { short: "Impr.", full: "Impressions" },
  escape_velocity: { short: "Escape", full: "Escape velocity" },
  breakout_ratio: { short: "Breakout", full: "Breakout ratio" },
  clicks: { short: "Clicks", full: "Link clicks" },
  profile: { short: "Profile", full: "Profile clicks" },
  bookmarks: { short: "Saves", full: "Bookmarks" },
  reply_rate: { short: "Reply", full: "Reply rate" },
  quote_to_repost: { short: "Q/R", full: "Quote / repost ratio" },
};

/** Hard cap on visible short labels — guards against regressing to #373 overflow. */
export const PERF_HEADER_SHORT_MAX = 8;

export function sortValue(p: PerformancePost, key: PerfSortKey): number {
  switch (key) {
    case "posted": {
      const t = p.last_sent_at ? Date.parse(p.last_sent_at) : NaN;
      return Number.isNaN(t) ? Number.NEGATIVE_INFINITY : t;
    }
    case "impressions":
      return p.latest_impressions ?? Number.NEGATIVE_INFINITY;
    case "escape_velocity":
      return p.escape_velocity ?? Number.NEGATIVE_INFINITY;
    case "breakout_ratio":
      return p.breakout_ratio ?? Number.NEGATIVE_INFINITY;
    case "clicks":
      return p.url_link_clicks ?? Number.NEGATIVE_INFINITY;
    case "profile":
      return p.user_profile_clicks ?? Number.NEGATIVE_INFINITY;
    case "bookmarks":
      return p.bookmarks ?? Number.NEGATIVE_INFINITY;
    case "reply_rate":
      return p.reply_rate ?? Number.NEGATIVE_INFINITY;
    case "quote_to_repost":
      return p.quote_to_repost_ratio ?? Number.NEGATIVE_INFINITY;
  }
}

/** Numeric sort with impressions-desc as a stable secondary key. */
export function sortPerformancePosts(
  posts: readonly PerformancePost[],
  sortCol: PerfSortKey,
  sortDir: PerfSortDir,
): PerformancePost[] {
  const copy = posts.slice();
  const mul = sortDir === "desc" ? -1 : 1;
  copy.sort((a, b) => {
    const av = sortValue(a, sortCol);
    const bv = sortValue(b, sortCol);
    if (av === bv) {
      return (b.latest_impressions ?? 0) - (a.latest_impressions ?? 0);
    }
    return av < bv ? -1 * mul : 1 * mul;
  });
  return copy;
}

/** Click-a-header state machine: same col toggles dir; new col starts desc. */
export function nextPerfSort(
  currentCol: PerfSortKey,
  currentDir: PerfSortDir,
  clicked: PerfSortKey,
): { col: PerfSortKey; dir: PerfSortDir } {
  if (clicked === currentCol) {
    return { col: currentCol, dir: currentDir === "desc" ? "asc" : "desc" };
  }
  return { col: clicked, dir: "desc" };
}
