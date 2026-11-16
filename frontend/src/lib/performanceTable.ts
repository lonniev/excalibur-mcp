// Pure helpers for the Performance page "Posts by reach" table.
// Sort + short header labels live here so node:test can pin the #373
// contract without mounting React.
//
// #373 — fixed-width columns + long header text ("Escape velocity", …)
// overlapped adjacent headers and made sort targets ambiguous. Short
// labels carry the full name in `full` for title=/tooltip.
//
// #360 — link placement is a three-state value (none/body/first_reply).
// Never render a missing placement as "Body"; never show 0 clicks for a
// post with no link (that conflates null with zero).

import { languageLocale } from "@tollbooth-dpyc/web";
import { tr } from "../i18n/index.ts";
import type { MessageKey } from "../i18n/en.ts";
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

/** Canonical three-state link placement (#360). */
export type LinkPlacement = "none" | "body" | "first_reply";

/** Every sortable column, in table order. */
export const PERF_SORT_KEYS: readonly PerfSortKey[] = [
  "posted",
  "impressions",
  "escape_velocity",
  "breakout_ratio",
  "clicks",
  "profile",
  "bookmarks",
  "reply_rate",
  "quote_to_repost",
];

/** Catalog keys for each column's `short` and `full` words. */
const PERF_SORT_WORDS: Record<PerfSortKey, { short: MessageKey; full: MessageKey }> = {
  posted: { short: "lib.performanceTable.postedShort", full: "lib.performanceTable.postedFull" },
  impressions: { short: "lib.performanceTable.impressionsShort", full: "lib.performanceTable.impressionsFull" },
  escape_velocity: { short: "lib.performanceTable.escapeShort", full: "lib.performanceTable.escapeFull" },
  breakout_ratio: { short: "lib.performanceTable.breakoutShort", full: "lib.performanceTable.breakoutFull" },
  clicks: { short: "lib.performanceTable.clicksShort", full: "lib.performanceTable.clicksFull" },
  profile: { short: "lib.performanceTable.profileShort", full: "lib.performanceTable.profileFull" },
  bookmarks: { short: "lib.performanceTable.bookmarksShort", full: "lib.performanceTable.bookmarksFull" },
  reply_rate: { short: "lib.performanceTable.replyShort", full: "lib.performanceTable.replyFull" },
  quote_to_repost: { short: "lib.performanceTable.quoteShort", full: "lib.performanceTable.quoteFull" },
};

/**
 * Visible header text must fit a ~6–10% table-fixed column (icon + tip +
 * sort chevron share the cell). Keep `short` to one tight token; put the
 * plain-language name in `full` for hover/title. Words in the language on
 * screen, so call it at render.
 */
export function perfSortColumn(key: PerfSortKey): { short: string; full: string } {
  const w = PERF_SORT_WORDS[key];
  return { short: tr(w.short), full: tr(w.full) };
}

/** Hard cap on visible short labels — guards against regressing to #373 overflow. */
export const PERF_HEADER_SHORT_MAX = 8;

/** Human labels for the three placement states — never invent "Body" for null. */
const LINK_PLACEMENT_LABELS: Record<LinkPlacement, MessageKey> = {
  none: "lib.performanceTable.placementNone",
  body: "lib.performanceTable.placementBody",
  first_reply: "lib.performanceTable.placementFirstReply",
};

/**
 * Coerce API/legacy placement into the three-state set.
 * Blank, null, unknown → `none` (not `body` — that was the #360 bug).
 */
export function normalizeLinkPlacement(
  value: string | null | undefined,
): LinkPlacement {
  if (value == null) return "none";
  const raw = String(value).trim().toLowerCase().replace(/[-\s]/g, "_");
  if (!raw) return "none";
  if (raw === "body" || raw === "in_body" || raw === "body_link") return "body";
  if (
    raw === "first_reply" ||
    raw === "firstreply" ||
    raw === "reply" ||
    raw === "in_reply" ||
    raw === "in_first_reply"
  ) {
    return "first_reply";
  }
  if (raw === "none" || raw === "no_link" || raw === "nolink" || raw === "missing") {
    return "none";
  }
  return "none";
}

/** Visible placement label for cohort rows / any residual per-row UI. */
export function formatLinkPlacement(
  value: string | null | undefined,
): string {
  return tr(LINK_PLACEMENT_LABELS[normalizeLinkPlacement(value)]);
}

/**
 * Link clicks cell: `0` only when a link was placed and the harvest measured
 * zero; `—` when there is no link OR the field was not captured.
 */
export function formatLinkClicks(
  clicks: number | null | undefined,
  placement: string | null | undefined,
): string {
  if (normalizeLinkPlacement(placement) === "none") return "—";
  if (clicks == null || Number.isNaN(clicks)) return "—";
  return Number(clicks).toLocaleString(languageLocale());
}

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
    case "clicks": {
      // No-link posts sort with uncaptured (bottom on desc), not as zero.
      if (normalizeLinkPlacement(p.link_placement) === "none") {
        return Number.NEGATIVE_INFINITY;
      }
      return p.url_link_clicks ?? Number.NEGATIVE_INFINITY;
    }
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
