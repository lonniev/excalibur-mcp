// Pure presentation rules for the Leads page — no React, no network.
//
// A lead's score is a sum of named signals the server already computed; the
// page only decides how loudly to show it and which glyph each signal gets.

import type { ConversationStatus } from "./mcp";

/// X caps a recent-search query at 512 characters; the server appends the
/// parentheses, the safe defaults and `-from:<own id>` (≤ 20 digits), which is
/// what the clause budget leaves out. Mirrors conversation_scoring.MAX_CLAUSE.
export const MAX_CLAUSE = 512 - (2 + 1 + "-is:retweet -has:links -has:cashtags lang:en".length + 1 + "-from:".length + 20);

export const STATUSES: readonly ConversationStatus[] = ["new", "seen", "engaged", "dismissed"];

export type ScoreTone = "hot" | "warm" | "cool";

/// 60+ is a question worth answering today; 30+ is worth a look; below that
/// the row is kept for the record (a penalty may have buried a real ask).
export function scoreTone(score: number): ScoreTone {
  if (score >= 60) return "hot";
  if (score >= 30) return "warm";
  return "cool";
}

/// Signal → short glyph title. Icons live in the page; this is the vocabulary.
export const SIGNAL_TITLES: Readonly<Record<string, string>> = {
  need: "Asks a question",
  thread: "Live thread",
  reachable: "Reachable author",
  spam: "Looks promotional",
  reply: "Is itself a reply",
  aged: "Older — score decayed",
};

/// Tally rows per status for the filter chips, in display order.
export function statusCounts(
  rows: ReadonlyArray<{ status: ConversationStatus }>,
): Record<ConversationStatus, number> {
  const out: Record<ConversationStatus, number> = { new: 0, seen: 0, engaged: 0, dismissed: 0 };
  for (const r of rows) out[r.status] += 1;
  return out;
}

/// A compact follower count: 12345 → "12.3k", 980 → "980", null → "—".
export function compactCount(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, "")}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1).replace(/\.0$/, "")}k`;
  return String(n);
}

// ─── Scoring weights — the editor's vocabulary ──────────────────────────────

/// Mirror of the server's DEFAULT_WEIGHTS (conversation_scoring.py). The
/// server stores only what a patron changed, so the editor shows these merged
/// and sends back the diff.
export const DEFAULT_WEIGHTS: Readonly<Record<string, number>> = {
  need: 40,
  replies: 20,
  band: 15,
  spam: -30,
  reply: -20,
  replies_min: 3,
  followers_min: 200,
  followers_max: 20000,
  decay_hours: 72,
};

export interface WeightField {
  key: string;
  label: string;
  hint: string;
  min: number;
  max: number;
}

/// Display order and bounds (bounds mirror the server's _WEIGHT_BOUNDS).
export const WEIGHT_FIELDS: readonly WeightField[] = [
  { key: "need", label: "Asks a question", hint: "how do I, anyone know, looking for…", min: -100, max: 100 },
  { key: "replies", label: "Live thread", hint: "reply count at or above the threshold", min: -100, max: 100 },
  { key: "replies_min", label: "Thread threshold", hint: "replies needed to count as live", min: 0, max: 1000 },
  { key: "band", label: "Reachable author", hint: "followers inside the band", min: -100, max: 100 },
  { key: "followers_min", label: "Band from", hint: "followers", min: 0, max: 10_000_000 },
  { key: "followers_max", label: "Band to", hint: "followers", min: 0, max: 10_000_000 },
  { key: "spam", label: "Looks promotional", hint: "cashtags, styled letters, airdrop…", min: -100, max: 100 },
  { key: "reply", label: "Is a reply", hint: "not a top-level post", min: -100, max: 100 },
  { key: "decay_hours", label: "Fades over", hint: "hours until positive signals reach 0", min: 1, max: 168 },
];

/// Merge stored overrides over the defaults for display.
export function mergedWeights(overrides: Record<string, number> | null | undefined): Record<string, number> {
  return { ...DEFAULT_WEIGHTS, ...(overrides ?? {}) };
}

/// The overrides to send: every key whose value differs from the default.
export function weightOverrides(values: Record<string, number>): Record<string, number> {
  const out: Record<string, number> = {};
  for (const f of WEIGHT_FIELDS) {
    const v = values[f.key];
    if (Number.isInteger(v) && v !== DEFAULT_WEIGHTS[f.key]) out[f.key] = v;
  }
  return out;
}

/// Client-side mirror of the server's bounds, so the form can refuse before a
/// round trip. Returns the first problem, or null.
export function weightsProblem(values: Record<string, number>): string | null {
  for (const f of WEIGHT_FIELDS) {
    const v = values[f.key];
    if (!Number.isInteger(v)) return `${f.label} must be a whole number`;
    if (v < f.min || v > f.max) return `${f.label} must be between ${f.min} and ${f.max}`;
  }
  if (values.followers_min > values.followers_max) return "Band from must not exceed Band to";
  return null;
}

/// Neon hands back Postgres text — `2026-10-04 19:21:02.344888+00` — which
/// `Date.parse` refuses on two counts: the space, and a two-digit offset.
export function normalizePgTimestamp(value: string): string {
  return value.trim().replace(" ", "T").replace(/([+-]\d{2})$/, "$1:00");
}

/// "2 min ago" style for the catalog's last-run column; null → "never".
export function lastRunLabel(iso: string | null | undefined, postsRead: number | null | undefined, now = Date.now()): string {
  if (!iso) return "never";
  const t = Date.parse(normalizePgTimestamp(iso));
  if (Number.isNaN(t)) return "—";
  const mins = Math.max(0, Math.round((now - t) / 60_000));
  const when = mins < 1 ? "just now"
    : mins < 60 ? `${mins} min ago`
    : mins < 60 * 48 ? `${Math.round(mins / 60)} h ago`
    : `${Math.round(mins / 1440)} d ago`;
  return postsRead === null || postsRead === undefined ? when : `${when} · ${postsRead} read`;
}

/// The one-line summary shown after a run.
export function runSummary(r: {
  posts_read?: number; new?: number; refreshed?: number; truncated_reason?: string | null;
}): string {
  const read = r.posts_read ?? 0;
  const fresh = r.new ?? 0;
  const seen = r.refreshed ?? 0;
  let s = `${read} read · ${fresh} new · ${seen} refreshed`;
  if (r.truncated_reason === "rate_limited") s += " · X paused us";
  else if (r.truncated_reason === "max_posts") s += " · more available";
  return s;
}
