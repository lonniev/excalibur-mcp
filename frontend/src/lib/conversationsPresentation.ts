// Pure presentation rules for the Leads page — no React, no network.
//
// A lead's score is a sum of named signals the server already computed; the
// page only decides how loudly to show it and which glyph each signal gets.

import type { ConversationStatus } from "./mcp";

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
