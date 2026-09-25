// eXcalibur's own clock helpers — the Posts cell, the Performance time-of-day
// cohort and its deep-link into Posts. The display zone itself, its stored
// preference ("excalibur:timezone") and every generic conversion come from
// @tollbooth-dpyc/web.

import { getZonedParts } from "@tollbooth-dpyc/web";

function pad2(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}

/** Compact "Posted" cell: month day, hour:minute in the patron zone. */
export function formatPostedShort(iso: string | null | undefined, timeZone: string): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  return new Date(t).toLocaleString(undefined, {
    timeZone,
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

// ── Time-of-day cohort in the patron zone ───────────────────────────────────

export type TodBucket = { median: number; n: number };

function medianOf(values: number[]): number {
  if (values.length === 0) return 0;
  const s = values.slice().sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 === 0 ? (s[mid - 1]! + s[mid]!) / 2 : s[mid]!;
}

/**
 * Bucket posts by the hour-of-day they were sent *in `timeZone`*.
 * Must compute from instants — never relabel UTC-hour keys (DST / date-line wrong).
 */
export function timeOfDayCohortInZone(
  posts: ReadonlyArray<{ last_sent_at?: string | null; latest_impressions?: number | null }>,
  timeZone: string,
): Record<string, TodBucket> {
  const buckets: Record<string, number[]> = {};
  for (const p of posts) {
    const sent = p.last_sent_at;
    const imp = p.latest_impressions;
    if (!sent || imp == null || Number.isNaN(Number(imp))) continue;
    const t = Date.parse(sent);
    if (Number.isNaN(t)) continue;
    const key = pad2(getZonedParts(new Date(t), timeZone).hour);
    (buckets[key] ??= []).push(Number(imp));
  }
  const out: Record<string, TodBucket> = {};
  for (const [k, vals] of Object.entries(buckets)) {
    if (!vals.length) continue;
    out[k] = { median: medianOf(vals), n: vals.length };
  }
  return out;
}

// ── Time-of-day deep-link (Performance chart → Posts) ───────────────────────
//
// The Performance Time-of-day chart deep-links into Posts with `?hour=HH`
// (local wall hour 0–23 in the patron zone). Posts applies that as a sent-hour
// filter so the operator lands on the posts behind a clicked bar.

/** Parse a URL/search hour param into 0–23, or null when absent/invalid. */
export function parseLocalHourParam(raw: string | null | undefined): number | null {
  if (raw == null) return null;
  const s = String(raw).trim();
  if (!/^\d{1,2}$/.test(s)) return null;
  const n = Number.parseInt(s, 10);
  return n >= 0 && n <= 23 ? n : null;
}

/** Zero-pad a local hour for URL/query keys ("9" → "09"). */
export function formatLocalHourParam(hour: number): string {
  return pad2(hour);
}

/**
 * Posts-page href that pre-applies a time-of-day filter for `localHour`.
 * Invalid hours yield the bare posts root (no filter) so a bad click never 404s.
 */
export function postsHrefForLocalHour(localHour: number): string {
  const h = parseLocalHourParam(String(localHour));
  if (h == null) return "/";
  return `/?hour=${formatLocalHourParam(h)}`;
}
