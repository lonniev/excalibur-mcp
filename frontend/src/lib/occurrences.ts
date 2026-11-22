// When posts go out, as events on a calendar: what was sent, what is coming,
// and what would come if a paused post were resumed.
//
// A recurring post is one row with its next slot in `publish_at`; the coming
// occurrences after it are walked from its `recurrence` exactly as the
// publisher walks them (`publisher._advance` / `upcoming_slot`), so the month
// shows the days the scheduler will actually post on. Pure: no clock is read
// that is not passed in.

import type { PostSummary } from "./mcp.ts";

/** A cadence as stored. Read loosely: a row written before a pattern was known may carry anything. */
export interface Cadence {
  freq?: string;
  interval?: number;
}

export type OccurrenceKind = "sent" | "coming" | "paused";

export interface Occurrence {
  /** When, in seconds. */
  at: number;
  kind: OccurrenceKind;
  post: PostSummary;
}

const DAY_MS = 86_400_000;
/** Bounds the walk, as `upcoming_slot` does: years of daily slots, never a spin. */
const MAX_STEPS = 2000;

const toMs = (iso: string | null | undefined): number | null => {
  if (!iso) return null;
  // Postgres says "2026-11-22 12:45:00+00"; Date wants the T and a full offset.
  const t = Date.parse(iso.replace(" ", "T").replace(/([+-]\d\d)$/, "$1:00"));
  return Number.isNaN(t) ? null : t;
};

function addMonths(ms: number, months: number): number {
  const d = new Date(ms);
  const m = d.getUTCMonth() + months;
  const year = d.getUTCFullYear() + Math.floor(m / 12);
  const month = ((m % 12) + 12) % 12;
  const last = new Date(Date.UTC(year, month + 1, 0)).getUTCDate();
  return Date.UTC(year, month, Math.min(d.getUTCDate(), last), d.getUTCHours(), d.getUTCMinutes(), d.getUTCSeconds(), d.getUTCMilliseconds());
}

/** `n` business days on, Mon–Fri counted in UTC as the publisher counts them. */
function addBusinessDays(ms: number, n: number): number {
  let r = ms;
  for (let added = 0; added < n; ) {
    r += DAY_MS;
    const wd = new Date(r).getUTCDay();
    if (wd !== 0 && wd !== 6) added++;
  }
  return r;
}

/** The slot after `ms`, or null for a pattern the publisher does not know. */
export function advance(ms: number, recurrence: Cadence): number | null {
  const interval = Number.isInteger(recurrence.interval) && recurrence.interval! >= 1 ? recurrence.interval! : 1;
  switch (recurrence.freq) {
    case "daily": return ms + interval * DAY_MS;
    case "weekdays": return addBusinessDays(ms, interval);
    case "weekly": return ms + interval * 7 * DAY_MS;
    case "monthly": return addMonths(ms, interval);
    default: return null;
  }
}

/**
 * The slots of a post that fall in `[fromMs, toMs)`, from its next slot on.
 * Nothing is placed in the past: a slot already passed is due, and goes out at
 * the scheduler's next tick, so it shows now; a paused post instead rejoins its
 * rhythm at its first slot after now, never in a burst of the ones it missed.
 * A one-off has just its own slot. Stops at `cease_at`.
 */
export function slotsIn(post: PostSummary, fromMs: number, toMsExcl: number, nowMs: number): number[] {
  let slot = toMs(post.publish_at);
  if (slot === null) return [];
  const rec: Cadence | null = post.recurrence ?? null;
  const cease = toMs(post.cease_at);
  const out: number[] = [];
  const keep = (ms: number) => { if (ms >= fromMs && ms < toMsExcl) out.push(ms); };
  if (slot <= nowMs && post.status !== "paused") keep(nowMs);
  if (!rec) {
    if (slot > nowMs) keep(slot);
    return out;
  }
  // After a due slot fires, the publisher moves to the first slot after now.
  for (let i = 0; slot !== null && slot <= nowMs && i < MAX_STEPS; i++) slot = advance(slot, rec);
  for (let i = 0; slot !== null && slot < toMsExcl && i < MAX_STEPS; i++) {
    if (cease !== null && slot > cease) break;
    if (slot >= fromMs) out.push(slot);
    slot = advance(slot, rec);
  }
  return out;
}

/**
 * Everything on the calendar between two instants: each sent post where it went
 * out, and the coming (or, paused, would-be) slots of the posts still to go.
 */
export function occurrencesIn(sent: PostSummary[], upcoming: PostSummary[], fromMs: number, toMsExcl: number, nowMs: number): Occurrence[] {
  const out: Occurrence[] = [];
  for (const post of sent) {
    const at = toMs(post.last_sent_at);
    if (at !== null && at >= fromMs && at < toMsExcl) out.push({ at: at / 1000, kind: "sent", post });
  }
  for (const post of upcoming) {
    const kind: OccurrenceKind = post.status === "paused" ? "paused" : "coming";
    for (const ms of slotsIn(post, fromMs, toMsExcl, nowMs)) out.push({ at: ms / 1000, kind, post });
  }
  return out.sort((a, b) => a.at - b.at);
}

/** How many of each kind a day holds, in the order they read. */
export function countsOf(day: Occurrence[]): [OccurrenceKind, number][] {
  const order: OccurrenceKind[] = ["sent", "coming", "paused"];
  return order.map((k) => [k, day.filter((o) => o.kind === k).length] as [OccurrenceKind, number]).filter(([, n]) => n > 0);
}
