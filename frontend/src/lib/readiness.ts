// Readiness — the one state a person flips on a post: Draft or Ready.
//
// A post's `status` column carries eight values, but only two of them are the
// author's to choose. "Draft" means the scheduler ignores it; "Ready" means it
// is in the queue (`scheduled` on the wire). The rest — resolving, resolved,
// sending, sent, archived — are the machine's own bookkeeping, and `paused` is
// the machine asking for a decision. The badge shows every one; it toggles
// only where a person may flip it.
//
// Before this module the flip lived in four controls on two surfaces: "Save
// draft" / "Save changes" (which never changed the state), "Schedule with
// Excalibur" (the only way in), "Unschedule" (the only way out — and it threw
// the publish time away), plus Resume / Return-to-Draft on the list. One badge
// now does it everywhere, and content saves are just content saves.

/** The wire status a flip persists. */
export type Flip = "draft" | "scheduled";

/** What the badge says for each status. `Ready` covers the whole queue family. */
export const BADGE_LABEL: Record<string, string> = {
  draft: "Draft",
  scheduled: "Ready",
  resolving: "Resolving",
  resolved: "Resolved",
  sending: "Sending",
  paused: "Paused",
  sent: "Sent",
  archived: "Archived",
};

/** Statuses a person may flip, and where each flip lands. */
const FLIPS: Record<string, Flip> = {
  draft: "scheduled",
  scheduled: "draft",
  // The machine stopped on a non-transient failure; the person's answer is
  // "go again" (Ready). Returning to Draft is the other exit — see `exits`.
  paused: "scheduled",
  // A claim that never finished. The only rescue is back to Draft.
  sending: "draft",
};

/** Where a flip from `status` lands, or null when the badge is read-only. */
export function flipOf(status: string): Flip | null {
  return FLIPS[status] ?? null;
}

/**
 * The scheduler sweeps on the hour and the half hour. A post made Ready with
 * no time of its own gets the next sweep after `now`, so "Ready" never means
 * "posts the instant you tap it" — the author sees the time and can change it.
 */
export function nextSweepSlot(now: Date = new Date()): Date {
  const next = new Date(now.getTime());
  next.setSeconds(0, 0);
  const m = next.getMinutes();
  next.setMinutes(m < 30 ? 30 : 60);
  return next;
}
