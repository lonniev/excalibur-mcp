// Readiness — the one state a person flips on a post: Draft or Ready.
//
// A post's `status` column carries eight values, but only two of them are the
// author's to choose. "Draft" means the scheduler ignores it; "Ready" means it
// is in the queue (`scheduled` on the wire). The rest — resolving, resolved,
// sending, sent — are the machine's own bookkeeping, `paused` is the machine
// asking for a decision, and `archived` is the owner's own "retire it". The badge shows every one; it toggles
// only where a person may flip it.
//
// Before this module the flip lived in four controls on two surfaces: "Save
// draft" / "Save changes" (which never changed the state), "Schedule with
// Excalibur" (the only way in), "Unschedule" (the only way out — and it threw
// the publish time away), plus Resume / Return-to-Draft on the list. One badge
// now does it everywhere, and content saves are just content saves.

import { tr } from "../i18n/index.ts";
import type { MessageKey } from "../i18n/en.ts";

/** The wire status a flip persists. */
export type Flip = "draft" | "scheduled";

/** The catalog key for what the badge says on each status. `Ready` covers the whole queue family. */
const BADGE_KEY: Record<string, MessageKey> = {
  draft: "lib.readiness.badge.draft",
  scheduled: "lib.readiness.badge.scheduled",
  resolving: "lib.readiness.badge.resolving",
  resolved: "lib.readiness.badge.resolved",
  sending: "lib.readiness.badge.sending",
  paused: "lib.readiness.badge.paused",
  sent: "lib.readiness.badge.sent",
  archived: "lib.readiness.badge.archived",
};

/** What the badge says for `status`, in the language on screen; an unknown status as it came. */
export function badgeLabel(status: string): string {
  const key = BADGE_KEY[status];
  return key ? tr(key) : status;
}

/** Statuses a person may flip, and where each flip lands. */
const FLIPS: Record<string, Flip> = {
  draft: "scheduled",
  scheduled: "draft",
  // The machine stopped on a non-transient failure; the person's answer is
  // "go again" (Ready). Returning to Draft is the other exit — see `exits`.
  paused: "scheduled",
  // A claim that never finished. The only rescue is back to Draft.
  sending: "draft",
  // Restore. Back to Draft, never straight to Ready: the owner looks at the
  // post — and the next slot the server gave it — before it goes out again.
  archived: "draft",
};

/**
 * Statuses where a post is still meant to go out. Archiving one of these takes
 * it out of rotation, so the confirm says so.
 */
const LIVE = new Set(["scheduled", "paused", "resolving", "resolved", "sending"]);

/** The question to ask before archiving a post in `status`. */
export function archivePrompt(status: string): string {
  return LIVE.has(status) ? tr("lib.readiness.archiveLive") : tr("lib.readiness.archive");
}

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
