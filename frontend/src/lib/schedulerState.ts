// What the scheduler log MEANS — derived once, read by every surface that shows it.
//
// Posts and Scheduler both answer "is the cron alive, and what is it holding?"
// from the same `get_scheduler_log` rows, but they used to answer it with two
// different bodies of code: Posts had the full derivation plus badges, while
// Scheduler kept its own copy of the freshness thresholds and a `health()` that
// only produced a dot and a label. The comment there said "mirrors
// SchedulerHealth", which is the tell — a mirror drifts, and this one already
// had: the primary Scheduler page showed strictly LESS about the scheduler than
// the Posts toolbar did.
//
// So the derivation lives here and the rendering lives in SchedulerStatusLine.
// A page supplies rows; it does not get to decide what they mean.

import type { SchedulerRun } from "./mcp";

// The cron fires ~every 30 min (on the half hour). A gap past ~40 min means the
// last tick is overdue (quiet); past ~100 min (three missed ticks) it reads as
// stalled, not idle.
export const FRESH_MS = 40 * 60 * 1000;
export const STALE_MS = 100 * 60 * 1000;
// A tick opens its run row before any work and closes it seconds later — it only
// dispatches. So an open row is unremarkable for a moment and damning after this:
// a tick cut off before it could hand its posts to a publisher. (It is NOT a
// signal about publishers, which run long and report separately.)
export const INFLIGHT_MS = 5 * 60 * 1000;

export type Health = "loading" | "healthy" | "cutoff" | "quiet" | "stalled" | "unknown";

export interface StuckPost {
  id: string;
  reason: string;
  /** Why, in the words of whatever refused — absent for older rows. */
  detail: string;
  paused: boolean;
}

export interface SchedulerState {
  health: Health;
  lastRun: string | null;
  /** Posts that didn't go out, newest outcome per post. */
  stuck: StuckPost[];
  /**
   * Posts whose body is being BUILT right now — the ones showing `resolving`.
   *
   * Was `publishing`, and was labelled "Sending", which is a different status
   * with its own filter. Since #318 split publishing in two, posting is inline
   * and takes milliseconds, so the only phase the log can honestly report as
   * in-flight is resolution.
   */
  resolving: string[];
  /** Posts queued ahead, from the newest tick's own owner-scoped forecast. */
  soon: number;
}

// How long a resolve claim is honoured before the scheduler hands the slot back. A
// `resolving` entry older than this is no longer evidence of live work — its worker is
// presumed dead and the row has been re-claimed or released. Without this bound the
// badge can only ever be cleared by a publication row, so it over-reports for the whole
// gap between "resolve finished" and "post sent", which for an early resolve is the
// entire wait.
//
// The real value is SERVED (`scheduler_status.resolve_budgets.lease_seconds`), derived
// there from the block budget ring. This is only the pre-fetch fallback, and it is
// deliberately generous: guessing SHORT would declare live resolves dead and blank a
// badge that is doing its job, whereas guessing long merely lets a finished one linger
// until the next poll.
const FALLBACK_RESOLVE_LEASE_MS = 60 * 60 * 1000;

export const UNKNOWN_STATE: SchedulerState = {
  health: "unknown", lastRun: null, stuck: [], resolving: [], soon: 0,
};

export function relative(fromIso: string): string {
  const then = new Date(fromIso).getTime();
  if (isNaN(then)) return "an unknown time ago";
  const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (secs < 90) return `${secs}s ago`;
  const mins = Math.round(secs / 60);
  if (mins < 90) return `${mins} min ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 36) return `${hrs} h ago`;
  return `${Math.round(hrs / 24)} d ago`;
}

/** Turn raw log rows into everything any surface needs to describe the scheduler. */
export function deriveSchedulerState(
  runs: SchedulerRun[],
  // The server's configured lease. Callers that have already fetched
  // scheduler_status should pass it; the fallback exists only for surfaces that
  // render before that round trip lands.
  leaseMs: number = FALLBACK_RESOLVE_LEASE_MS,
): SchedulerState {
  // Freshness must come from a TICK. A publication finishes minutes after the
  // tick that launched it, so reading its timestamp as the heartbeat would make
  // a dying cron look livelier than it is.
  const newest = runs.find((r) => r.summary?.kind !== "publication");
  if (!newest) {
    return { health: "quiet", lastRun: null, stuck: [], resolving: [], soon: 0 };
  }

  const s = newest.summary ?? {};
  // One pass, newest first: whichever row we meet first for a post is its latest
  // word, and a publication settles it.
  const accounted = new Set<string>();
  const stuck: StuckPost[] = [];
  const resolving: string[] = [];
  const now = Date.now();
  for (const r of runs) {
    const row = r.summary;
    if (!row) continue;
    if (row.kind === "publication") {
      if (!row.post_id || accounted.has(row.post_id)) continue;
      accounted.add(row.post_id);
      if (row.outcome === "held" || row.outcome === "paused") {
        stuck.push({
          id: row.post_id.slice(0, 8),
          reason: row.reason ?? "unreported",
          detail: row.detail ?? "",
          paused: row.outcome === "paused",
        });
      }
      continue;
    }
    // Only `resolving` is in-flight work. `posted` is NOT: since #318 the tick
    // publishes inline and writes the entry with its outcome already decided, so
    // counting it meant reporting a finished action as ongoing. That was the
    // pre-split assumption, when launch and publication were one phase.
    //
    // Two bugs lived here. It read `row.launched` until 2026-08-04 — a key the
    // scheduler stopped emitting at the split — so the list was always empty and
    // a post sat unreported for days. The fix restored the count but kept the
    // name: a post being BUILT was reported as "Sending", a different status
    // whose Posts filter correctly showed nothing.
    //
    // The lease bound is the second half. `accounted` is only ever set by a
    // publication row, and a finished resolve writes none — so without an age
    // limit an entry lingers from "resolve started" until "post sent", which for
    // a post resolved a tick early is the whole wait.
    // Scoped to the resolving loop only — a stale row's `recovered` entries are
    // still worth reporting, and an early `continue` here would swallow them.
    const startedAt = Date.parse(r.run_at ?? "");
    const withinLease = isNaN(startedAt) || now - startedAt <= leaseMs;
    if (withinLease) {
      for (const l of row.resolving ?? []) {
        if (!l.post_id || accounted.has(l.post_id)) continue;
        accounted.add(l.post_id);
        resolving.push(l.post_id.slice(0, 8));
      }
    }
    // A tick that repaired a stranded post is reporting something the owner has
    // to act on: a pause means a tweet may already be live.
    for (const [what, entries] of Object.entries(row.recovered ?? {})) {
      if (!what.startsWith("paused")) continue;
      for (const e of entries ?? []) {
        if (!e.post_id || accounted.has(e.post_id)) continue;
        accounted.add(e.post_id);
        stuck.push({
          id: e.post_id.slice(0, 8),
          reason: what === "paused_unknown"
            ? "x_post_outcome_unknown" : "sending_orphaned_pre_split",
          detail: "The publisher never confirmed. Check your X timeline before resuming.",
          paused: true,
        });
      }
    }
  }

  const age = Date.now() - new Date(newest.run_at).getTime();
  // A stall always outranks activity: publishers can be mid-flight while the cron
  // behind them has died, and the dead cron is the thing worth saying. A publisher
  // being mid-flight is POST state, reported by the Resolving badge — the dot stays
  // about the cron so the two never compete to describe the same thing.
  const health: Health = isNaN(age)
    ? "unknown"
    : s.status === "started" && age > INFLIGHT_MS
      ? "cutoff"
      : age > STALE_MS
        ? "stalled"
        : age > FRESH_MS
          ? "quiet"
          : "healthy";

  return {
    health,
    lastRun: newest.run_at,
    stuck,
    resolving,
    soon: newest.summary?.upcoming?.count ?? 0,
  };
}

/** The hover text for a status line. `clickable` adds the refresh affordance. */
export function schedulerStatusTitle(
  { health, lastRun, stuck }: SchedulerState,
  { clickable = false }: { clickable?: boolean } = {},
): string {
  const stuckNote = stuck.length
    ? ` · didn't post: ${stuck
        .map((p) => `${p.id} (${p.reason}${p.paused ? ", Paused" : ", Scheduled — retries next run"})${p.detail ? ` — ${p.detail}` : ""}`)
        .join("; ")}`
    : "";
  if (health === "unknown") {
    return `Couldn't read scheduler status — your sign-in proof may have lapsed.${clickable ? " Click to retry." : ""}`;
  }
  if (health === "cutoff") {
    return `A scheduler run started ${relative(lastRun ?? "")} and never finished — it was cut short before it could post. The next run picks the work back up.`;
  }
  if (lastRun) {
    return `Scheduler last ran ${relative(lastRun)}${stuckNote}.${clickable ? " Click to refresh." : ""}`;
  }
  return "The scheduler hasn't logged a run yet — it checks for due posts about every half hour.";
}
