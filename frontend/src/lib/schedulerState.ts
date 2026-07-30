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
  paused: boolean;
}

export interface SchedulerState {
  health: Health;
  lastRun: string | null;
  /** Posts that didn't go out, newest outcome per post. */
  stuck: StuckPost[];
  /** Posts launched whose publisher hasn't reported back — the ones showing Sending. */
  publishing: string[];
  /** Posts queued ahead, from the newest tick's own owner-scoped forecast. */
  soon: number;
}

export const UNKNOWN_STATE: SchedulerState = {
  health: "unknown", lastRun: null, stuck: [], publishing: [], soon: 0,
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
export function deriveSchedulerState(runs: SchedulerRun[]): SchedulerState {
  // Freshness must come from a TICK. A publication finishes minutes after the
  // tick that launched it, so reading its timestamp as the heartbeat would make
  // a dying cron look livelier than it is.
  const newest = runs.find((r) => r.summary?.kind !== "publication");
  if (!newest) {
    return { health: "quiet", lastRun: null, stuck: [], publishing: [], soon: 0 };
  }

  const s = newest.summary ?? {};
  // One pass, newest first: whichever row we meet first for a post is its latest
  // word. A publication settles it. A launch with no publication since means a
  // publisher is STILL WORKING it — precisely the post sitting in Sending on the
  // Posts tab, and the only honest way to say "in progress" from a log that
  // records only starts and finishes.
  const accounted = new Set<string>();
  const stuck: StuckPost[] = [];
  const publishing: string[] = [];
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
          paused: row.outcome === "paused",
        });
      }
      continue;
    }
    for (const l of row.launched ?? []) {
      if (!l.post_id || accounted.has(l.post_id)) continue;
      accounted.add(l.post_id);
      publishing.push(l.post_id.slice(0, 8));
    }
  }

  const age = Date.now() - new Date(newest.run_at).getTime();
  // A stall always outranks activity: publishers can be mid-flight while the cron
  // behind them has died, and the dead cron is the thing worth saying. A publisher
  // being mid-flight is POST state, reported by the Sending badge — the dot stays
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
    publishing,
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
        .map((p) => `${p.id} (${p.reason}${p.paused ? ", Paused" : ", Scheduled — retries next run"})`)
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
