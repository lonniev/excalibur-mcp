// A calm, at-a-glance health signal for the scheduler thread. The Cloudflare
// cron Worker records a heartbeat every tick (`scheduler_runs`, surfaced by
// `get_scheduler_log` — owner-scoped, so a patron still sees the global run_at
// heartbeat). We read the newest tick and turn its freshness into one dot, so a
// stalled scheduler is visible rather than silently swallowing scheduled posts.

import { useCallback, useEffect, useRef, useState } from "react";
import { getSchedulerLog } from "../lib/mcp";

// The cron fires ~every 30 min (on the half hour). A gap past ~40 min means the
// last tick is overdue (quiet); past ~100 min (three missed ticks) it reads as
// stalled, not idle.
const FRESH_MS = 40 * 60 * 1000;
const STALE_MS = 100 * 60 * 1000;
// A tick opens its run row before any work and now closes it seconds later — it
// only dispatches. So an open row is unremarkable for a moment and damning after
// this: a tick that was cut off before it could hand its posts to a publisher.
// (It is NOT a signal about publishers, which run long and report separately.)
const INFLIGHT_MS = 5 * 60 * 1000;
// Poll cadence for the status dot. The scheduler only ticks every 30 min, so a
// 5-min poll surfaces a stall promptly without pinning the Neon compute awake.
// We also pause entirely while the tab is hidden (see the effect below).
const POLL_MS = 5 * 60 * 1000;

type Health = "loading" | "healthy" | "working" | "cutoff" | "quiet" | "stalled" | "unknown";

function relative(fromIso: string): string {
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

export default function SchedulerHealth() {
  const [health, setHealth] = useState<Health>("loading");
  const [lastRun, setLastRun] = useState<string | null>(null);
  // Posts that didn't go out, newest outcome per post. NOT a count of rows: one
  // post failing on every tick writes a row each time, and reporting "2" for a
  // single struggling post sends you hunting for a second one.
  const [stuck, setStuck] = useState<{ id: string; reason: string; paused: boolean }[]>([]);
  // Posts launched whose publisher hasn't reported back — the ones showing as
  // Sending. This is the "in progress" the dot should mean.
  const [publishing, setPublishing] = useState<string[]>([]);
  const timer = useRef<number | null>(null);

  const refresh = useCallback(async () => {
    try {
      // Enough rows that a tick is in the window even when publications — one
      // per post published — are interleaved with the heartbeats.
      const runs = await getSchedulerLog(25);
      // Freshness must come from a TICK. A publication finishes minutes after
      // the tick that launched it, so reading its timestamp as the heartbeat
      // would make a dying cron look livelier than it is.
      const newest = runs.find((r) => r.summary?.kind !== "publication");
      if (!newest) {
        setHealth("quiet");
        setLastRun(null);
        setStuck([]);
        setPublishing([]);
        return;
      }
      setLastRun(newest.run_at);
      const s = newest.summary ?? {};
      // Publications are per-post rows written by the publisher that did the
      // work, owner-scoped before they reach us. Runs arrive newest-first, so
      // the first row seen for a post is its latest word: a post that has since
      // published stops counting, and one that keeps failing counts once.
      // One pass, newest first: whichever row we meet first for a post is its
      // latest word. A publication settles it. A launch with no publication
      // since means a publisher is STILL WORKING it — which is precisely the
      // post sitting in Sending on the Posts tab, and the only honest way to
      // say "in progress" from a log that only records starts and finishes.
      const accounted = new Set<string>();
      const unposted: { id: string; reason: string; paused: boolean }[] = [];
      const inFlight: string[] = [];
      for (const r of runs) {
        const row = r.summary;
        if (!row) continue;
        if (row.kind === "publication") {
          if (!row.post_id || accounted.has(row.post_id)) continue;
          accounted.add(row.post_id);
          if (row.outcome === "held" || row.outcome === "paused") {
            unposted.push({
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
          inFlight.push(l.post_id.slice(0, 8));
        }
      }
      setStuck(unposted);
      setPublishing(inFlight);
      const age = Date.now() - new Date(newest.run_at).getTime();
      // A stall always outranks activity: publishers can be mid-flight while the
      // cron behind them has died, and the dead cron is the thing worth saying.
      if (isNaN(age)) setHealth("unknown");
      else if (s.status === "started" && age > INFLIGHT_MS) setHealth("cutoff");
      else if (age > STALE_MS) setHealth("stalled");
      else if (age > FRESH_MS) setHealth("quiet");
      else if (inFlight.length) setHealth("working");
      else setHealth("healthy");
    } catch {
      // Free + proof-gated; a failure means the sign-in proof lapsed, not that
      // the scheduler is down — show "unknown", never a false alarm.
      setHealth("unknown");
    }
  }, []);

  useEffect(() => {
    const stop = () => {
      if (timer.current) {
        window.clearInterval(timer.current);
        timer.current = null;
      }
    };
    // Only poll while the tab is visible. A backgrounded tab neither needs a
    // fresh dot nor should it keep waking the Neon compute every few minutes.
    const start = () => {
      if (timer.current) return;
      timer.current = window.setInterval(() => void refresh(), POLL_MS);
    };
    const onVisibility = () => {
      if (document.hidden) {
        stop();
      } else {
        void refresh(); // catch up immediately on return
        start();
      }
    };

    if (!document.hidden) {
      void refresh();
      start();
    }
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      document.removeEventListener("visibilitychange", onVisibility);
      stop();
    };
  }, [refresh]);

  const dot = {
    loading: "bg-zinc-400",
    healthy: "bg-green-500",
    working: "bg-sky-500",
    cutoff: "bg-red-500",
    quiet: "bg-amber-400",
    stalled: "bg-red-500",
    unknown: "bg-zinc-400",
  }[health];
  const pulse = health === "healthy" || health === "quiet" || health === "working";
  const label = {
    loading: "Scheduler…",
    healthy: "Scheduler healthy",
    working: "Scheduler publishing",
    cutoff: "Scheduler cut off",
    quiet: "Scheduler quiet",
    stalled: "Scheduler stalled",
    unknown: "Scheduler status unknown",
  }[health];
  // Name the posts and say where each one LIVES. "Held" is an attempt outcome,
  // not a status — a held post is still Scheduled — so pointing at a status
  // that doesn't exist is what sends someone hunting through the Posts page.
  const stuckNote = stuck.length
    ? ` · didn't post: ${stuck
        .map((p) => `${p.id} (${p.reason}${p.paused ? ", now Paused" : ", still Scheduled — retries next run"})`)
        .join("; ")}`
    : "";
  const title =
    health === "unknown"
      ? "Couldn't read scheduler status — your sign-in proof may have lapsed. Click to retry."
      : health === "cutoff"
        ? `A scheduler run started ${relative(lastRun ?? "")} and never finished — it was cut short before it could post. The next run picks the work back up.`
        : lastRun
          ? `Scheduler last ran ${relative(lastRun)}${stuckNote}. Click to refresh.`
          : "The scheduler hasn't logged a run yet — it checks for due posts about every half hour.";

  return (
    <button
      onClick={() => void refresh()}
      title={title}
      className="flex items-center gap-1.5 rounded-lg px-2 py-1 text-xs text-stone-500 transition-colors hover:bg-stone-100 dark:text-zinc-400 dark:hover:bg-zinc-800"
    >
      <span className={`inline-block h-2 w-2 rounded-full ${dot} ${pulse ? "animate-pulse" : ""}`} />
      <span className="hidden sm:inline">{label}</span>
      {publishing.length > 0 && (
        <span
          className="rounded-full bg-sky-500/15 px-1.5 text-[10px] text-sky-600 dark:text-sky-400"
          title={`A publisher is working on ${publishing.join(", ")} right now — the post shows as Sending until it reports back.`}
        >
          {publishing.length} publishing
        </span>
      )}
      {stuck.length > 0 && (
        <span className="rounded-full bg-rose-500/15 px-1.5 text-[10px] text-rose-600 dark:text-rose-400">
          {stuck.length} not posted
        </span>
      )}
    </button>
  );
}
