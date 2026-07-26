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
// A tick opens its run row before doing any work, so a fresh row may simply be a
// tick in flight. It works to a budget well under two minutes, so a row still
// reading `started` past this is a tick that was cut off and never came back —
// which must NOT read as healthy just because its heartbeat is recent.
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
  const [held, setHeld] = useState(0);
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
        setHeld(0);
        return;
      }
      setLastRun(newest.run_at);
      const s = newest.summary ?? {};
      // Publications are per-post rows written by the publisher that did the
      // work, and are owner-scoped before they reach us — so counting the recent
      // window gives the reader their OWN posts that didn't go out.
      setHeld(
        runs.filter(
          (r) => r.summary?.kind === "publication"
            && (r.summary.outcome === "held" || r.summary.outcome === "paused"),
        ).length,
      );
      const age = Date.now() - new Date(newest.run_at).getTime();
      if (isNaN(age)) {
        setHealth("unknown");
      } else if (s.status === "started") {
        // An open row: in flight if it just started, cut off if it never closed.
        setHealth(age <= INFLIGHT_MS ? "working" : "cutoff");
      } else {
        setHealth(age <= FRESH_MS ? "healthy" : age <= STALE_MS ? "quiet" : "stalled");
      }
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
    working: "Scheduler working",
    cutoff: "Scheduler cut off",
    quiet: "Scheduler quiet",
    stalled: "Scheduler stalled",
    unknown: "Scheduler status unknown",
  }[health];
  const title =
    health === "unknown"
      ? "Couldn't read scheduler status — your sign-in proof may have lapsed. Click to retry."
      : health === "cutoff"
        ? `A scheduler run started ${relative(lastRun ?? "")} and never finished — it was cut short before it could post. The next run picks the work back up.`
        : lastRun
          ? `Scheduler last ran ${relative(lastRun)}${held ? ` · ${held} of your posts were held that tick` : ""}. Click to refresh.`
          : "The scheduler hasn't logged a run yet — it checks for due posts about every half hour.";

  return (
    <button
      onClick={() => void refresh()}
      title={title}
      className="flex items-center gap-1.5 rounded-lg px-2 py-1 text-xs text-stone-500 transition-colors hover:bg-stone-100 dark:text-zinc-400 dark:hover:bg-zinc-800"
    >
      <span className={`inline-block h-2 w-2 rounded-full ${dot} ${pulse ? "animate-pulse" : ""}`} />
      <span className="hidden sm:inline">{label}</span>
      {held > 0 && (
        <span className="rounded-full bg-rose-500/15 px-1.5 text-[10px] text-rose-600 dark:text-rose-400">
          {held} held
        </span>
      )}
    </button>
  );
}
