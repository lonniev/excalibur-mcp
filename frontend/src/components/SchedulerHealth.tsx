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
// Poll cadence for the status dot. The scheduler only ticks every 30 min, so a
// 5-min poll surfaces a stall promptly without pinning the Neon compute awake.
// We also pause entirely while the tab is hidden (see the effect below).
const POLL_MS = 5 * 60 * 1000;

type Health = "loading" | "healthy" | "quiet" | "stalled" | "unknown";

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
      const runs = await getSchedulerLog(5);
      if (!runs.length) {
        setHealth("quiet");
        setLastRun(null);
        setHeld(0);
        return;
      }
      const newest = runs[0];
      setLastRun(newest.run_at);
      const s = newest.summary ?? {};
      // Owner-scoped: for a patron these arrays already hold only their OWN posts.
      setHeld((s.skipped?.length ?? 0) + (s.errors?.length ?? 0));
      const age = Date.now() - new Date(newest.run_at).getTime();
      setHealth(isNaN(age) ? "unknown" : age <= FRESH_MS ? "healthy" : age <= STALE_MS ? "quiet" : "stalled");
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
    quiet: "bg-amber-400",
    stalled: "bg-red-500",
    unknown: "bg-zinc-400",
  }[health];
  const pulse = health === "healthy" || health === "quiet";
  const label = {
    loading: "Scheduler…",
    healthy: "Scheduler healthy",
    quiet: "Scheduler quiet",
    stalled: "Scheduler stalled",
    unknown: "Scheduler status unknown",
  }[health];
  const title =
    health === "unknown"
      ? "Couldn't read scheduler status — your sign-in proof may have lapsed. Click to retry."
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
