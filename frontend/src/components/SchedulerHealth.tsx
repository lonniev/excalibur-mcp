// The Posts toolbar's scheduler signal: poll the log, render the shared status
// line, refresh on click.
//
// This component owns only the FETCHING. What the rows mean lives in
// lib/schedulerState, and how they look in SchedulerStatusLine — both shared with
// the Scheduler page, which used to keep its own thinner copy and therefore told
// you less about the scheduler than this toolbar did.

import { useCallback, useEffect, useRef, useState } from "react";
import { getSchedulerLog, getSchedulerStatus } from "../lib/mcp";
import {
  deriveSchedulerState, schedulerStatusTitle, UNKNOWN_STATE,
  type SchedulerState,
} from "../lib/schedulerState";
import SchedulerStatusLine from "./SchedulerStatusLine";

// Poll cadence for the status dot. The scheduler only ticks every 30 min, so a
// 5-min poll surfaces a stall promptly without pinning the Neon compute awake.
// We also pause entirely while the tab is hidden (see the effect below).
const POLL_MS = 5 * 60 * 1000;

export default function SchedulerHealth() {
  const [state, setState] = useState<SchedulerState>({ ...UNKNOWN_STATE, health: "loading" });
  const timer = useRef<number | null>(null);

  const refresh = useCallback(async () => {
    try {
      // Enough rows that a tick is in the window even when publications — one per
      // post published — are interleaved with the heartbeats.
      //
      // Status comes along for the ride because the rows alone cannot say WHY
      // they stopped: an unauthorized Worker writes none, and this toolbar was
      // calling that "stalled". It also carries the real resolve lease, which
      // this surface was previously guessing with the fallback constant.
      const [runs, status] = await Promise.all([getSchedulerLog(25), getSchedulerStatus()]);
      const leaseSeconds = status?.resolve_budgets?.lease_seconds;
      setState(deriveSchedulerState(
        runs, leaseSeconds ? leaseSeconds * 1000 : undefined, status?.authorization?.phase));
    } catch {
      // Free + proof-gated; a failure means the sign-in proof lapsed, not that
      // the scheduler is down — show "unknown", never a false alarm.
      setState(UNKNOWN_STATE);
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

  return (
    <button
      onClick={() => void refresh()}
      title={schedulerStatusTitle(state, { clickable: true })}
      className="flex items-center gap-1.5 rounded-lg px-2 py-1 text-xs text-stone-500 transition-colors hover:bg-stone-100 dark:text-zinc-400 dark:hover:bg-zinc-800"
    >
      <SchedulerStatusLine state={state} collapseLabel />
    </button>
  );
}
