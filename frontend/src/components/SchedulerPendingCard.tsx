// The Device-Grant "second surface" for the scheduled-post Worker.
//
// When the cron Worker's authorization lapses it DMs the operator a challenge
// phrase and waits. Asleep-at-3am, the operator later needs to know WHAT asked
// and prove it's their own scheduler, not a well-timed impostor. This card is
// that proof: it shows — owner-private, fed from the Worker's own KV — the same
// phrase the DM carries. Matching the two is the approval gate. If the phrase
// here doesn't appear in any DM, the operator should NOT approve.
//
// Hidden unless the scheduler is actually pending AND the viewer is the
// operator (getSchedulerPending returns null otherwise — the MCP gates it to
// the operator npub). A plain npub login suffices; the browser signs nothing.
// Approval itself happens in Pricing Studio — the operator nsec that signs the
// reply lives there, not in this browser.

import { useCallback, useEffect, useState } from "react";
import { getSchedulerPending, runSchedulerCheckNow, type SchedulerPending } from "../lib/mcp";

const POLL_MS = 5 * 60 * 1000;

function relative(ms: number): string {
  const secs = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (secs < 90) return `${secs}s ago`;
  const mins = Math.round(secs / 60);
  if (mins < 90) return `${mins} min ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 36) return `${hrs} h ago`;
  return `${Math.round(hrs / 24)} d ago`;
}

export default function SchedulerPendingCard() {
  const [state, setState] = useState<SchedulerPending | null>(null);
  const [busy, setBusy] = useState(false);
  const [poked, setPoked] = useState(false);

  const refresh = useCallback(async () => {
    setState(await getSchedulerPending());
  }, []);

  // "I've approved — check now": poke the scheduler to run a tick immediately so
  // it claims the reply instead of waiting for the next cron. The Worker runs
  // the tick in the background; give it a moment, then refresh — if it completed,
  // the phase flips and this card disappears.
  const checkNow = useCallback(async () => {
    setBusy(true);
    setPoked(false);
    await runSchedulerCheckNow();
    window.setTimeout(() => {
      void refresh();
      setBusy(false);
      setPoked(true);
    }, 4000);
  }, [refresh]);

  useEffect(() => {
    let timer: number | null = null;
    const start = () => {
      if (!timer) timer = window.setInterval(() => void refresh(), POLL_MS);
    };
    const stop = () => {
      if (timer) {
        window.clearInterval(timer);
        timer = null;
      }
    };
    const onVisibility = () => {
      if (document.hidden) stop();
      else {
        void refresh();
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

  if (state?.phase !== "pending") return null;

  return (
    <div
      role="status"
      className="rounded-xl border border-amber-300/70 bg-amber-50 p-4 text-sm text-amber-900 dark:border-amber-500/40 dark:bg-amber-950/40 dark:text-amber-100"
    >
      <div className="flex items-center gap-2 font-medium">
        <span className="inline-block h-2 w-2 animate-pulse rounded-full bg-amber-500" />
        Your scheduler is waiting for your OK
      </div>
      <p className="mt-1.5 text-amber-800 dark:text-amber-200/90">{state.reason}</p>
      <div className="mt-3">
        <div className="text-xs uppercase tracking-wide text-amber-700/80 dark:text-amber-300/70">
          Confirmation phrase
        </div>
        <div className="mt-0.5 select-all font-mono text-base font-semibold text-amber-950 dark:text-amber-50">
          {state.code}
        </div>
      </div>
      <p className="mt-3 text-xs leading-relaxed text-amber-700 dark:text-amber-300/80">
        Requested {relative(state.requestedAt)}. Approve in <b>Pricing Studio</b> — reply to the
        proof DM whose phrase matches this one. If you can't find a DM with this exact phrase,
        don't approve it.
      </p>
      <div className="mt-3 flex flex-wrap items-center gap-3">
        <button
          onClick={() => void checkNow()}
          disabled={busy}
          className="rounded-lg bg-amber-600 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-amber-500 disabled:opacity-60"
        >
          {busy ? "Checking…" : "I've approved — check now"}
        </button>
        {poked && !busy && (
          <span className="text-xs text-amber-700 dark:text-amber-300/80">
            Still waiting — give your reply a moment to land, then check again.
          </span>
        )}
      </div>
    </div>
  );
}
