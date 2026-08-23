// The Device-Grant "second surface" for the scheduled-post Worker.
//
// When the cron Worker's authorization lapses it DMs the operator a challenge
// phrase and parks. Asleep-at-3am, the operator later needs to know WHAT asked
// and prove it's their own scheduler, not a well-timed impostor. This card is
// that proof: it shows — owner-private, fed from the Worker's own KV — the same
// phrase the DM carries. Matching the two is the approval gate. If the phrase
// here doesn't appear in any DM, the operator should NOT approve.
//
// Two viewers, two different needs:
//
//   The OPERATOR sees the phrase, because they are the one about to approve and
//   the phrase is what they match the DM against. That read stays gated to the
//   operator npub (`scheduler_pending`) — an impostor learning the phrase is
//   exactly the attack this card exists to defeat.
//
//   A PATRON sees that the scheduler is parked, and nothing secret. Their posts
//   are the ones not going out, so hiding the whole situation from them (which
//   this card used to do — it rendered null for every non-operator) left the
//   person most affected staring at a red "Stalled" dot with no explanation and
//   no move to make. They get the one move that is legitimately theirs: "the
//   operator says they approved — go look now." That poke carries no authority.
//
// Approval itself always happens in Pricing Studio — the operator nsec that
// signs the reply lives there, not in this browser.

import { useCallback, useEffect, useState } from "react";
import {
  getSchedulerPending,
  getSchedulerStatus,
  getStoredNpub,
  runSchedulerCheckNow,
} from "../lib/mcp";

const POLL_MS = 5 * 60 * 1000;

/** A parked scheduler as THIS viewer is entitled to see it. `code` is the
 *  operator's alone; everything else is public to any proven patron. */
interface Parked {
  isOperator: boolean;
  reason: string;
  requestedAt: number;
  code?: string;
}

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
  const [state, setState] = useState<Parked | null>(null);
  const [busy, setBusy] = useState(false);
  const [poked, setPoked] = useState(false);

  const refresh = useCallback(async () => {
    // `scheduler_status` is free to any proven patron and already carries the
    // phase, the reason, and when it was asked — everything but the phrase. So
    // the shared facts come from there, and the operator-only call is made only
    // when the viewer IS the operator. Asking for the phrase as a patron would
    // just log a misleading "proof cache invalid" error every poll.
    const status = await getSchedulerStatus();
    const auth = status?.authorization;
    if (auth?.phase !== "pending") {
      setState(null);
      return;
    }
    const operator = status?.operator_npub;
    if (!operator || getStoredNpub() !== operator) {
      setState({ isOperator: false, reason: auth.reason, requestedAt: auth.requestedAt });
      return;
    }
    const pending = await getSchedulerPending();
    if (pending?.phase !== "pending") {
      setState(null);
      return;
    }
    setState({
      isOperator: true,
      reason: pending.reason,
      requestedAt: pending.requestedAt,
      code: pending.code,
    });
  }, []);

  // "check now": poke the scheduler to run a tick immediately so it claims the
  // reply instead of waiting for the next cron. The Worker runs the tick in the
  // background; give it a moment, then refresh — if it completed, the phase
  // flips and this card disappears.
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

  if (!state) return null;

  return (
    <div
      role="status"
      className="rounded-xl border border-amber-300/70 bg-amber-50 p-4 text-sm text-amber-900 dark:border-amber-500/40 dark:bg-amber-950/40 dark:text-amber-100"
    >
      <div className="flex items-center gap-2 font-medium">
        <span className="inline-block h-2 w-2 animate-pulse rounded-full bg-amber-500" />
        {state.isOperator
          ? "Your scheduler is waiting for your OK"
          : "Scheduled posts are paused until the operator approves"}
      </div>
      <p className="mt-1.5 text-amber-800 dark:text-amber-200/90">{state.reason}</p>

      {state.isOperator && (
        <div className="mt-3">
          <div className="text-xs uppercase tracking-wide text-amber-700/80 dark:text-amber-300/70">
            Confirmation phrase
          </div>
          <div className="mt-0.5 select-all font-mono text-base font-semibold text-amber-950 dark:text-amber-50">
            {state.code}
          </div>
        </div>
      )}

      <p className="mt-3 text-xs leading-relaxed text-amber-700 dark:text-amber-300/80">
        {state.isOperator ? (
          <>
            Requested {relative(state.requestedAt)}. Approve in <b>Pricing Studio</b> — reply to the
            proof DM whose phrase matches this one. If you can't find a DM with this exact phrase,
            don't approve it.
          </>
        ) : (
          <>
            Requested {relative(state.requestedAt)}. Nothing goes out until the operator replies —
            only they can approve it. If you know they already have, check now and the scheduler
            picks it up instead of waiting for the next run.
          </>
        )}
      </p>

      <div className="mt-3 flex flex-wrap items-center gap-3">
        <button
          onClick={() => void checkNow()}
          disabled={busy}
          className="rounded-lg bg-amber-600 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-amber-500 disabled:opacity-60"
        >
          {busy ? "Checking…" : state.isOperator ? "I've approved — check now" : "Check now"}
        </button>
        {poked && !busy && (
          <span className="text-xs text-amber-700 dark:text-amber-300/80">
            Still waiting — give the reply a moment to land, then check again.
          </span>
        )}
      </div>
    </div>
  );
}
