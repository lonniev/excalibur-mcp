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
//
// What this card CAN do for the operator is un-stick a request that is never
// going to complete. The Worker keeps its last look for the reply; the card
// says what it found, and the operator can have a fresh request sent now
// instead of waiting out the Worker's hour on a dead one.

import { useCallback, useEffect, useState } from "react";
import { getNostrProfile, getStoredNpub } from "@tollbooth-dpyc/web";
import {
  getSchedulerPending,
  getSchedulerStatus,
  reissueSchedulerProof,
  runSchedulerCheckNow,
  type SchedulerLastCheck,
} from "../lib/mcp";
import { isDead, lastCheckLine, waitingOnLine } from "../lib/schedulerCheck";

// Profile names, looked up once per npub per page load: the card re-polls
// every few minutes and a name does not change in that time.
const names = new Map<string, Promise<string | null>>();

function nameOf(npub: string): Promise<string | null> {
  let p = names.get(npub);
  if (!p) {
    p = getNostrProfile(npub)
      .then((r) => (r.success ? r.profile?.display_name || r.profile?.name || null : null))
      .catch(() => null);
    names.set(npub, p);
  }
  return p;
}

const POLL_MS = 5 * 60 * 1000;

/** A parked scheduler as THIS viewer is entitled to see it. `code` is the
 *  operator's alone; everything else is public to any proven patron. */
interface Parked {
  isOperator: boolean;
  reason: string;
  requestedAt: number;
  code?: string;
  lastCheck?: SchedulerLastCheck | null;
  /** For a non-operator: whose approval this waits on, and who they are
   *  signed in as — so being signed in as the wrong npub is obvious. */
  waitingOn?: string;
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
  const [reissued, setReissued] = useState("");

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
    const viewer = getStoredNpub();
    if (!operator || viewer !== operator) {
      const [opName, viewerName] = operator
        ? await Promise.all([nameOf(operator), viewer ? nameOf(viewer) : Promise.resolve(null)])
        : [null, null];
      setState({
        isOperator: false, reason: auth.reason, requestedAt: auth.requestedAt,
        lastCheck: auth.lastCheck ?? null,
        waitingOn: operator
          ? waitingOnLine({ npub: operator, name: opName }, viewer ? { npub: viewer, name: viewerName } : null)
          : undefined,
      });
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
      lastCheck: pending.lastCheck ?? null,
    });
  }, []);

  // "send a fresh request": the operator can see this one is stuck — an older
  // DM answered, or a last check saying it can never complete — and has the
  // Worker drop it and DM a new phrase now. The card then shows that phrase.
  const reissue = useCallback(async () => {
    setBusy(true);
    setPoked(false);
    setReissued("");
    const r = await reissueSchedulerProof();
    await refresh();
    setBusy(false);
    setReissued(
      r.success
        ? "A fresh request is on its way. Approve the newest DM in Pricing Studio — the one whose phrase matches the one above — then check now."
        : `No fresh request was sent: ${r.error ?? "the scheduler didn't answer"}`,
    );
  }, [refresh]);

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
      {state.waitingOn && (
        <p className="mt-1.5 text-xs font-medium text-amber-900 dark:text-amber-100">{state.waitingOn}</p>
      )}

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
            proof DM whose phrase matches this one; a reply to any older DM does not count. If you
            can't find a DM with this exact phrase, don't approve it — send a fresh request instead.
          </>
        ) : (
          <>
            Requested {relative(state.requestedAt)}. Nothing goes out until the operator replies —
            only they can approve it. If you know they already have, check now and the scheduler
            picks it up instead of waiting for the next run.
          </>
        )}
      </p>

      {lastCheckLine(state.lastCheck) && (
        <p className="mt-2 text-xs leading-relaxed text-amber-800 dark:text-amber-200/90">
          {lastCheckLine(state.lastCheck)}
          {isDead(state.lastCheck) &&
            (state.isOperator
              ? " A fresh request goes out on the next check — or send one now."
              : " A fresh request goes out on the next check.")}
        </p>
      )}

      <div className="mt-3 flex flex-wrap items-center gap-3">
        <button
          onClick={() => void checkNow()}
          disabled={busy}
          className="rounded-lg bg-amber-600 px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-amber-500 disabled:opacity-60"
        >
          {busy ? "Checking…" : state.isOperator ? "I've approved — check now" : "Check now"}
        </button>
        {state.isOperator && (
          <button
            onClick={() => void reissue()}
            disabled={busy}
            className="rounded-lg border border-amber-600/60 px-3 py-1.5 text-xs font-medium text-amber-800 transition-colors hover:bg-amber-100 disabled:opacity-60 dark:text-amber-200 dark:hover:bg-amber-900/40"
          >
            Send a fresh request
          </button>
        )}
        {poked && !busy && (
          <span className="text-xs text-amber-700 dark:text-amber-300/80">
            Still waiting — give the reply a moment to land, then check again.
          </span>
        )}
      </div>
      {reissued && !busy && (
        <p className="mt-2 text-xs leading-relaxed text-amber-800 dark:text-amber-200/90">{reissued}</p>
      )}
    </div>
  );
}
