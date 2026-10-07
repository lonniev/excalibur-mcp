import type { MouseEvent } from "react";
import { BADGE_LABEL, flipOf, type Flip } from "../lib/readiness";

// One badge for a post's state, everywhere a post is seen or edited. Where a
// person may flip it (Draft ↔ Ready, Paused → Ready, a stuck Sending → Draft)
// it is a button; otherwise it is a label. Same pill either way, so the eye
// learns one shape.

const STYLE: Record<string, string> = {
  draft: "bg-stone-100 text-stone-600 dark:bg-zinc-800 dark:text-zinc-300",
  scheduled: "bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-400",
  // Building the body: a worker is resolving this post's dynamic blocks. The
  // slow phase — minutes, not milliseconds — so it pulses.
  resolving: "bg-violet-100 text-violet-700 dark:bg-violet-500/15 dark:text-violet-400 animate-pulse",
  // Built and waiting for its moment. Nothing is running; the text is final and
  // the next tick will send it.
  resolved: "bg-teal-100 text-teal-700 dark:bg-teal-500/15 dark:text-teal-400",
  // Transient: the scheduler has claimed this finished body and is posting it
  // right now. Milliseconds, so this is rarely seen.
  sending: "bg-sky-100 text-sky-700 dark:bg-sky-500/15 dark:text-sky-400 animate-pulse",
  // A "needs attention" stop-state: the scheduler paused this post after a
  // non-transient failure (e.g. a lapsed X subscription). Distinct from the
  // grey draft fallback so it reads as actionable, not idle.
  paused: "bg-rose-100 text-rose-700 dark:bg-rose-500/15 dark:text-rose-400",
  sent: "bg-green-100 text-green-700 dark:bg-green-500/15 dark:text-green-400",
  archived: "bg-stone-100 text-stone-400 dark:bg-zinc-800 dark:text-zinc-500",
};

const FLIP_TITLE: Record<Flip, string> = {
  scheduled: "Mark Ready — the scheduler posts it at its publish time",
  draft: "Return to Draft — it won't post until you mark it Ready again",
};

export default function ReadinessBadge({
  status, onFlip, busy = false, caution,
}: {
  status: string;
  /** Receives the wire status to persist. Omit to render a label only. */
  onFlip?: (next: Flip) => void;
  busy?: boolean;
  /** Extra line for the tooltip — e.g. a pause that may already be live on X. */
  caution?: string;
}) {
  const label = BADGE_LABEL[status] ?? status;
  const style = STYLE[status] ?? STYLE.draft;
  const next = onFlip ? flipOf(status) : null;
  const pill = `inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs ${style}`;
  if (!next) return <span className={pill}>{label}</span>;
  const title = caution ? `${FLIP_TITLE[next]}\n\n${caution}` : FLIP_TITLE[next];
  const click = (e: MouseEvent) => { e.stopPropagation(); e.preventDefault(); onFlip!(next); };
  return (
    <button
      type="button"
      onClick={click}
      disabled={busy}
      title={title}
      aria-label={`${label} — ${FLIP_TITLE[next]}`}
      className={`${pill} ring-1 ring-inset ring-current/30 transition-opacity hover:opacity-80 disabled:opacity-50 ${busy ? "animate-pulse" : ""}`}
    >
      {label}
      <span aria-hidden className="text-[10px] opacity-60">⇄</span>
    </button>
  );
}
