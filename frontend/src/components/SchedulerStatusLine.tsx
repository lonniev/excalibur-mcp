// The scheduler status line: one dot, one label, and the badges that qualify it.
//
// Renders as a FRAGMENT, not a box, so each surface supplies its own container:
// Posts wraps it in a button (click to refresh), Scheduler in a plain span beside
// the page title. That is the only thing the two are allowed to differ on — what
// the badges say, and when they appear, is decided here for both.
//
// The three counts are disjoint by construction, which is what makes showing them
// side by side honest: claiming a post sets it Sending (so it leaves the Soon
// query), and `upcoming` counts only `publish_at > now` (so the overdue posts in
// Retrying are excluded too). No post is ever counted twice.

import type { SchedulerState } from "../lib/schedulerState";

const DOT: Record<SchedulerState["health"], string> = {
  loading: "bg-zinc-400",
  healthy: "bg-green-500",
  cutoff: "bg-red-500",
  quiet: "bg-amber-400",
  stalled: "bg-red-500",
  unknown: "bg-zinc-400",
};

const LABEL: Record<SchedulerState["health"], string> = {
  loading: "Scheduler…",
  healthy: "Scheduler healthy",
  cutoff: "Scheduler cut off",
  quiet: "Scheduler quiet",
  stalled: "Scheduler stalled",
  unknown: "Scheduler status unknown",
};

const CHIP = "rounded-full px-1.5 text-[10px]";

export default function SchedulerStatusLine({
  state,
  /** Hide the "Scheduler healthy" text on narrow screens (toolbar use). */
  collapseLabel = false,
}: {
  state: SchedulerState;
  collapseLabel?: boolean;
}) {
  const { health, resolving, stuck, soon } = state;
  const pulse = health === "healthy" || health === "quiet";
  // Every badge must name a real Post status and land you on that Posts filter —
  // "publishing" and "not posted" were earlier inventions here, and a name with
  // nowhere to click is what makes a post hard to track down.
  //
  // The rule was written when a Post was one of six things; #318 made it eight by
  // splitting publishing into Resolving and Resolved. This badge kept saying
  // "Sending" for a post being BUILT, so it pointed at a filter that correctly
  // showed nothing — the badge and the list beside it disagreeing in plain sight.
  // The statuses are the vocabulary; a badge does not get to coin its own.
  //
  // The held badge is the one deliberate exception. It counts a SUBSET of
  // Scheduled — the ones that tried and were held — so labelling it "Scheduled"
  // read as the whole rotation and undercounted it: "3 Scheduled" beside a dozen
  // scheduled posts looks like a bug in the badge. It says "Retrying" instead,
  // which is what those posts are doing and matches the words the Posts list
  // already uses ("X didn't answer — retrying"). Its tooltip still names the
  // Scheduled filter, so the click-through the rule protects is intact.
  const held = stuck.filter((p) => !p.paused);
  const paused = stuck.filter((p) => p.paused);

  return (
    <>
      <span className={`inline-block h-2 w-2 rounded-full ${DOT[health]} ${pulse ? "animate-pulse" : ""}`} />
      <span className={collapseLabel ? "hidden sm:inline" : undefined}>{LABEL[health]}</span>

      {resolving.length > 0 && (
        <span
          className={`${CHIP} bg-sky-500/15 text-sky-600 dark:text-sky-400`}
          title={`A worker is building the body of ${resolving.join(", ")} right now. Filter Posts by Resolving to see it.`}
        >
          {resolving.length} Resolving
        </span>
      )}

      {held.length > 0 && (
        <span
          className={`${CHIP} bg-amber-500/15 text-amber-700 dark:text-amber-400`}
          title={`Held on the last run, still Scheduled and due to retry: ${held
            .map((p) => `${p.id} (${p.reason})`)
            .join("; ")}. Filter Posts by Scheduled — each one carries the same ⚠ marker.`}
        >
          ⚠ Retrying {held.length}
        </span>
      )}

      {/* The calm-state counterpart to the warning badges: when nothing is wrong
          there is still something worth knowing, and "Scheduler healthy" alone
          never said whether anything was actually queued. Suppressed unless
          healthy, because a forecast read off a tick that may not run is a
          promise the badge cannot keep. */}
      {health === "healthy" && soon > 0 && (
        <span
          className={`${CHIP} bg-stone-500/10 text-stone-600 dark:bg-zinc-400/15 dark:text-zinc-300`}
          title={`${soon} post${soon === 1 ? "" : "s"} queued ahead, as of the last tick. Filter Posts by Scheduled to see them.`}
        >
          ⓘ {soon} Soon
        </span>
      )}

      {paused.length > 0 && (
        <span
          className={`${CHIP} bg-rose-500/15 text-rose-600 dark:text-rose-400`}
          title={`Stopped until you resume them: ${paused
            .map((p) => `${p.id} (${p.reason})`)
            .join("; ")}. Filter Posts by Paused.`}
        >
          ⏸ {paused.length} Paused
        </span>
      )}
    </>
  );
}
