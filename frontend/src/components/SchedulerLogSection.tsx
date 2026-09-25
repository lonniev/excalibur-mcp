// eXcalibur's own section of the shared debug panel (@tollbooth-dpyc/web's
// DebugPanel renders it above the log while the panel is open).
//
// It surfaces the Cloudflare cron Worker's traffic, which is otherwise
// invisible here: "Scheduler ↻" pulls recent process_scheduled_posts ticks
// (operator-only) and merges each run — with its per-post skip/error reasons —
// into the same page-wide log. With "auto" on it re-polls every 5 min while the
// panel is open AND the tab is visible — a hidden tab stops polling so it never
// keeps the Neon compute awake in the background.

import { useEffect, useState } from "react";
import { debugEntries, debugPush, displayTimeZone, formatTime, onDebug } from "@tollbooth-dpyc/web";
import { getSchedulerLog, type SchedulerOutcome, type SchedulerRun } from "../lib/mcp";

// Module-level, not component state: the panel unmounts this section when it
// closes, and neither the rendered ticks nor the auto choice should reset then.
const seen = new Set<string>(); // run_at values already rendered
let autoPoll = false;

// Clear empties the shared log; let ticks render again after that.
onDebug(() => {
  if (debugEntries().length === 0) seen.clear();
});

const short = (id?: string) => (id ? id.slice(0, 8) : "?");

// "47 min" reads fine; "1387 min" does not. Hours and days once it's worth it.
function humanMins(m: number): string {
  if (m < 90) return `${m} min`;
  const h = Math.round(m / 60);
  return h < 36 ? `${h} h` : `${Math.round(h / 24)} d`;
}
const outcome = (e: SchedulerOutcome, verb: string) =>
  `  ↳ ${short(e.post_id)} ${verb}${e.reason ? `:${e.reason}` : ""}${e.tweet_url ? ` ${e.tweet_url}` : ""}`;

// Render one audit-ring row into the log. The ring carries scheduler TICKS
// (dispatch: what was launched) and PUBLICATIONS (one post's outcome, written by
// the publisher that did the work). debugPush prepends, so detail lines go first
// and the header last — the header lands above its details.
function pushRun(run: SchedulerRun): void {
  const s = run.summary ?? {};
  const tz = displayTimeZone();
  const when = formatTime(run.run_at, tz) || run.run_at;

  if (s.kind === "publication") {
    const fell = s.fallbacks ?? [];
    for (const f of fell) {
      debugPush("error", `  ↳ block ${f.block} fell back: ${f.reason}${f.budget_s ? ` (budget ${f.budget_s}s)` : ""}`);
    }
    const bad = s.outcome === "held" || s.outcome === "paused";
    // Its own line, below the header — the reason is a code you skim, the
    // detail is the sentence that actually explains the hold, and cramming
    // both into one row buried the half worth reading.
    if (s.detail) debugPush(bad ? "error" : "result", `  ↳ ${s.detail}`);
    const summary = [s.reason, s.tweet_url].filter(Boolean).join(" ");
    debugPush(
      bad ? "error" : "result",
      `publish ${when} · ${short(s.post_id)} ${s.outcome ?? "?"}${summary ? ` · ${summary}` : ""}`,
    );
    return;
  }

  // Keys must track `scheduler.process_due_posts`. `launched` was read here long
  // after the scheduler stopped emitting it, so every tick logged "launched=0"
  // regardless of what actually happened.
  const posted = s.posted ?? [];
  const resolving = s.resolving ?? [];
  const contended = s.contended ?? [];
  const recovered = Object.entries(s.recovered ?? {});
  for (const e of contended) debugPush("error", outcome(e, "skip"));
  for (const [what, entries] of recovered) {
    for (const e of entries ?? []) {
      debugPush(
        what.startsWith("paused") ? "error" : "result",
        `  ↳ ${short(e.post_id)} recovered: ${what}`,
      );
    }
  }
  for (const e of posted) debugPush("result", `  ↳ ${short(e.post_id)} ${e.outcome ?? "posted"}`);
  for (const e of resolving) debugPush("result", `  ↳ ${short(e.post_id)} resolving`);
  const processed = s.processed ?? 0;
  // A processed=0 tick is the Worker's heartbeat — say so plainly, otherwise a
  // row of zeroes reads like a failure when it just means nothing was due.
  // What's coming, so the quiet tick forecasts instead of just reassuring.
  const up = s.upcoming;
  const ahead =
    !up || !up.count
      ? "nothing scheduled ahead"
      : up.next_in_minutes === undefined
        ? `${up.count} ahead`
        : `next of ${up.count} in ${humanMins(up.next_in_minutes)}`;
  const tally =
    s.status === "started"
      ? "started, never finished"
      : processed === 0
        ? `alive · nothing due · ${ahead}`
        : `did=${processed} posted=${posted.length} resolving=${resolving.length}` +
          `${recovered.length ? ` recovered=${recovered.reduce((n, [, e]) => n + (e?.length ?? 0), 0)}` : ""}` +
          ` · ${ahead}`;
  // Name the build. "alive" alone is noise you learn to skim past; "alive, and
  // it's THIS commit" is the line that settles a "did my deploy land?" question.
  const who = [s.who?.version && `v${s.who.version}`, s.who?.commit].filter(Boolean).join(" ");
  debugPush(
    contended.length || s.status === "started" ? "error" : "result",
    `scheduler ${when} · ${tally}${who ? ` · ${who}` : ""}`,
  );
}

const control =
  "min-h-10 rounded-lg border border-[var(--tb-line)] bg-[var(--tb-surface-2)] px-3 text-xs text-[var(--tb-ink)]";

export default function SchedulerLogSection() {
  const [auto, setAuto] = useState(autoPoll);
  const [busy, setBusy] = useState(false);

  async function loadScheduler(silent: boolean): Promise<void> {
    setBusy(true);
    try {
      const runs = await getSchedulerLog();
      // Render oldest→newest so the latest tick ends up on top.
      const fresh = runs.filter((r) => !seen.has(r.run_at)).reverse();
      for (const r of fresh) {
        seen.add(r.run_at);
        pushRun(r);
      }
      if (!silent && fresh.length === 0) {
        if (runs.length === 0) {
          // Genuinely empty: the scheduler has never logged a run.
          debugPush(
            "info",
            "The scheduler hasn't run yet. It checks for due posts on its own about every half hour — nothing will show here until its first run.",
          );
        } else {
          // Ticks exist; this refresh just found nothing newer. Tell the human
          // it's current and when the scheduler last ran, so the empty result
          // reads as "up to date", not "broken".
          const tz = displayTimeZone();
          const lastWhen = formatTime(runs[0].run_at, tz) || runs[0].run_at;
          debugPush(
            "info",
            `Up to date — no new scheduler runs since you last checked. It last ran at ${lastWhen} and checks again on its own about every half hour.`,
          );
        }
      }
    } catch {
      // Free + proof-gated; a failure here means the npub proof is missing/expired.
      if (!silent) debugPush("info", "scheduler log needs a valid npub proof — sign in again");
    } finally {
      setBusy(false);
    }
  }

  // Auto re-poll every 5 min while the panel is open (this section is mounted
  // only then), auto is on, AND the tab is visible. A hidden tab stops polling
  // so it never keeps the Neon compute awake in the background; it catches up
  // immediately when the tab becomes visible.
  useEffect(() => {
    if (!auto) return;
    let id: number | null = null;
    const stop = () => {
      if (id !== null) {
        window.clearInterval(id);
        id = null;
      }
    };
    const start = () => {
      if (id !== null) return;
      id = window.setInterval(() => void loadScheduler(true), 5 * 60_000);
    };
    const onVisibility = () => {
      if (document.hidden) {
        stop();
      } else {
        void loadScheduler(true);
        start();
      }
    };
    if (!document.hidden) {
      void loadScheduler(true);
      start();
    }
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      document.removeEventListener("visibilitychange", onVisibility);
      stop();
    };
  }, [auto]);

  function toggleAuto(next: boolean): void {
    autoPoll = next;
    setAuto(next);
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <button
        type="button"
        onClick={() => void loadScheduler(false)}
        disabled={busy}
        title="Pull recent scheduler-Worker ticks into the log (operator-only)"
        className={`${control} disabled:opacity-50`}
      >
        Scheduler ↻
      </button>
      <label className={`${control} flex items-center gap-2`}>
        <input type="checkbox" checked={auto} onChange={(e) => toggleAuto(e.target.checked)} />
        auto
      </label>
    </div>
  );
}
