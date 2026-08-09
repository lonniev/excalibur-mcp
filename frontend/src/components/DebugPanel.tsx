// On-screen MCP activity log, ported from taxsort-mcp. A fixed bottom bar that
// shows every MCP call/result/error so you can see what the FE is doing —
// invaluable for diagnosing "Post does nothing" and the OAuth flow.
//
// It also surfaces the Cloudflare cron Worker's traffic, which is otherwise
// invisible here: "Scheduler ↻" pulls recent process_scheduled_posts ticks
// (operator-only) and merges each run — with its per-post skip/error reasons —
// into this same log. With "auto" on it re-polls every 5 min while the panel is
// open AND the tab is visible — a hidden tab stops polling so it never keeps the
// Neon compute awake in the background.

import { useEffect, useRef, useState } from "react";
import { clearDebug, debugPush, useDebugLog, type DebugEntry } from "../lib/debugLog";
import { getSchedulerLog, type SchedulerOutcome, type SchedulerRun } from "../lib/mcp";
import { formatTime, resolveTimeZone, readStoredTimezonePref } from "../lib/timezone";

const TYPE_COLOR: Record<DebugEntry["type"], string> = {
  info: "text-sky-400",
  call: "text-amber-400",
  result: "text-green-400",
  error: "text-red-400",
};

function isFailure(entry: DebugEntry): boolean {
  if (entry.type === "error") return true;
  if (entry.type === "result") {
    const m = entry.message;
    return m.includes('"success":false') || m.includes('"error"') || m.includes("error_code");
  }
  return false;
}

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
  const tz = resolveTimeZone(readStoredTimezonePref());
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

export default function DebugPanel() {
  const log = useDebugLog();
  const [open, setOpen] = useState(false);
  const [auto, setAuto] = useState(false);
  const [busy, setBusy] = useState(false);
  const seen = useRef<Set<string>>(new Set()); // run_at values already rendered

  const errorCount = log.filter(isFailure).length;

  async function loadScheduler(silent: boolean): Promise<void> {
    setBusy(true);
    try {
      const runs = await getSchedulerLog();
      // Render oldest→newest so the latest tick ends up on top.
      const fresh = runs.filter((r) => !seen.current.has(r.run_at)).reverse();
      for (const r of fresh) {
        seen.current.add(r.run_at);
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
          const tz = resolveTimeZone(readStoredTimezonePref());
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

  // Auto re-poll every 5 min while the panel is open, auto is on, AND the tab is
  // visible. A hidden tab stops polling so it never keeps the Neon compute awake
  // in the background; it catches up immediately when the tab becomes visible.
  useEffect(() => {
    if (!open || !auto) return;
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
  }, [open, auto]);

  function handleClear(): void {
    clearDebug();
    seen.current.clear(); // allow ticks to re-render after a manual clear
  }

  return (
    <div className="fixed bottom-0 left-0 right-0 z-50 flex flex-col items-end">
      {/* Control bar — always in flow ABOVE the panel, so the minimize (Hide)
          tab is never overlapped by the expanded log. */}
      <div className="flex gap-1 pr-3">
        {open && (
          <>
            <button
              onClick={() => void loadScheduler(false)}
              disabled={busy}
              title="Pull recent scheduler-Worker ticks into the log (operator-only)"
              className="rounded-t-lg bg-indigo-700 px-3 py-1 text-xs text-zinc-100 hover:bg-indigo-600 disabled:opacity-50"
            >
              Scheduler ↻
            </button>
            <label className="flex items-center gap-1 rounded-t-lg bg-zinc-700 px-2 py-1 text-xs text-zinc-200">
              <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} />
              auto
            </label>
            <button
              onClick={handleClear}
              className="rounded-t-lg bg-zinc-700 px-3 py-1 text-xs text-zinc-200 hover:bg-zinc-600"
            >
              Clear
            </button>
          </>
        )}
        <button
          onClick={() => setOpen(!open)}
          className={`rounded-t-lg px-3 py-1 text-xs text-white ${
            errorCount > 0 ? "bg-red-700 hover:bg-red-600" : "bg-zinc-800 hover:bg-zinc-700"
          }`}
        >
          {open ? "Hide" : "Debug"} ({log.length}
          {errorCount > 0 ? ` · ${errorCount} err` : ""})
        </button>
      </div>
      {open && (
        <div className="max-h-64 w-full overflow-y-auto border-t border-zinc-700 bg-zinc-950/95 p-3 font-mono text-xs backdrop-blur-sm">
          {log.length === 0 && <div className="text-zinc-500">No MCP activity yet.</div>}
          {log.map((entry, i) => {
            const failed = isFailure(entry);
            return (
              <div
                key={i}
                className={`flex gap-2 py-0.5 ${failed ? "-mx-1 rounded-sm bg-red-950/60 px-1" : ""}`}
              >
                <span className="shrink-0 text-zinc-600">{entry.ts}</span>
                <span className={`w-12 shrink-0 ${failed ? "font-bold text-red-400" : TYPE_COLOR[entry.type]}`}>
                  {entry.type}
                  {failed && entry.type !== "error" ? " !" : ""}
                </span>
                <span className={`break-all ${failed ? "text-red-300" : "text-zinc-300"}`}>{entry.message}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
