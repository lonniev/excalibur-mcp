// On-screen MCP activity log, ported from taxsort-mcp. A fixed bottom bar that
// shows every MCP call/result/error so you can see what the FE is doing —
// invaluable for diagnosing "Post does nothing" and the OAuth flow.
//
// It also surfaces the Cloudflare cron Worker's traffic, which is otherwise
// invisible here: "Scheduler ↻" pulls recent process_scheduled_posts ticks
// (operator-only) and merges each run — with its per-post skip/error reasons —
// into this same log. Auto re-polls every 60s while the panel is open.

import { useEffect, useRef, useState } from "react";
import { clearDebug, debugPush, useDebugLog, type DebugEntry } from "../lib/debugLog";
import { getSchedulerLog, type SchedulerOutcome, type SchedulerRun } from "../lib/mcp";

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
const outcome = (e: SchedulerOutcome, verb: string) =>
  `  ↳ ${short(e.post_id)} ${verb}${e.reason ? `:${e.reason}` : ""}${e.tweet_url ? ` ${e.tweet_url}` : ""}`;

// Render one scheduler tick into the log. debugPush prepends, so we push the
// detail lines first and the header last — the header lands above its details,
// and the newest run (processed last by the caller) lands at the top.
function pushRun(run: SchedulerRun): void {
  const s = run.summary ?? {};
  const posted = s.posted ?? [];
  const skipped = s.skipped ?? [];
  const errors = s.errors ?? [];
  for (const e of errors) debugPush("error", outcome(e, "err"));
  for (const e of skipped) debugPush("error", outcome(e, "skip"));
  for (const e of posted) debugPush("result", `  ↳ ${short(e.post_id)} → ${e.next_status ?? "sent"}${e.tweet_url ? ` ${e.tweet_url}` : ""}`);
  const bad = skipped.length + errors.length > 0;
  let when = run.run_at;
  try {
    when = new Date(run.run_at).toLocaleTimeString();
  } catch {
    /* keep raw */
  }
  debugPush(
    bad ? "error" : "result",
    `scheduler ${when} · processed=${s.processed ?? 0} posted=${posted.length} skipped=${skipped.length} errors=${errors.length}`,
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
      if (!silent && fresh.length === 0) debugPush("info", "scheduler: no new ticks");
    } catch {
      // Operator-only: a patron-only session (or missing proof) just sees nothing.
      if (!silent) debugPush("info", "scheduler log unavailable — sign in as the operator");
    } finally {
      setBusy(false);
    }
  }

  // Auto re-poll every 60s while the panel is open and auto is on.
  useEffect(() => {
    if (!open || !auto) return;
    void loadScheduler(true);
    const id = window.setInterval(() => void loadScheduler(true), 60_000);
    return () => window.clearInterval(id);
  }, [open, auto]);

  function handleClear(): void {
    clearDebug();
    seen.current.clear(); // allow ticks to re-render after a manual clear
  }

  return (
    <div className="fixed bottom-0 left-0 right-0 z-50">
      <div className="absolute bottom-0 right-3 flex gap-1">
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
        <div className="max-h-64 overflow-y-auto border-t border-zinc-700 bg-zinc-950/95 p-3 font-mono text-xs backdrop-blur">
          {log.length === 0 && <div className="text-zinc-500">No MCP activity yet.</div>}
          {log.map((entry, i) => {
            const failed = isFailure(entry);
            return (
              <div
                key={i}
                className={`flex gap-2 py-0.5 ${failed ? "-mx-1 rounded bg-red-950/60 px-1" : ""}`}
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
