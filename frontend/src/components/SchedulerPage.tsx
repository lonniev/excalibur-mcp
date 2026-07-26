// The Scheduler tab — the cron Worker made legible. It composes three already
// npub-scoped sources, so the page itself needs no extra gate: `scheduler_status`
// (config + phase, safe for any proven patron), `scheduler_pending` (the
// operator-only approval code, via SchedulerPendingCard), and `get_scheduler_log`
// (the owner-scoped per-tick traffic log). Each tool reveals only what the
// current proofed npub is allowed to see.

import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getSchedulerStatus, getSchedulerLog, type SchedulerStatus, type SchedulerRun } from "../lib/mcp";
import SchedulerPendingCard from "./SchedulerPendingCard";

const POLL_MS = 60 * 1000;

function relative(ms: number): string {
  const secs = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (secs < 90) return `${secs}s ago`;
  const mins = Math.round(secs / 60);
  if (mins < 90) return `${mins} min ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 36) return `${hrs} h ago`;
  return `${Math.round(hrs / 24)} d ago`;
}

function until(ms: number): string {
  const secs = Math.round((ms - Date.now()) / 1000);
  if (secs <= 0) return "now";
  const days = Math.round(secs / 86400);
  if (days >= 2) return `in ${days} days`;
  const hrs = Math.round(secs / 3600);
  if (hrs >= 2) return `in ${hrs} h`;
  return `in ${Math.max(1, Math.round(secs / 60))} min`;
}

// ── health, derived from the newest tick's freshness (mirrors SchedulerHealth) ─
const FRESH_MS = 40 * 60 * 1000;
const STALE_MS = 100 * 60 * 1000;
function health(runs: SchedulerRun[]): { dot: string; label: string } {
  if (!runs.length) return { dot: "bg-amber-400", label: "No tick logged yet" };
  const age = Date.now() - new Date(runs[0].run_at).getTime();
  if (isNaN(age)) return { dot: "bg-zinc-400", label: "Status unknown" };
  if (age <= FRESH_MS) return { dot: "bg-green-500", label: "Healthy" };
  if (age <= STALE_MS) return { dot: "bg-amber-400", label: "Quiet" };
  return { dot: "bg-red-500", label: "Stalled" };
}

// "47 min" reads fine; "1387 min" does not. Hours and days once it's worth it.
function untilMins(m: number): string {
  if (m < 90) return `${m} min`;
  const h = Math.round(m / 60);
  return h < 36 ? `${h} h` : `${Math.round(h / 24)} d`;
}

// One log row, rendered by kind. A TICK is the scheduler dispatching — it never
// publishes anything, so it has no outcome to show, only what it handed off. A
// PUBLICATION is one post's result, written by the publisher that did the work.
function RunCells({ summary: s }: { summary: SchedulerRun["summary"] }) {
  const cell = "py-1.5 pr-4";
  if (s.kind === "publication") {
    const fell = s.fallbacks ?? [];
    const tone =
      s.outcome === "posted" ? "text-green-700 dark:text-green-400"
        : s.outcome === "paused" ? "text-rose-600 dark:text-rose-400"
          : "text-amber-600 dark:text-amber-400";
    return (
      <>
        <td className={`${cell} ${tone}`}>
          {s.outcome ?? "published"}
          {/* Which post. Without it the log tells you something didn't publish
              and leaves you to find it — and "held" is an attempt outcome, not
              a status, so there is no Held tab to look in. The post is still
              Scheduled (or Paused); this goes straight to it. */}
          {s.post_id && (
            <Link
              to={`/post/${s.post_id}`}
              onClick={(e) => e.stopPropagation()}
              className="ml-1.5 font-mono text-[11px] text-stone-500 underline decoration-dotted underline-offset-2 hover:text-stone-800 dark:text-zinc-400 dark:hover:text-zinc-100"
              title="Open this post"
            >
              {s.post_id.slice(0, 8)}
            </Link>
          )}
        </td>
        <td className={cell}>
          {s.reason && <span className="text-stone-600 dark:text-zinc-300">{s.reason}</span>}
          {fell.length > 0 && (
            <span
              className="ml-1.5 text-amber-600 dark:text-amber-400"
              title={`Posted, but ${fell.length === 1 ? "a dynamic block" : `${fell.length} dynamic blocks`} fell back to the author's text: ${fell
                .map((f) => `${f.reason}${f.budget_s ? ` (budget ${f.budget_s}s)` : ""}`)
                .join(", ")}`}
            >
              ⚠ {fell.length} on fallback
            </span>
          )}
          {!s.reason && !fell.length && <span className="text-stone-400">—</span>}
        </td>
      </>
    );
  }
  // A tick still open is one that was cut off before it could close its row.
  if (s.status === "started") {
    return (
      <>
        <td className={`${cell} text-stone-500 dark:text-zinc-400`}>tick</td>
        <td className={`${cell} text-amber-600 dark:text-amber-400`}>started, never finished</td>
      </>
    );
  }
  const launched = s.launched?.length ?? 0;
  const contended = s.contended?.length ?? 0;
  return (
    <>
      <td className={`${cell} text-stone-500 dark:text-zinc-400`}>tick</td>
      <td className={`${cell} text-stone-600 dark:text-zinc-300`}>
        {s.processed ? `${s.processed} due · ${launched} launched` : "nothing due"}
        {/* The forecast — what makes a quiet tick worth reading. */}
        {(() => {
          const up = s.upcoming;
          if (!up) return null;
          const text = !up.count
            ? "nothing scheduled ahead"
            : up.next_in_minutes === undefined
              ? `${up.count} ahead`
              : `next of ${up.count} in ${untilMins(up.next_in_minutes)}`;
          return <span className="ml-1.5 text-stone-500 dark:text-zinc-400">· {text}</span>;
        })()}
        {contended > 0 && (
          <span
            className="ml-1.5 text-stone-500 dark:text-zinc-400"
            title={(s.contended ?? []).map((c) => c.reason).filter(Boolean).join(", ")}
          >
            · {contended} skipped
          </span>
        )}
        {/* Which build answered — turns a row you skim past into one that can
            settle "is my deploy actually live?". */}
        {(s.who?.version || s.who?.commit) && (
          <span className="ml-1.5 text-stone-400 dark:text-zinc-500" title="The build that ran this tick">
            · {[s.who.version && `v${s.who.version}`, s.who.commit].filter(Boolean).join(" ")}
          </span>
        )}
      </td>
    </>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-3 py-1.5 text-sm">
      <div className="w-40 shrink-0 text-stone-500 dark:text-zinc-400">{label}</div>
      <div className="min-w-0 break-words text-stone-800 dark:text-zinc-100">{children}</div>
    </div>
  );
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-xl border border-stone-200 p-4 dark:border-zinc-800">
      <h2 className="mb-2 text-sm font-semibold text-stone-700 dark:text-zinc-200">{title}</h2>
      {children}
    </section>
  );
}

function authorizationLine(status: SchedulerStatus | null): string {
  const a = status?.authorization;
  if (!a) return "—";
  if (a.phase === "active") return `Authorized — renews ${until(a.expiresAt)}`;
  if (a.phase === "pending") return `Awaiting your approval (requested ${relative(a.requestedAt)})`;
  return "Idle — no authorization needed right now";
}

export default function SchedulerPage() {
  const [status, setStatus] = useState<SchedulerStatus | null>(null);
  const [runs, setRuns] = useState<SchedulerRun[]>([]);
  const [loaded, setLoaded] = useState(false);

  const refresh = useCallback(async () => {
    const [s, r] = await Promise.all([getSchedulerStatus(), getSchedulerLog(25)]);
    setStatus(s);
    setRuns(r);
    setLoaded(true);
  }, []);

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

  const h = health(runs);
  const workerDown = status?.worker === "unavailable";

  return (
    <div className="mx-auto w-[90%] max-w-[1000px] px-4 py-6">
      <div className="mb-4 flex items-center gap-3">
        <h1 className="text-lg font-semibold">Scheduler</h1>
        <span className="flex items-center gap-1.5 text-xs text-stone-500 dark:text-zinc-400">
          <span className={`inline-block h-2 w-2 rounded-full ${h.dot}`} />
          {h.label}
        </span>
        <button
          onClick={() => void refresh()}
          className="ml-auto rounded-lg px-2 py-1 text-xs text-stone-500 hover:bg-stone-100 dark:text-zinc-400 dark:hover:bg-zinc-800"
        >
          Refresh
        </button>
      </div>

      <p className="mb-4 text-sm text-stone-500 dark:text-zinc-400">
        A background worker checks for due posts on a schedule and posts them on each owner's behalf.
        It holds no keys — it renews a short-lived authorization from your npub, the same way you sign in.
      </p>

      {/* Pending approval (operator-only; renders nothing otherwise). */}
      <div className="mb-4">
        <SchedulerPendingCard />
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card title="Status">
          <Row label="Authorization">{authorizationLine(status)}</Row>
          <Row label="Last tick">{runs.length ? relative(new Date(runs[0].run_at).getTime()) : "—"}</Row>
          <Row label="Runs on">{status?.cadence ?? "—"}</Row>
          {workerDown && (
            <Row label="Worker">
              <span className="text-amber-600 dark:text-amber-400">unreachable right now</span>
            </Row>
          )}
        </Card>

        <Card title="Configuration">
          <Row label="Acts for (operator)">
            <span className="font-mono text-xs">
              {status?.operator_npub ? `${status.operator_npub.slice(0, 14)}…${status.operator_npub.slice(-6)}` : "—"}
            </span>
          </Row>
          <Row label="Cadence">{status?.cadence ?? "—"}</Row>
          <Row label="Renewal">
            {status?.renewsBeforeExpiryHours != null
              ? `re-requests ${status.renewsBeforeExpiryHours} h before the token expires`
              : "—"}
          </Row>
          <Row label="Re-nudge">
            {status?.rerequestAfterHours != null
              ? `resends the DM if unanswered for ${status.rerequestAfterHours} h`
              : "—"}
          </Row>
          <Row label="Worker version">{status?.version ?? "—"}</Row>
          <Row label="Verify venue">
            {status?.verifyAt ? (
              <a href={status.verifyAt} className="text-amber-700 underline dark:text-amber-400">
                {status.verifyAt}
              </a>
            ) : (
              "—"
            )}
          </Row>
        </Card>
      </div>

      <div className="mt-4">
        <Card title="Traffic log">
          {!loaded ? (
            <p className="text-sm text-stone-400">Loading…</p>
          ) : !runs.length ? (
            <p className="text-sm text-stone-500 dark:text-zinc-400">
              No ticks recorded yet — the scheduler logs a run each time it checks for due posts.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="text-xs uppercase tracking-wide text-stone-400 dark:text-zinc-500">
                  <tr>
                    <th className="py-1.5 pr-4 font-medium">When</th>
                    <th className="py-1.5 pr-4 font-medium">Event</th>
                    <th className="py-1.5 pr-4 font-medium">Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {runs.map((run, i) => (
                    <tr key={i} className="border-t border-stone-100 dark:border-zinc-800/70">
                      <td className="py-1.5 pr-4 whitespace-nowrap text-stone-700 dark:text-zinc-200" title={run.run_at}>
                        {relative(new Date(run.run_at).getTime())}
                      </td>
                      <RunCells summary={run.summary ?? {}} />
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
