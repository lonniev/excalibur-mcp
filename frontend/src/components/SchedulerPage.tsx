// The Scheduler tab — the cron Worker made legible. It composes three already
// npub-scoped sources, so the page itself needs no extra gate: `scheduler_status`
// (config + phase, safe for any proven patron), `scheduler_pending` (the
// operator-only approval code, via SchedulerPendingCard), and `get_scheduler_log`
// (the owner-scoped per-tick traffic log). Each tool reveals only what the
// current proofed npub is allowed to see.

import { useCallback, useEffect, useState } from "react";
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
                    <th className="py-1.5 pr-4 font-medium">Checked</th>
                    <th className="py-1.5 pr-4 font-medium">Posted</th>
                    <th className="py-1.5 pr-4 font-medium">Held / errors</th>
                  </tr>
                </thead>
                <tbody>
                  {runs.map((run, i) => {
                    const s = run.summary ?? {};
                    const posted = s.posted?.length ?? 0;
                    const held = (s.skipped?.length ?? 0) + (s.errors?.length ?? 0);
                    const reasons = [...(s.skipped ?? []), ...(s.errors ?? [])]
                      .map((o) => o.reason)
                      .filter(Boolean);
                    return (
                      <tr key={i} className="border-t border-stone-100 dark:border-zinc-800/70">
                        <td className="py-1.5 pr-4 text-stone-700 dark:text-zinc-200" title={run.run_at}>
                          {relative(new Date(run.run_at).getTime())}
                        </td>
                        <td className="py-1.5 pr-4 text-stone-600 dark:text-zinc-300">{s.processed ?? 0}</td>
                        <td className="py-1.5 pr-4 text-stone-600 dark:text-zinc-300">{posted}</td>
                        <td className="py-1.5 pr-4">
                          {held ? (
                            <span className="text-rose-600 dark:text-rose-400" title={reasons.join(", ")}>
                              {held}
                              {reasons.length ? ` · ${reasons[0]}${reasons.length > 1 ? "…" : ""}` : ""}
                            </span>
                          ) : (
                            <span className="text-stone-400">0</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
