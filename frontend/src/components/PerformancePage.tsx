import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  getPostPerformance,
  type PerformancePost,
  type PostPerformanceResult,
} from "../lib/mcp";
import RefreshButton from "./RefreshButton";

const card = "rounded-xl border border-stone-200 dark:border-zinc-800 bg-white dark:bg-zinc-900";

/** Tiny SVG sparkline from impression points (oldest → newest). */
function Sparkline({ points }: { points: { impressions?: number | null }[] }) {
  const vals = points
    .map((p) => (typeof p.impressions === "number" ? p.impressions : null))
    .filter((v): v is number => v !== null);
  if (vals.length < 2) {
    const v = vals[0];
    return (
      <span className="text-[11px] tabular-nums text-stone-400 dark:text-zinc-500">
        {v != null ? v.toLocaleString() : "—"}
      </span>
    );
  }
  const w = 72;
  const h = 22;
  const min = Math.min(...vals);
  const max = Math.max(...vals);
  const span = max - min || 1;
  const coords = vals
    .map((v, i) => {
      const x = (i / (vals.length - 1)) * w;
      const y = h - ((v - min) / span) * (h - 2) - 1;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} className="inline-block align-middle" aria-hidden>
      <polyline
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeLinecap="round"
        points={coords}
        className="text-amber-500 dark:text-amber-400"
      />
    </svg>
  );
}

function fmtRatio(n: number | null | undefined): string {
  if (n == null || Number.isNaN(n)) return "—";
  return `${n.toFixed(2)}×`;
}

function fmtInt(n: number | null | undefined): string {
  if (n == null || Number.isNaN(n)) return "—";
  return n.toLocaleString();
}

export default function PerformancePage() {
  const [data, setData] = useState<PostPerformanceResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await getPostPerformance();
      if (r.error) setError(r.error);
      setData(r);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const posts: PerformancePost[] = data?.posts ?? [];
  const corpus = data?.corpus;
  const cohorts = data?.cohorts?.link_placement ?? {};
  const cohortEntries = Object.entries(cohorts).sort((a, b) => b[1] - a[1]);

  return (
    <div className="max-w-5xl mx-auto px-4 py-6 space-y-5">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-lg font-semibold">Performance</h1>
          <p className="text-sm text-stone-500 dark:text-zinc-400 mt-0.5">
            Reach signals from your harvested post metrics — escape velocity, breakout ratio,
            link-placement cohorts. Snapshots are captured on a decaying cadence for 28 days after
            each send.
          </p>
        </div>
        <RefreshButton onClick={() => void refresh()} busy={loading} />
      </div>

      {error && (
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-700 dark:border-rose-500/30 dark:bg-rose-500/10 dark:text-rose-300">
          {error}
        </div>
      )}

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className={`${card} p-4`}>
          <div className="text-[11px] uppercase tracking-wide text-stone-400 dark:text-zinc-500">Posts</div>
          <div className="text-2xl font-semibold tabular-nums mt-1">
            {fmtInt(corpus?.post_count ?? posts.length)}
          </div>
        </div>
        <div className={`${card} p-4`}>
          <div className="text-[11px] uppercase tracking-wide text-stone-400 dark:text-zinc-500">Snapshots</div>
          <div className="text-2xl font-semibold tabular-nums mt-1">
            {fmtInt(corpus?.snapshot_count)}
          </div>
        </div>
        <div className={`${card} p-4`}>
          <div className="text-[11px] uppercase tracking-wide text-stone-400 dark:text-zinc-500">Median t+15m</div>
          <div className="text-2xl font-semibold tabular-nums mt-1">
            {fmtInt(corpus?.rolling_median_t15 ?? null)}
          </div>
        </div>
        <div className={`${card} p-4`}>
          <div className="text-[11px] uppercase tracking-wide text-stone-400 dark:text-zinc-500">Followers</div>
          <div className="text-2xl font-semibold tabular-nums mt-1">
            {fmtInt(data?.follower_count ?? null)}
          </div>
        </div>
      </div>

      {cohortEntries.length > 0 && (
        <div className={`${card} p-4`}>
          <h2 className="text-sm font-medium mb-3">Link-placement cohort</h2>
          <p className="text-xs text-stone-500 dark:text-zinc-400 mb-3">
            Median impressions for link-in-body vs. link-in-first-reply vs. no link — grounded in
            your corpus, not third-party claims.
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-stone-400 dark:text-zinc-500 border-b border-stone-100 dark:border-zinc-800">
                  <th className="py-1.5 pr-3 font-medium">Placement</th>
                  <th className="py-1.5 font-medium">Median impressions</th>
                </tr>
              </thead>
              <tbody>
                {cohortEntries.map(([place, med]) => (
                  <tr key={place} className="border-b border-stone-50 dark:border-zinc-900 last:border-0">
                    <td className="py-2 pr-3 capitalize">{place.replace("_", " ")}</td>
                    <td className="py-2 tabular-nums">{fmtInt(med)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className={`${card} overflow-hidden`}>
        <div className="px-4 py-3 border-b border-stone-100 dark:border-zinc-800 flex items-center justify-between">
          <h2 className="text-sm font-medium">Posts by reach</h2>
          <span className="text-xs text-stone-400 dark:text-zinc-500">
            EV = escape velocity · BR = breakout ratio
          </span>
        </div>
        {posts.length === 0 ? (
          <div className="px-4 py-10 text-center text-sm text-stone-500 dark:text-zinc-400">
            {loading ? (
              "Loading…"
            ) : (
              <>
                No harvested metrics yet. After a post is sent, snapshots land at t+15m, +1h, +6h,
                +24h, +72h, +7d, and +28d.{" "}
                <Link to="/" className="text-amber-600 dark:text-amber-400 hover:underline">
                  Back to posts →
                </Link>
              </>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-stone-400 dark:text-zinc-500 border-b border-stone-100 dark:border-zinc-800">
                  <th className="px-4 py-2 font-medium">Post</th>
                  <th className="px-3 py-2 font-medium">Curve</th>
                  <th className="px-3 py-2 font-medium text-right">Impr.</th>
                  <th className="px-3 py-2 font-medium text-right">EV</th>
                  <th className="px-3 py-2 font-medium text-right">BR</th>
                  <th className="px-3 py-2 font-medium">Link</th>
                  <th className="px-3 py-2 font-medium text-right">Clicks</th>
                </tr>
              </thead>
              <tbody>
                {posts.map((p) => (
                  <tr
                    key={p.post_id}
                    className="border-b border-stone-50 dark:border-zinc-900 last:border-0 hover:bg-stone-50 dark:hover:bg-zinc-900/60"
                  >
                    <td className="px-4 py-2.5">
                      <Link
                        to={`/post/${p.post_id}`}
                        className="font-mono text-xs text-amber-700 dark:text-amber-400 hover:underline"
                      >
                        {p.post_id.slice(0, 8)}…
                      </Link>
                    </td>
                    <td className="px-3 py-2.5">
                      <Sparkline points={p.sparkline ?? []} />
                    </td>
                    <td className="px-3 py-2.5 text-right tabular-nums">
                      {fmtInt(p.latest_impressions)}
                    </td>
                    <td
                      className={`px-3 py-2.5 text-right tabular-nums ${
                        (p.escape_velocity ?? 0) >= 1.5
                          ? "text-emerald-600 dark:text-emerald-400 font-medium"
                          : ""
                      }`}
                      title="t+15m impressions ÷ your rolling median"
                    >
                      {fmtRatio(p.escape_velocity)}
                    </td>
                    <td
                      className={`px-3 py-2.5 text-right tabular-nums ${
                        (p.breakout_ratio ?? 0) > 1.2
                          ? "text-sky-600 dark:text-sky-400 font-medium"
                          : ""
                      }`}
                      title="impressions ÷ follower count"
                    >
                      {fmtRatio(p.breakout_ratio)}
                    </td>
                    <td className="px-3 py-2.5 text-xs capitalize text-stone-500 dark:text-zinc-400">
                      {(p.link_placement || "—").replace("_", " ")}
                    </td>
                    <td className="px-3 py-2.5 text-right tabular-nums text-stone-500 dark:text-zinc-400">
                      {fmtInt(p.url_link_clicks)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
