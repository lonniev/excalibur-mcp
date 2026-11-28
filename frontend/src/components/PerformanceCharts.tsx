// The Performance page's charts: your last posts against your typical post,
// the format mix, and the daily trend of followers and median views.

import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { languageLocale } from "@tollbooth-dpyc/web";
import { useT } from "../i18n";
import type { FollowerReading, PerformancePost } from "../lib/mcp";
import {
  dailyMedianViews,
  followerTrend,
  type FormatMixRow,
  type LastPostsChart,
  type TrendPoint,
} from "../lib/performanceCharts";
import { formatLinkPlacement } from "../lib/performanceTable";
import { formatPostedShort } from "../lib/timezone";

function fmt(n: number): string {
  return Math.round(n).toLocaleString(languageLocale());
}

// ── Last posts ──────────────────────────────────────────────────────────────

const LAST_H = 140; // px of bar area

export function LastPostsBars({ chart, timeZone }: { chart: LastPostsChart; timeZone: string }) {
  const t = useT();
  const nav = useNavigate();
  const { bars, typical, top, clippedBest } = chart;
  const typicalPx = typical != null ? (typical / top) * LAST_H : null;

  return (
    <div data-testid="last-posts-chart">
      <div className="relative" style={{ height: LAST_H + 14 }}>
        {typicalPx != null ? (
          <div
            className="pointer-events-none absolute inset-x-0 border-t border-dashed border-stone-400 dark:border-zinc-500"
            style={{ bottom: typicalPx }}
            aria-hidden
          >
            <span className="absolute right-0 -top-4 text-[10px] tabular-nums text-stone-500 dark:text-zinc-400">
              {t("ui.performancePage.lastTypical", { value: fmt(typical!) })}
            </span>
          </div>
        ) : null}
        <div className="absolute inset-x-0 bottom-0 flex items-end gap-0.5 sm:gap-1" style={{ height: LAST_H + 14 }}>
          {bars.map((b) => {
            const h = Math.max(2, (b.drawn / top) * LAST_H);
            const above = typical != null && b.views > typical;
            const label = t("ui.performancePage.lastBar", {
              posted: formatPostedShort(b.post.last_sent_at, timeZone),
              views: fmt(b.views),
            });
            return (
              <div key={b.post.post_id} className="flex-1 min-w-0 flex flex-col items-center justify-end h-full">
                <span className="mb-0.5 text-[9px] tabular-nums leading-none text-stone-500 dark:text-zinc-400">
                  {fmt(b.views)}
                </span>
                <button
                  type="button"
                  title={label}
                  aria-label={label}
                  onClick={() => nav(`/post/${b.post.post_id}`)}
                  className={`relative w-full max-w-[28px] rounded-t-sm cursor-pointer focus:outline-hidden focus-visible:ring-2 focus-visible:ring-amber-500 ${
                    above ? "bg-amber-500 dark:bg-amber-400" : "bg-amber-300/70 dark:bg-amber-500/50"
                  }`}
                  style={{ height: h }}
                >
                  {b.clipped ? (
                    <span
                      className="absolute inset-x-0 top-1 h-1 bg-white/80 dark:bg-zinc-900/80 -skew-y-12"
                      aria-hidden
                    />
                  ) : null}
                </button>
              </div>
            );
          })}
        </div>
      </div>
      {clippedBest != null ? (
        <p className="mt-2 text-[11px] text-right text-stone-500 dark:text-zinc-400">
          {t("ui.performancePage.lastClipped", { value: fmt(clippedBest) })}
        </p>
      ) : null}
    </div>
  );
}

// ── Format mix ──────────────────────────────────────────────────────────────

export function FormatMixTable({ rows }: { rows: FormatMixRow[] }) {
  const t = useT();
  return (
    <div className="space-y-2.5" data-testid="format-mix">
      {rows.map((r) => {
        const provisional = r.n > 0 && r.n < 3;
        return (
          <div key={r.placement} className={provisional ? "text-stone-400 dark:text-zinc-500" : ""}>
            <div className="flex items-baseline justify-between gap-3 text-sm">
              <span className="min-w-0 truncate">{formatLinkPlacement(r.placement)}</span>
              <span className="shrink-0 text-right tabular-nums text-xs">
                <span className="font-medium">{Math.round(r.share * 100)}%</span>
                <span className="mx-1.5 text-stone-300 dark:text-zinc-600">·</span>
                {t("ui.performancePage.colMedianImpressions")} {fmt(r.median)}
                <span className="mx-1.5 text-stone-300 dark:text-zinc-600">·</span>
                n={r.n}
                {provisional ? (
                  <span className="ml-1.5 text-[10px] uppercase tracking-wide">
                    {t("ui.performancePage.provisional")}
                  </span>
                ) : null}
              </span>
            </div>
            <div
              className="mt-1 h-2 rounded-full bg-stone-100 dark:bg-zinc-800 overflow-hidden"
              role="img"
              aria-label={`${formatLinkPlacement(r.placement)} ${Math.round(r.share * 100)}%`}
            >
              <div
                className="h-full rounded-full bg-amber-500 dark:bg-amber-400"
                style={{ width: `${Math.max(2, r.share * 100)}%` }}
              />
            </div>
          </div>
        );
      })}
      {rows.length === 1 ? (
        <p className="text-xs text-right text-stone-500 dark:text-zinc-400">{t("ui.performancePage.mixOnlyOne")}</p>
      ) : null}
    </div>
  );
}

// ── Daily trend ─────────────────────────────────────────────────────────────

type TrendMetric = "followers" | "following" | "views";
const RANGES = [30, 90] as const;

function TrendLine({ points }: { points: TrendPoint[] }) {
  const t = useT();
  const w = 600;
  const h = 120;
  const pad = 6;
  const vals = points.map((p) => p.value);
  const min = Math.min(...vals);
  const max = Math.max(...vals);
  const span = max - min || 1;
  const xy = points.map((p, i) => {
    const x = pad + (i / Math.max(1, points.length - 1)) * (w - 2 * pad);
    const y = h - pad - ((p.value - min) / span) * (h - 2 * pad);
    return [x, y] as const;
  });
  const line = xy.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const area = `${pad},${h - pad} ${line} ${(w - pad).toFixed(1)},${h - pad}`;
  return (
    <div>
      <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" className="w-full h-32" aria-hidden>
        <polygon points={area} className="fill-amber-500/10 dark:fill-amber-400/10" />
        <polyline
          points={line}
          fill="none"
          strokeWidth="2"
          vectorEffect="non-scaling-stroke"
          strokeLinejoin="round"
          className="stroke-amber-500 dark:stroke-amber-400"
        />
        {xy.map(([x, y], i) => (
          <circle key={points[i]!.date} cx={x} cy={y} r="3" className="fill-amber-500 dark:fill-amber-400">
            <title>{t("ui.performancePage.trendPoint", { date: points[i]!.date, value: fmt(points[i]!.value) })}</title>
          </circle>
        ))}
      </svg>
      <div className="mt-1 flex justify-between text-[10px] tabular-nums text-stone-400 dark:text-zinc-500">
        <span>
          {points[0]!.date} · {fmt(points[0]!.value)}
        </span>
        <span>
          {points[points.length - 1]!.date} · {fmt(points[points.length - 1]!.value)}
        </span>
      </div>
    </div>
  );
}

export function DailyTrend({
  history,
  posts,
  timeZone,
}: {
  history: FollowerReading[];
  posts: PerformancePost[];
  timeZone: string;
}) {
  const t = useT();
  const [metric, setMetric] = useState<TrendMetric>("followers");
  const [days, setDays] = useState<(typeof RANGES)[number]>(30);

  const points: TrendPoint[] = useMemo(
    () =>
      metric === "views"
        ? dailyMedianViews(posts, timeZone, days)
        : followerTrend(history, metric, days),
    [metric, days, history, posts, timeZone],
  );

  const tabs: { key: TrendMetric; label: string }[] = [
    { key: "followers", label: t("ui.performancePage.trendFollowers") },
    { key: "following", label: t("ui.performancePage.trendFollowing") },
    { key: "views", label: t("ui.performancePage.trendMedianViews") },
  ];
  const pill = (active: boolean) =>
    `px-2.5 py-1 rounded-md text-xs transition-colors ${
      active
        ? "bg-amber-100 text-amber-800 dark:bg-amber-500/20 dark:text-amber-300"
        : "text-stone-500 hover:text-stone-800 dark:text-zinc-400 dark:hover:text-zinc-100"
    }`;

  const firstReading = history[0]?.date;
  const followerMetric = metric !== "views";

  return (
    <div data-testid="daily-trend">
      <div className="flex flex-wrap items-center justify-end gap-2 mb-3">
        <div className="flex gap-1" role="tablist">
          {tabs.map((tab) => (
            <button
              key={tab.key}
              type="button"
              role="tab"
              aria-selected={metric === tab.key}
              onClick={() => setMetric(tab.key)}
              className={pill(metric === tab.key)}
            >
              {tab.label}
            </button>
          ))}
        </div>
        <div className="flex gap-1 rounded-lg border border-stone-200 dark:border-zinc-800 p-0.5">
          {RANGES.map((r) => (
            <button
              key={r}
              type="button"
              aria-pressed={days === r}
              onClick={() => setDays(r)}
              className={pill(days === r)}
            >
              {t(r === 30 ? "ui.performancePage.range30" : "ui.performancePage.range90")}
            </button>
          ))}
        </div>
      </div>
      {points.length >= 2 ? (
        <TrendLine points={points} />
      ) : (
        <p className="py-6 text-sm text-right text-stone-500 dark:text-zinc-400">
          {followerMetric && firstReading && history.length < 2
            ? t("ui.performancePage.trendStarted", { date: firstReading })
            : t("ui.performancePage.trendEmpty")}
        </p>
      )}
    </div>
  );
}
