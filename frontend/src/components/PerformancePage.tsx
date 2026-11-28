import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { Link, useNavigate } from "react-router-dom";
import {
  BarChart3,
  Bookmark,
  Camera,
  Clock,
  Eye,
  FileText,
  Flame,
  Info,
  LineChart,
  Link2,
  MessageCircle,
  Quote,
  Rocket,
  TrendingUp,
  UserRound,
  Users,
} from "lucide-react";
import {
  getPostPerformance,
  type CohortBucket,
  type PerformancePost,
  type PostPerformanceResult,
} from "../lib/mcp";
import {
  formatLinkClicks,
  nextPerfSort,
  perfSortColumn,
  sortPerformancePosts,
  type PerfSortDir,
  type PerfSortKey,
} from "../lib/performanceTable";
import { formatHourLabel, languageLocale } from "@tollbooth-dpyc/web";
import { tr, useT } from "../i18n";
import { formatPostedShort, postsHrefForLocalHour, timeOfDayCohortInZone } from "../lib/timezone";
import { QuoteScroller, useTimezone } from "@tollbooth-dpyc/web/react";
import { QUOTES } from "../lib/quotes";
import { quoteStyles } from "../lib/quoteStyles";
import { RefreshButton } from "@tollbooth-dpyc/web/react";
import { refreshStyles } from "../lib/packageStyles";
import { followRatio, formatMix, lastPostsChart } from "../lib/performanceCharts";
import { DailyTrend, FormatMixTable, LastPostsBars } from "./PerformanceCharts";

const card = "rounded-xl border border-stone-200 dark:border-zinc-800 bg-white dark:bg-zinc-900";

// Plain-language definitions (catalog keys) — sourced from metrics_harvest.py, not paraphrased
// from the labels. One Tip treatment is used on summary widgets, table headers,
// and cells so the reader never has to re-learn where the explanation lives.
const TIPS = {
  posts: "ui.performancePage.tipPosts",
  snapshots: "ui.performancePage.tipSnapshots",
  medianT15: "ui.performancePage.tipMedianT15",
  followers: "ui.performancePage.tipFollowers",
  escapeVelocity: "ui.performancePage.tipEscapeVelocity",
  breakoutRatio: "ui.performancePage.tipBreakoutRatio",
  trend: "ui.performancePage.tipTrend",
  linkPlacement: "ui.performancePage.tipLinkPlacement",
  profileClicks: "ui.performancePage.tipProfileClicks",
  bookmarks: "ui.performancePage.tipBookmarks",
  replyRate: "ui.performancePage.tipReplyRate",
  quoteToRepost: "ui.performancePage.tipQuoteToRepost",
  timeOfDay: "ui.performancePage.tipTimeOfDay",
  last: "ui.performancePage.tipLast",
  viewsPerFollower: "ui.performancePage.tipViewsPerFollower",
  engagement: "ui.performancePage.tipEngagement",
  trendDaily: "ui.performancePage.tipTrendDaily",
} as const;

const TIP_W = 256; // px — must match the w-64 on the panel
const TIP_GAP = 6; // px between the ⓘ and the panel
const TIP_MARGIN = 8; // px kept clear of the viewport edge

/** Normalize API cohort bucket (new {median,n} or legacy bare number). */
function cohortBucket(raw: CohortBucket | number | undefined | null): CohortBucket | null {
  if (raw == null) return null;
  if (typeof raw === "number") {
    if (Number.isNaN(raw)) return null;
    return { median: raw, n: 0 };
  }
  const median = typeof raw.median === "number" ? raw.median : Number(raw.median);
  const n = typeof raw.n === "number" ? raw.n : Number(raw.n);
  if (Number.isNaN(median)) return null;
  return { median, n: Number.isNaN(n) ? 0 : n };
}

/**
 * Hover / focus annotation with a real design (not a bare title= attribute).
 *
 * The panel is portalled to <body> and positioned `fixed` from the trigger's
 * client rect. An in-flow `absolute` panel cannot work here: every ⓘ in the two
 * tables lives inside `overflow-x-auto` — which computes `overflow-y: auto`, so
 * the scroll container clips vertically too — nested in an `overflow-hidden`
 * card. Those ancestors clipped the panel away entirely even though it did
 * reach `opacity: 1`. Portalling also lets the panel be clamped to the viewport,
 * which a `-translate-x-1/2` panel hanging off a right-edge column cannot be.
 */
function Tip({ label, children }: { label: string; children: ReactNode }) {
  const ref = useRef<HTMLSpanElement>(null);
  const [pos, setPos] = useState<{ left: number; top: number; flip: boolean } | null>(null);

  const place = useCallback(() => {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const left = Math.min(
      Math.max(r.left + r.width / 2 - TIP_W / 2, TIP_MARGIN),
      Math.max(window.innerWidth - TIP_W - TIP_MARGIN, TIP_MARGIN),
    );
    // Flip above when a panel below would run past the viewport bottom. 96px is
    // a generous height for the longest TIPS string at this width.
    const flip = r.bottom + TIP_GAP + 96 > window.innerHeight;
    setPos({ left, top: flip ? r.top - TIP_GAP : r.bottom + TIP_GAP, flip });
  }, []);

  // While open, follow the trigger: `fixed` coordinates go stale the moment the
  // page or an inner table scrolls. Capture phase so nested scrollers count.
  // Keyed on open/closed, not on `pos` — each reposition writes a new `pos` and
  // would otherwise re-bind the listeners on every scroll frame.
  const open = pos !== null;
  useEffect(() => {
    if (!open) return;
    const onMove = () => place();
    window.addEventListener("scroll", onMove, true);
    window.addEventListener("resize", onMove);
    return () => {
      window.removeEventListener("scroll", onMove, true);
      window.removeEventListener("resize", onMove);
    };
  }, [open, place]);

  const close = useCallback(() => setPos(null), []);

  // Touch has no hover, so the ⓘ is a tap toggle there — which means it also
  // needs a tap-outside dismissal. Ignored for inside taps so the button's own
  // onClick still decides.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: PointerEvent) => {
      if (!ref.current?.contains(e.target as Node)) close();
    };
    document.addEventListener("pointerdown", onDown);
    return () => document.removeEventListener("pointerdown", onDown);
  }, [open, close]);

  return (
    <span
      ref={ref}
      className="relative inline-flex max-w-full min-w-0 items-center gap-1"
      onPointerEnter={(e) => e.pointerType !== "touch" && place()}
      onPointerLeave={(e) => e.pointerType !== "touch" && close()}
    >
      {children}
      <button
        type="button"
        className="inline-flex text-stone-300 hover:text-stone-500 dark:text-zinc-600 dark:hover:text-zinc-400 focus:outline-hidden focus-visible:text-amber-600"
        aria-label={label}
        onFocus={place}
        onBlur={close}
        onClick={place}
        onKeyDown={(e) => e.key === "Escape" && close()}
      >
        <Info className="h-3 w-3" aria-hidden />
      </button>
      {pos
        ? createPortal(
            <span
              role="tooltip"
              aria-hidden
              style={{
                left: pos.left,
                top: pos.top,
                width: TIP_W,
                transform: pos.flip ? "translateY(-100%)" : undefined,
              }}
              className="pointer-events-none fixed z-50 rounded-lg border border-stone-200 bg-white px-2.5 py-2 text-left text-[11px] font-normal normal-case tracking-normal leading-snug text-stone-600 shadow-lg dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-300"
            >
              {label}
            </span>,
            document.body,
          )
        : null}
    </span>
  );
}

/** Summary widget: Material-style lucide glyph + label + value, centered. */
function StatCard({
  icon,
  label,
  value,
  tip,
  unit,
  sub,
}: {
  icon: ReactNode;
  label: string;
  value: string;
  tip: string;
  unit?: string;
  /** Context under the value: a baseline, a ratio, a change. */
  sub?: ReactNode;
}) {
  return (
    <div className={`${card} p-4 text-center`}>
      <div className="flex items-center justify-center gap-1.5 text-stone-400 dark:text-zinc-500">
        <span className="text-amber-600 dark:text-amber-400" aria-hidden>
          {icon}
        </span>
        <Tip label={tip}>
          <span className="text-[11px] uppercase tracking-wide">{label}</span>
        </Tip>
      </div>
      <div className="text-2xl font-semibold tabular-nums mt-2">
        {value}
        {unit ? (
          <span className="ml-1 text-xs font-normal text-stone-400 dark:text-zinc-500">
            {unit}
          </span>
        ) : null}
      </div>
      {sub ? (
        <div className="mt-1 text-[11px] tabular-nums text-stone-500 dark:text-zinc-400 space-y-0.5">{sub}</div>
      ) : null}
    </div>
  );
}

/** Card shell shared by the chart sections: centered icon + tipped heading + intro. */
function ChartCard({
  icon,
  title,
  tip,
  intro,
  children,
}: {
  icon: ReactNode;
  title: string;
  tip: string;
  intro?: string;
  children: ReactNode;
}) {
  return (
    <div className={`${card} p-4`}>
      <div className="flex items-center justify-center gap-2 mb-1">
        <span className="text-amber-600 dark:text-amber-400" aria-hidden>
          {icon}
        </span>
        <Tip label={tip}>
          <h2 className="text-sm font-medium">{title}</h2>
        </Tip>
      </div>
      {intro ? (
        <p className="text-xs text-stone-500 dark:text-zinc-400 mb-3 text-center">{intro}</p>
      ) : (
        <div className="mb-3" />
      )}
      {children}
    </div>
  );
}

/** Signed whole number: "+13", "−4", "0". */
function fmtSigned(n: number): string {
  const abs = Math.abs(n).toLocaleString(languageLocale());
  return n > 0 ? `+${abs}` : n < 0 ? `−${abs}` : abs;
}

/** Tiny SVG sparkline from impression points (oldest → newest). */
function Sparkline({ points }: { points: { impressions?: number | null }[] }) {
  const vals = points
    .map((p) => (typeof p.impressions === "number" ? p.impressions : null))
    .filter((v): v is number => v !== null);
  if (vals.length < 2) {
    const v = vals[0];
    return (
      <span className="text-[11px] tabular-nums text-stone-400 dark:text-zinc-500">
        {v != null ? v.toLocaleString(languageLocale()) : "—"}
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
  return n.toLocaleString(languageLocale());
}

/** Fraction as a percentage with one decimal (0.053 → "5.3%"). */
function fmtPct(n: number | null | undefined): string {
  if (n == null || Number.isNaN(n)) return "—";
  return `${(n * 100).toFixed(1)}%`;
}

/** Prefer title, then opening words; never lead with a hash. */
function postLabel(p: PerformancePost): string {
  const title = (p.title || "").trim();
  if (title) return title;
  const excerpt = (p.excerpt || "").trim().replace(/\s+/g, " ");
  if (excerpt) {
    return excerpt.length > 72 ? `${excerpt.slice(0, 72).trimEnd()}…` : excerpt;
  }
  return tr("ui.performancePage.untitledPost");
}

type TodBar = { localHour: number; median: number; n: number };

/**
 * Continuous 24-hour chart of median impressions by send hour in the patron's
 * IANA zone. Buckets are computed from post instants (#367) — never by
 * relabeling UTC hour keys (wrong near DST edges and the date line).
 * Empty hours stay on the axis (the gaps are the signal). n is encoded as bar
 * opacity + a count label; n<3 reads as provisional.
 *
 * #506 — bars with data are buttons that deep-link to Posts filtered to that
 * local send hour (`/?hour=HH`), so the operator can open the posts behind a bar.
 */
function TimeOfDayChart({
  buckets,
  timeZone,
}: {
  buckets: Record<string, CohortBucket | number>;
  timeZone: string;
}) {
  const t = useT();
  const nav = useNavigate();
  const bars: TodBar[] = useMemo(() => {
    const byLocal = new Map<number, TodBar>();
    for (let h = 0; h < 24; h++) {
      byLocal.set(h, { localHour: h, median: 0, n: 0 });
    }
    // Keys are already local-hour ("00"…"23") when computed via timeOfDayCohortInZone.
    for (const [key, raw] of Object.entries(buckets)) {
      const b = cohortBucket(raw);
      if (!b) continue;
      const lh = Number.parseInt(key, 10);
      if (Number.isNaN(lh) || lh < 0 || lh > 23) continue;
      const cur = byLocal.get(lh)!;
      cur.median = b.median;
      cur.n = b.n;
    }
    return Array.from(byLocal.values());
  }, [buckets]);

  const maxMed = Math.max(1, ...bars.map((b) => b.median));
  const chartH = 120;

  return (
    <div className="time-of-day-chart" data-testid="time-of-day-chart">
      <div
        className="flex items-end gap-px sm:gap-0.5 h-[120px]"
        role="list"
        aria-label={t("ui.performancePage.todAria")}
      >
        {bars.map((b) => {
          const has = b.n > 0;
          const hPx = has ? Math.max(4, (b.median / maxMed) * chartH) : 0;
          const provisional = has && b.n < 3;
          // Opacity scales with sample size; provisional stays readable but soft.
          const opacity = !has ? 0 : provisional ? 0.35 + 0.15 * b.n : Math.min(1, 0.55 + 0.15 * Math.min(b.n, 4));
          const label = formatHourLabel(b.localHour, timeZone);
          const title = has
            ? t(provisional ? "ui.performancePage.todBarProvisional" : "ui.performancePage.todBar", {
                hour: label,
                median: Math.round(b.median).toLocaleString(languageLocale()),
                n: b.n,
              })
            : t("ui.performancePage.todBarEmpty", { hour: label });
          const barClass = `w-full max-w-[18px] mx-auto rounded-t-sm ${
            provisional
              ? "bg-amber-400/80 dark:bg-amber-500/70"
              : "bg-amber-500 dark:bg-amber-400"
          } ${!has ? "bg-stone-100 dark:bg-zinc-800" : ""}`;
          const barStyle = {
            height: has ? hPx : 2,
            opacity: has ? opacity : 0.35,
          } as const;
          return (
            <div
              key={b.localHour}
              role="listitem"
              className="flex-1 min-w-0 flex flex-col items-center justify-end h-full group relative"
              title={title}
            >
              {has ? (
                <span
                  className={`mb-0.5 text-[9px] tabular-nums leading-none ${
                    provisional
                      ? "text-stone-400 dark:text-zinc-500"
                      : "text-stone-500 dark:text-zinc-400"
                  }`}
                >
                  n={b.n}
                </span>
              ) : (
                <span className="mb-0.5 text-[9px] leading-none opacity-0">n</span>
              )}
              {has ? (
                <button
                  type="button"
                  data-testid={`tod-bar-${b.localHour}`}
                  aria-label={t("ui.performancePage.todBarOpen", { hour: label })}
                  onClick={() => nav(postsHrefForLocalHour(b.localHour))}
                  className={`${barClass} cursor-pointer transition-opacity hover:opacity-100 focus:outline-hidden focus-visible:ring-2 focus-visible:ring-amber-500 focus-visible:ring-offset-1 dark:focus-visible:ring-offset-zinc-900`}
                  style={barStyle}
                />
              ) : (
                <div className={barClass} style={barStyle} aria-hidden />
              )}
            </div>
          );
        })}
      </div>
      <div className="flex gap-px sm:gap-0.5 mt-1.5">
        {bars.map((b) => (
          <div
            key={`lbl-${b.localHour}`}
            className="flex-1 min-w-0 text-center text-[9px] tabular-nums text-stone-400 dark:text-zinc-500 truncate"
          >
            {/* Label every 3 hours so the axis stays readable at narrow widths. */}
            {b.localHour % 3 === 0 ? formatHourLabel(b.localHour, timeZone) : ""}
          </div>
        ))}
      </div>
      <p className="mt-2 text-[10px] text-center text-stone-400 dark:text-zinc-500">
        {t("ui.performancePage.todFooter", { zone: timeZone })}
      </p>
    </div>
  );
}

/**
 * Sortable th for the Posts-by-reach table.
 * #373 — no whitespace-nowrap: long labels used to overflow fixed-width
 * columns and paint over neighbors. Short label + title= full name +
 * min-w-0 / truncate keep the click target inside its col.
 */
function PerfSortHeader({
  sortKey,
  activeKey,
  dir,
  onSort,
  tip,
  icon,
  className = "",
}: {
  sortKey: PerfSortKey;
  activeKey: PerfSortKey;
  dir: PerfSortDir;
  onSort: (k: PerfSortKey) => void;
  tip?: string;
  icon?: ReactNode;
  className?: string;
}) {
  const t = useT();
  const active = sortKey === activeKey;
  const { short, full } = perfSortColumn(sortKey);
  const btn = (
    <button
      type="button"
      onClick={() => onSort(sortKey)}
      title={full}
      aria-label={active ? t(dir === "desc" ? "ui.performancePage.sortedDesc" : "ui.performancePage.sortedAsc", { column: full }) : t("ui.performancePage.sortBy", { column: full })}
      className={`inline-flex max-w-full min-w-0 items-center gap-0.5 hover:text-amber-600 dark:hover:text-amber-400 transition-colors ${
        active ? "text-amber-600 dark:text-amber-400" : ""
      }`}
    >
      {icon ? <span className="shrink-0">{icon}</span> : null}
      <span className="min-w-0 truncate">{short}</span>
      {active && <span className="shrink-0" aria-hidden>{dir === "desc" ? "▾" : "▴"}</span>}
    </button>
  );
  return (
    <th className={`px-1.5 py-2 font-medium min-w-0 overflow-hidden ${className}`}>
      {tip ? <Tip label={tip}>{btn}</Tip> : btn}
    </th>
  );
}

export default function PerformancePage() {
  const t = useT();
  const [data, setData] = useState<PostPerformanceResult | null>(null);
  const [, timeZone] = useTimezone();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sortCol, setSortCol] = useState<PerfSortKey>("impressions");
  const [sortDir, setSortDir] = useState<PerfSortDir>("desc");

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

  const onSort = useCallback((col: PerfSortKey) => {
    const next = nextPerfSort(sortCol, sortDir, col);
    setSortCol(next.col);
    setSortDir(next.dir);
  }, [sortCol, sortDir]);

  const posts: PerformancePost[] = data?.posts ?? [];
  const sortedPosts = useMemo(
    () => sortPerformancePosts(posts, sortCol, sortDir),
    [posts, sortCol, sortDir],
  );

  const corpus = data?.corpus;
  const linkCohorts = data?.cohorts?.link_placement;
  const mixRows = useMemo(() => {
    const buckets: Record<string, CohortBucket> = {};
    for (const [place, raw] of Object.entries(linkCohorts ?? {})) {
      const b = cohortBucket(raw);
      if (b) buckets[place] = b;
    }
    return formatMix(buckets);
  }, [linkCohorts]);
  // #367 — recompute ToD in the patron zone from post instants. The API still
  // returns UTC-hour cohorts for other consumers; the chart must not relabel them.
  const todCohorts = useMemo(
    () => timeOfDayCohortInZone(posts, timeZone),
    [posts, timeZone],
  );
  const todBucketCount = Object.keys(todCohorts).length;
  const followers = data?.follower_count ?? null;
  const following = data?.following_count ?? null;
  const ratio = followRatio(followers, following);
  const growth = data?.follower_growth_30d ?? null;
  const history = data?.follower_history ?? [];
  const lastChart = useMemo(
    () => lastPostsChart(posts, corpus?.rolling_median_final ?? null),
    [posts, corpus?.rolling_median_final],
  );

  // Initial load: full-page quote loader. Refresh keeps the shell visible.
  const initialLoading = loading && data == null && !error;

  return (
    <div className="max-w-[90rem] mx-auto px-4 py-6 space-y-5">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-lg font-semibold">{t("ui.performancePage.title")}</h1>
          <p className="text-sm text-stone-500 dark:text-zinc-400 mt-0.5">
            {t("ui.performancePage.intro")}
          </p>
        </div>
        <div className="shrink-0 ml-auto">
          <RefreshButton onRefresh={refresh} busy={loading} label={t("ui.performancePage.refresh")} classNames={refreshStyles.header} />
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-700 dark:border-rose-500/30 dark:bg-rose-500/10 dark:text-rose-300">
          {error}
        </div>
      )}

      {initialLoading ? (
        <div className="py-16">
          <QuoteScroller quotes={QUOTES} spinner heading={t("ui.performancePage.loading")} classNames={quoteStyles} />
        </div>
      ) : (
        <>
      <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-6 gap-3">
        <StatCard
          icon={<FileText className="h-4 w-4" />}
          label={t("ui.performancePage.statPosts")}
          value={fmtInt(corpus?.post_count ?? posts.length)}
          tip={t(TIPS.posts)}
        />
        <StatCard
          icon={<Camera className="h-4 w-4" />}
          label={t("ui.performancePage.statSnapshots")}
          value={fmtInt(corpus?.snapshot_count)}
          tip={t(TIPS.snapshots)}
        />
        <StatCard
          icon={<TrendingUp className="h-4 w-4" />}
          label={t("ui.performancePage.statMedianT15")}
          value={fmtInt(corpus?.rolling_median_t15 ?? null)}
          unit={t("ui.performancePage.unitImpr")}
          tip={t(TIPS.medianT15)}
        />
        <StatCard
          icon={<Users className="h-4 w-4" />}
          label={t("ui.performancePage.statFollowers")}
          value={fmtInt(followers)}
          tip={t(TIPS.followers)}
          sub={
            <>
              {growth ? (
                <div
                  className={
                    growth.delta > 0
                      ? "text-emerald-600 dark:text-emerald-400"
                      : growth.delta < 0
                        ? "text-rose-600 dark:text-rose-400"
                        : ""
                  }
                >
                  {t("ui.performancePage.followerGrowth", { delta: fmtSigned(growth.delta), days: growth.days })}
                </div>
              ) : null}
              {following != null && ratio != null ? (
                <div>
                  {t("ui.performancePage.followingRatio", {
                    following: fmtInt(following),
                    ratio: ratio.toFixed(1),
                  })}
                </div>
              ) : null}
            </>
          }
        />
        <StatCard
          icon={<Eye className="h-4 w-4" />}
          label={t("ui.performancePage.statViewsPerFollower")}
          value={fmtPct(corpus?.views_per_follower)}
          tip={t(TIPS.viewsPerFollower)}
        />
        <StatCard
          icon={<Flame className="h-4 w-4" />}
          label={t("ui.performancePage.statEngagement")}
          value={fmtPct(corpus?.engagement_rate)}
          tip={t(TIPS.engagement)}
        />
      </div>

      <ChartCard
        icon={<LineChart className="h-4 w-4" />}
        title={t("ui.performancePage.trendTitle")}
        tip={t(TIPS.trendDaily)}
      >
        <DailyTrend history={history} posts={posts} timeZone={timeZone} />
      </ChartCard>

      {lastChart.bars.length > 0 && (
        <ChartCard
          icon={<BarChart3 className="h-4 w-4" />}
          title={t("ui.performancePage.lastTitle", { count: lastChart.bars.length })}
          tip={t(TIPS.last)}
          intro={t("ui.performancePage.lastIntro")}
        >
          <LastPostsBars chart={lastChart} timeZone={timeZone} />
        </ChartCard>
      )}

      {mixRows.length > 0 && (
        <ChartCard
          icon={<Link2 className="h-4 w-4" />}
          title={t("ui.performancePage.mixTitle")}
          tip={t(TIPS.linkPlacement)}
          intro={t("ui.performancePage.mixIntro")}
        >
          <FormatMixTable rows={mixRows} />
        </ChartCard>
      )}

      {todBucketCount > 0 && (
        <div className={`${card} p-4`}>
          <div className="flex items-center justify-center gap-2 mb-1">
            <Clock className="h-4 w-4 text-amber-600 dark:text-amber-400" aria-hidden />
            <Tip label={t(TIPS.timeOfDay)}>
              <h2 className="text-sm font-medium">{t("ui.performancePage.todTitle")}</h2>
            </Tip>
          </div>
          <p className="text-xs text-stone-500 dark:text-zinc-400 mb-3 text-center">
            {t("ui.performancePage.todIntro")}
          </p>
          <TimeOfDayChart buckets={todCohorts} timeZone={timeZone} />
        </div>
      )}

      <div className={`${card} overflow-hidden`}>
        <div className="px-4 py-3 border-b border-stone-100 dark:border-zinc-800">
          <h2 className="text-sm font-medium">{t("ui.performancePage.reachTitle")}</h2>
        </div>
        {posts.length === 0 ? (
          <div className="px-4 py-10 text-center text-sm text-stone-500 dark:text-zinc-400">
            {loading ? (
              <div className="py-6">
                <QuoteScroller quotes={QUOTES} spinner heading={t("ui.performancePage.loading")} classNames={quoteStyles} />
              </div>
            ) : (
              <>
                {t("ui.performancePage.empty")}{" "}
                <Link to="/" className="text-amber-600 dark:text-amber-400 hover:underline">
                  {t("ui.performancePage.backToPosts")} →
                </Link>
              </>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm table-fixed">
              <colgroup>
                <col style={{ width: "22%" }} />
                <col style={{ width: "9%" }} />
                <col style={{ width: "8%" }} />
                <col style={{ width: "6%" }} />
                <col style={{ width: "10%" }} />
                <col style={{ width: "10%" }} />
                <col style={{ width: "6%" }} />
                <col style={{ width: "7%" }} />
                <col style={{ width: "8%" }} />
                <col style={{ width: "7%" }} />
                <col style={{ width: "7%" }} />
              </colgroup>
              <thead>
                <tr className="text-left text-xs text-stone-400 dark:text-zinc-500 border-b border-stone-100 dark:border-zinc-800">
                  <th className="px-3 py-2 font-medium">{t("ui.performancePage.colPost")}</th>
                  <PerfSortHeader
                    sortKey="posted"
                    activeKey={sortCol}
                    dir={sortDir}
                    onSort={onSort}
                    className="text-left"
                  />
                  <th className="px-1.5 py-2 font-medium min-w-0 overflow-hidden">
                    <Tip label={t(TIPS.trend)}>
                      <span title={t("ui.performancePage.colTrend")}>{t("ui.performancePage.colTrend")}</span>
                    </Tip>
                  </th>
                  <PerfSortHeader
                    sortKey="impressions"
                    activeKey={sortCol}
                    dir={sortDir}
                    onSort={onSort}
                    className="text-right"
                  />
                  <PerfSortHeader
                    sortKey="escape_velocity"
                    activeKey={sortCol}
                    dir={sortDir}
                    onSort={onSort}
                    tip={t(TIPS.escapeVelocity)}
                    icon={<Rocket className="h-3 w-3" aria-hidden />}
                    className="text-right"
                  />
                  <PerfSortHeader
                    sortKey="breakout_ratio"
                    activeKey={sortCol}
                    dir={sortDir}
                    onSort={onSort}
                    tip={t(TIPS.breakoutRatio)}
                    icon={<TrendingUp className="h-3 w-3" aria-hidden />}
                    className="text-right"
                  />
                  <PerfSortHeader
                    sortKey="clicks"
                    activeKey={sortCol}
                    dir={sortDir}
                    onSort={onSort}
                    className="text-right"
                  />
                  <PerfSortHeader
                    sortKey="profile"
                    activeKey={sortCol}
                    dir={sortDir}
                    onSort={onSort}
                    tip={t(TIPS.profileClicks)}
                    icon={<UserRound className="h-3 w-3" aria-hidden />}
                    className="text-right"
                  />
                  <PerfSortHeader
                    sortKey="bookmarks"
                    activeKey={sortCol}
                    dir={sortDir}
                    onSort={onSort}
                    tip={t(TIPS.bookmarks)}
                    icon={<Bookmark className="h-3 w-3" aria-hidden />}
                    className="text-right"
                  />
                  <PerfSortHeader
                    sortKey="reply_rate"
                    activeKey={sortCol}
                    dir={sortDir}
                    onSort={onSort}
                    tip={t(TIPS.replyRate)}
                    icon={<MessageCircle className="h-3 w-3" aria-hidden />}
                    className="text-right"
                  />
                  <PerfSortHeader
                    sortKey="quote_to_repost"
                    activeKey={sortCol}
                    dir={sortDir}
                    onSort={onSort}
                    tip={t(TIPS.quoteToRepost)}
                    icon={<Quote className="h-3 w-3" aria-hidden />}
                    className="text-right"
                  />
                </tr>
              </thead>
              <tbody>
                {sortedPosts.map((p) => {
                  const posted = formatPostedShort(p.last_sent_at, timeZone);
                  const brSample = data?.corpus?.breakout_sample_size ?? 0;
                  const brMin = data?.corpus?.breakout_min_sample ?? 5;
                  const brThin = p.breakout_ratio == null && brSample < brMin;
                  return (
                    <tr
                      key={p.post_id}
                      className="border-b border-stone-50 dark:border-zinc-900 last:border-0 hover:bg-stone-50 dark:hover:bg-zinc-900/60"
                    >
                      <td className="px-3 py-2.5">
                        <Link
                          to={`/post/${p.post_id}`}
                          className="block text-sm font-medium text-stone-900 dark:text-zinc-100 hover:text-amber-700 dark:hover:text-amber-400 hover:underline truncate"
                          title={postLabel(p)}
                        >
                          {postLabel(p)}
                        </Link>
                      </td>
                      <td
                        className="px-2 py-2.5 text-[11px] tabular-nums text-stone-500 dark:text-zinc-400 whitespace-nowrap"
                        title={p.last_sent_at ?? undefined}
                      >
                        {posted}
                      </td>
                      <td className="px-2 py-2.5">
                        <Sparkline points={p.sparkline ?? []} />
                      </td>
                      <td className="px-2 py-2.5 text-right tabular-nums">
                        {fmtInt(p.latest_impressions)}
                      </td>
                      <td
                        className={`px-2 py-2.5 text-right tabular-nums ${
                          (p.escape_velocity ?? 0) >= 1.5
                            ? "text-emerald-600 dark:text-emerald-400 font-medium"
                            : ""
                        }`}
                      >
                        <Tip label={t(TIPS.escapeVelocity)}>
                          <span>{fmtRatio(p.escape_velocity)}</span>
                        </Tip>
                      </td>
                      <td
                        className={`px-2 py-2.5 text-right tabular-nums ${
                          (p.breakout_ratio ?? 0) > 1.2
                            ? "text-sky-600 dark:text-sky-400 font-medium"
                            : ""
                        }`}
                      >
                        <Tip
                          label={
                            brThin
                              ? t("ui.performancePage.breakoutThin", { min: brMin, sample: brSample })
                              : t(TIPS.breakoutRatio)
                          }
                        >
                          <span>{fmtRatio(p.breakout_ratio)}</span>
                        </Tip>
                      </td>
                      <td className="px-2 py-2.5 text-right tabular-nums text-stone-500 dark:text-zinc-400">
                        {formatLinkClicks(p.url_link_clicks, p.link_placement)}
                      </td>
                      <td className="px-2 py-2.5 text-right tabular-nums">
                        <Tip label={t(TIPS.profileClicks)}>
                          <span className="inline-flex flex-col items-end leading-tight">
                            <span>{fmtInt(p.user_profile_clicks)}</span>
                            <span className="text-[10px] text-stone-400 dark:text-zinc-500">
                              {fmtPct(p.profile_click_rate)}
                            </span>
                          </span>
                        </Tip>
                      </td>
                      <td className="px-2 py-2.5 text-right tabular-nums">
                        <Tip label={t(TIPS.bookmarks)}>
                          <span className="inline-flex flex-col items-end leading-tight">
                            <span>{fmtInt(p.bookmarks)}</span>
                            <span className="text-[10px] text-stone-400 dark:text-zinc-500">
                              {fmtPct(p.bookmark_rate)}
                            </span>
                          </span>
                        </Tip>
                      </td>
                      <td className="px-2 py-2.5 text-right tabular-nums">
                        <Tip label={t(TIPS.replyRate)}>
                          <span>{fmtPct(p.reply_rate)}</span>
                        </Tip>
                      </td>
                      <td className="px-2 py-2.5 text-right tabular-nums">
                        <Tip label={t(TIPS.quoteToRepost)}>
                          <span>{fmtRatio(p.quote_to_repost_ratio)}</span>
                        </Tip>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
        </>
      )}
    </div>
  );
}
