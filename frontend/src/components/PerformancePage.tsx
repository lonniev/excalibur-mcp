import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { Link } from "react-router-dom";
import {
  Bookmark,
  Camera,
  Clock,
  FileText,
  Info,
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
  type PerformancePost,
  type PostPerformanceResult,
} from "../lib/mcp";
import RefreshButton from "./RefreshButton";

const card = "rounded-xl border border-stone-200 dark:border-zinc-800 bg-white dark:bg-zinc-900";

// Plain-language definitions — sourced from metrics_harvest.py, not paraphrased
// from the labels. One Tip treatment is used on summary widgets, table headers,
// and cells so the reader never has to re-learn where the explanation lives.
const TIPS = {
  posts: "How many of your posts have at least one harvested metrics reading.",
  snapshots:
    "A snapshot is one reading of a post's metrics at a cadence step (t+15m, +1h, +6h, +24h, +72h, +7d, +28d). Whatever is not snapshotted inside that 28-day window is gone — X stops exposing the private metrics after ~30 days.",
  medianT15:
    "Your personal baseline: the rolling median of impressions in the first 15 minutes across your harvested posts. This is the denominator of escape velocity — why the number is on the page at all. Unit: impressions.",
  followers:
    "Your current X follower count (best-effort from the account lookup). Denominator of breakout ratio. When this is unavailable, breakout ratio cells stay empty rather than guessing.",
  escapeVelocity:
    "How this post's first 15 minutes compared to your own typical post: impressions at t+15m ÷ your rolling median t+15m. Above 1× means faster than your normal.",
  breakoutRatio:
    "Whether the post travelled beyond your followers: impressions ÷ follower count. Much greater than 1× implies For You pickup; around 1× means it mostly stayed on the home timeline. Empty when follower count is unavailable.",
  trend:
    "Impressions at each snapshot for this post, oldest to newest (t+15m through +28d). The line shows the shape of the climb; the Impr. column carries the latest number.",
  linkPlacement:
    "Median impressions grouped by where the link sat — in the body, in the first reply, or no link at all. Only the groups your corpus actually contains appear, and the panel stays hidden until there are two of them, because one median compares to nothing.",
  profileClicks:
    "How many readers opened your profile from this post. Strongest free intent proxy on X: the post made someone want to find out who wrote it. The rate is profile clicks ÷ impressions.",
  bookmarks:
    "Saves for later. X weights bookmarks heavily in ranking; bookmark rate (bookmarks ÷ impressions) separates evergreen reference posts from ephemeral ones.",
  replyRate:
    "Replies ÷ impressions, kept separate from the blended engagement mix. Author-reply chains carry heavy ranking weight, so this predicts next-post reach better than aggregates.",
  quoteToRepost:
    "Quotes ÷ reposts. Quotes recruit the quoter's out-of-network audience with commentary; plain reposts do neither to the same degree. High ratio means the post provoked response, not mere agreement.",
  timeOfDay:
    "Median impressions for posts sent in each UTC hour. Actionable for the scheduler; accumulates automatically as the corpus grows. Underpowered with few posts — treat early numbers as directional.",
} as const;

const TIP_W = 256; // px — must match the w-64 on the panel
const TIP_GAP = 6; // px between the ⓘ and the panel
const TIP_MARGIN = 8; // px kept clear of the viewport edge

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
      className="relative inline-flex items-center gap-1"
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
}: {
  icon: ReactNode;
  label: string;
  value: string;
  tip: string;
  unit?: string;
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
    </div>
  );
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

/** Fraction as a percentage with one decimal (0.053 → "5.3%"). */
function fmtPct(n: number | null | undefined): string {
  if (n == null || Number.isNaN(n)) return "—";
  return `${(n * 100).toFixed(1)}%`;
}

/** UTC hour key `"14"` → `"14:00 UTC"`. */
function fmtHour(hh: string): string {
  return `${hh}:00 UTC`;
}

function fmtPosted(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

/** Prefer title, then opening words; never lead with a hash. */
function postLabel(p: PerformancePost): string {
  const title = (p.title || "").trim();
  if (title) return title;
  const excerpt = (p.excerpt || "").trim().replace(/\s+/g, " ");
  if (excerpt) {
    return excerpt.length > 72 ? `${excerpt.slice(0, 72).trimEnd()}…` : excerpt;
  }
  return "Untitled post";
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
  const todCohorts = data?.cohorts?.time_of_day ?? {};
  // Lexical sort on zero-padded HH keys == chronological.
  const todEntries = Object.entries(todCohorts).sort((a, b) => a[0].localeCompare(b[0]));
  const followers = data?.follower_count ?? null;

  return (
    <div className="max-w-5xl mx-auto px-4 py-6 space-y-5">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-lg font-semibold">Performance</h1>
          <p className="text-sm text-stone-500 dark:text-zinc-400 mt-0.5">
            How your recent posts are travelling — early momentum versus your own baseline,
            reach past your followers, and where a link helped. Metrics are read at set
            intervals for 28 days after each send; after that X stops exposing them.
          </p>
        </div>
        <div className="shrink-0 ml-auto">
          <RefreshButton onClick={() => void refresh()} busy={loading} title="Refresh performance" size="sm" />
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-700 dark:border-rose-500/30 dark:bg-rose-500/10 dark:text-rose-300">
          {error}
        </div>
      )}

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <StatCard
          icon={<FileText className="h-4 w-4" />}
          label="Posts"
          value={fmtInt(corpus?.post_count ?? posts.length)}
          tip={TIPS.posts}
        />
        <StatCard
          icon={<Camera className="h-4 w-4" />}
          label="Snapshots"
          value={fmtInt(corpus?.snapshot_count)}
          tip={TIPS.snapshots}
        />
        <StatCard
          icon={<TrendingUp className="h-4 w-4" />}
          label="Median t+15m"
          value={fmtInt(corpus?.rolling_median_t15 ?? null)}
          unit="impr."
          tip={TIPS.medianT15}
        />
        <StatCard
          icon={<Users className="h-4 w-4" />}
          label="Followers"
          value={fmtInt(followers)}
          tip={TIPS.followers}
        />
      </div>

      {cohortEntries.length > 1 && (
        <div className={`${card} p-4`}>
          <div className="flex items-center justify-center gap-2 mb-1">
            <Link2 className="h-4 w-4 text-amber-600 dark:text-amber-400" aria-hidden />
            <Tip label={TIPS.linkPlacement}>
              <h2 className="text-sm font-medium">Link placement and reach</h2>
            </Tip>
          </div>
          <p className="text-xs text-stone-500 dark:text-zinc-400 mb-3 text-center">
            Median impressions grouped by where the link sat — grounded in your corpus, not
            third-party claims.
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

      {todEntries.length > 1 && (
        <div className={`${card} p-4`}>
          <div className="flex items-center justify-center gap-2 mb-1">
            <Clock className="h-4 w-4 text-amber-600 dark:text-amber-400" aria-hidden />
            <Tip label={TIPS.timeOfDay}>
              <h2 className="text-sm font-medium">Time of day</h2>
            </Tip>
          </div>
          <p className="text-xs text-stone-500 dark:text-zinc-400 mb-3 text-center">
            Median impressions by the UTC hour the post went out — free, accumulates with every
            send.
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-stone-400 dark:text-zinc-500 border-b border-stone-100 dark:border-zinc-800">
                  <th className="py-1.5 pr-3 font-medium">Send hour</th>
                  <th className="py-1.5 font-medium">Median impressions</th>
                </tr>
              </thead>
              <tbody>
                {todEntries.map(([hour, med]) => (
                  <tr key={hour} className="border-b border-stone-50 dark:border-zinc-900 last:border-0">
                    <td className="py-2 pr-3 tabular-nums">{fmtHour(hour)}</td>
                    <td className="py-2 tabular-nums">{fmtInt(med)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className={`${card} overflow-hidden`}>
        <div className="px-4 py-3 border-b border-stone-100 dark:border-zinc-800">
          <h2 className="text-sm font-medium">Posts by reach</h2>
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
                  <th className="px-3 py-2 font-medium">
                    <Tip label={TIPS.trend}>
                      <span>Trend</span>
                    </Tip>
                  </th>
                  <th className="px-3 py-2 font-medium text-right">Impr.</th>
                  <th className="px-3 py-2 font-medium text-right">
                    <Tip label={TIPS.escapeVelocity}>
                      <span className="inline-flex items-center gap-1">
                        <Rocket className="h-3 w-3" aria-hidden />
                        Escape velocity
                      </span>
                    </Tip>
                  </th>
                  <th className="px-3 py-2 font-medium text-right">
                    <Tip label={TIPS.breakoutRatio}>
                      <span className="inline-flex items-center gap-1">
                        <TrendingUp className="h-3 w-3" aria-hidden />
                        Breakout ratio
                      </span>
                    </Tip>
                  </th>
                  <th className="px-3 py-2 font-medium">Link</th>
                  <th className="px-3 py-2 font-medium text-right">Clicks</th>
                  <th className="px-3 py-2 font-medium text-right">
                    <Tip label={TIPS.profileClicks}>
                      <span className="inline-flex items-center gap-1">
                        <UserRound className="h-3 w-3" aria-hidden />
                        Profile
                      </span>
                    </Tip>
                  </th>
                  <th className="px-3 py-2 font-medium text-right">
                    <Tip label={TIPS.bookmarks}>
                      <span className="inline-flex items-center gap-1">
                        <Bookmark className="h-3 w-3" aria-hidden />
                        Bookmarks
                      </span>
                    </Tip>
                  </th>
                  <th className="px-3 py-2 font-medium text-right">
                    <Tip label={TIPS.replyRate}>
                      <span className="inline-flex items-center gap-1">
                        <MessageCircle className="h-3 w-3" aria-hidden />
                        Reply rate
                      </span>
                    </Tip>
                  </th>
                  <th className="px-3 py-2 font-medium text-right">
                    <Tip label={TIPS.quoteToRepost}>
                      <span className="inline-flex items-center gap-1">
                        <Quote className="h-3 w-3" aria-hidden />
                        Quote/repost
                      </span>
                    </Tip>
                  </th>
                </tr>
              </thead>
              <tbody>
                {posts.map((p) => {
                  const posted = fmtPosted(p.last_sent_at);
                  const brMissing = p.breakout_ratio == null && followers == null;
                  return (
                    <tr
                      key={p.post_id}
                      className="border-b border-stone-50 dark:border-zinc-900 last:border-0 hover:bg-stone-50 dark:hover:bg-zinc-900/60"
                    >
                      <td className="px-4 py-2.5 max-w-[16rem]">
                        <Link
                          to={`/post/${p.post_id}`}
                          className="block text-sm font-medium text-stone-900 dark:text-zinc-100 hover:text-amber-700 dark:hover:text-amber-400 hover:underline truncate"
                          title={postLabel(p)}
                        >
                          {postLabel(p)}
                        </Link>
                        {posted ? (
                          <div className="text-[11px] text-stone-400 dark:text-zinc-500 mt-0.5">
                            Posted {posted}
                          </div>
                        ) : null}
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
                      >
                        <Tip label={TIPS.escapeVelocity}>
                          <span>{fmtRatio(p.escape_velocity)}</span>
                        </Tip>
                      </td>
                      <td
                        className={`px-3 py-2.5 text-right tabular-nums ${
                          (p.breakout_ratio ?? 0) > 1.2
                            ? "text-sky-600 dark:text-sky-400 font-medium"
                            : ""
                        }`}
                      >
                        <Tip
                          label={
                            brMissing
                              ? "Breakout ratio needs your follower count, which is unavailable right now — reconnect X or try refresh."
                              : TIPS.breakoutRatio
                          }
                        >
                          <span>{fmtRatio(p.breakout_ratio)}</span>
                        </Tip>
                      </td>
                      <td className="px-3 py-2.5 text-xs capitalize text-stone-500 dark:text-zinc-400">
                        {(p.link_placement || "—").replace("_", " ")}
                      </td>
                      <td className="px-3 py-2.5 text-right tabular-nums text-stone-500 dark:text-zinc-400">
                        {fmtInt(p.url_link_clicks)}
                      </td>
                      <td className="px-3 py-2.5 text-right tabular-nums">
                        <Tip label={TIPS.profileClicks}>
                          <span className="inline-flex flex-col items-end leading-tight">
                            <span>{fmtInt(p.user_profile_clicks)}</span>
                            <span className="text-[10px] text-stone-400 dark:text-zinc-500">
                              {fmtPct(p.profile_click_rate)}
                            </span>
                          </span>
                        </Tip>
                      </td>
                      <td className="px-3 py-2.5 text-right tabular-nums">
                        <Tip label={TIPS.bookmarks}>
                          <span className="inline-flex flex-col items-end leading-tight">
                            <span>{fmtInt(p.bookmarks)}</span>
                            <span className="text-[10px] text-stone-400 dark:text-zinc-500">
                              {fmtPct(p.bookmark_rate)}
                            </span>
                          </span>
                        </Tip>
                      </td>
                      <td className="px-3 py-2.5 text-right tabular-nums">
                        <Tip label={TIPS.replyRate}>
                          <span>{fmtPct(p.reply_rate)}</span>
                        </Tip>
                      </td>
                      <td className="px-3 py-2.5 text-right tabular-nums">
                        <Tip label={TIPS.quoteToRepost}>
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
    </div>
  );
}
