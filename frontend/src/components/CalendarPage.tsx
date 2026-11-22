// When posts go out, on a month: what was sent each day, what is coming, and
// what a paused post would send if it were resumed. A quiet day, or a week the
// scheduler stopped, shows at a glance; a tap lists the day's posts.

import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { localDateFilterBounds, monthWeeks } from "@tollbooth-dpyc/web";
import { MonthCalendar, RefreshButton, useLanguageLocale, useTimezone } from "@tollbooth-dpyc/web/react";
import { useT } from "../i18n";
import { listPosts, type PostSummary } from "../lib/mcp";
import { countsOf, occurrencesIn, type Occurrence, type OccurrenceKind } from "../lib/occurrences";
import { refreshStyles } from "../lib/packageStyles";

const MARK: Record<OccurrenceKind, string> = { sent: "✅", coming: "🕒", paused: "⏸️" };
const KINDS: OccurrenceKind[] = ["sent", "coming", "paused"];
// Everything still to go out, or held from going out.
const UPCOMING = "scheduled,resolving,resolved,sending,paused";
const PAGE = 100;

/** Every page of one listing. */
async function allPosts(opts: Parameters<typeof listPosts>[0]): Promise<PostSummary[]> {
  const out: PostSummary[] = [];
  for (let page = 0; ; page++) {
    const r = await listPosts({ ...opts, page, pageSize: PAGE });
    if (r.error) throw new Error(r.error);
    out.push(...(r.posts ?? []));
    if ((r.posts ?? []).length < PAGE || out.length >= (r.total ?? 0)) return out;
  }
}

/** The instants the grid of a month covers, from its first Sunday to the day after its last Saturday, in `timeZone`. */
function gridBounds(year: number, month: number, timeZone: string): { from: string; to: string } | null {
  const days = monthWeeks(year, month).flat();
  const b = localDateFilterBounds(days[0]!.key, days[days.length - 1]!.key, timeZone);
  return b.dateFrom && b.dateTo ? { from: b.dateFrom, to: b.dateTo } : null;
}

function Day({ list, timeZone }: { list: Occurrence[]; timeZone: string }) {
  const t = useT();
  const locale = useLanguageLocale();
  return (
    <ul className="grid gap-2">
      {list.map((o, i) => (
        <li key={`${o.post.post_id}-${o.at}-${i}`}
          className={`flex items-baseline gap-3 rounded-lg border border-stone-200 dark:border-zinc-800 px-3 py-2 ${o.kind === "paused" ? "opacity-60" : ""}`}>
          <span className="tabular-nums text-sm text-stone-500 dark:text-zinc-400 shrink-0">
            {new Date(o.at * 1000).toLocaleTimeString(locale, { timeZone, hour: "numeric", minute: "2-digit" })}
          </span>
          <span aria-hidden>{MARK[o.kind]}</span>
          <Link to={`/post/${o.post.post_id}`} className="min-w-0 flex-1 truncate hover:underline">
            {o.post.title || o.post.excerpt || o.post.post_id}
          </Link>
          <span className="text-xs text-stone-500 dark:text-zinc-400 shrink-0">{t(`ui.calendarPage.kind.${o.kind}`)}</span>
        </li>
      ))}
    </ul>
  );
}

export default function CalendarPage() {
  const t = useT();
  const [, timeZone] = useTimezone();
  const [now] = useState(() => Math.floor(Date.now() / 1000));
  const [shown, setShown] = useState<{ year: number; month: number } | null>(null);
  const [upcoming, setUpcoming] = useState<PostSummary[] | null>(null);
  const [sent, setSent] = useState<PostSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!shown) return;
    const bounds = gridBounds(shown.year, shown.month, timeZone);
    if (!bounds) return;
    setLoading(true);
    setError(null);
    try {
      const [up, done] = await Promise.all([
        allPosts({ status: UPCOMING, sortCol: "scheduled", sortDir: "asc" }),
        allPosts({ status: "sent", dateField: "sent", dateFrom: bounds.from, dateTo: bounds.to, sortCol: "created", sortDir: "asc" }),
      ]);
      setUpcoming(up);
      setSent(done);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [shown, timeZone]);

  useEffect(() => { void load(); }, [load]);

  const events = useMemo(() => {
    if (!shown || !upcoming) return [];
    const bounds = gridBounds(shown.year, shown.month, timeZone);
    if (!bounds) return [];
    return occurrencesIn(sent, upcoming, Date.parse(bounds.from), Date.parse(bounds.to), now * 1000);
  }, [sent, upcoming, shown, timeZone, now]);

  const onMonth = useCallback((m: { year: number; month: number }) => setShown(m), []);
  const counted = (day: Occurrence[]) => countsOf(day).map(([k, n]) => t(`ui.calendarPage.count.${k}`, { count: n }));

  return (
    <div className="max-w-[90rem] mx-auto px-4 py-6 space-y-5 posts-calendar">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-lg font-semibold">{t("ui.calendarPage.title")}</h1>
          <p className="text-sm text-stone-500 dark:text-zinc-400 mt-0.5">{t("ui.calendarPage.intro", { zone: timeZone })}</p>
        </div>
        <div className="shrink-0 ml-auto">
          <RefreshButton onRefresh={load} busy={loading} label={t("ui.calendarPage.refresh")} classNames={refreshStyles.header} />
        </div>
      </div>
      {error && <p className="text-sm text-red-600 dark:text-red-400 text-right">{error}</p>}
      <MonthCalendar
        events={events}
        at={(o) => o.at}
        now={now}
        timeZone={timeZone}
        onMonth={onMonth}
        marks={(day) => countsOf(day).map(([k, n]) => `${MARK[k]}${n}`)}
        dayLabel={counted}
        dayClass={(day) => day.some((o) => o.kind === "paused") && "month-day-paused"}
        legend={KINDS.map((k) => ({ mark: MARK[k], label: t(`ui.calendarPage.kind.${k}`) }))}
        renderDay={(list) => <Day list={list} timeZone={timeZone} />}
        classNames={{ title: "text-base font-semibold", marks: "month-marks", count: "text-stone-500 dark:text-zinc-400 tabular-nums" }}
      />
    </div>
  );
}
