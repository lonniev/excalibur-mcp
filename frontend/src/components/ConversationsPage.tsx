import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  ChevronDown, ChevronRight, Eye, ExternalLink, Image, Loader2, MapPin, MessageCircle,
  MessageSquare, Radar, Search, Users, X,
} from "lucide-react";
import {
  deleteConversationQuery, findConversations, listConversationQueries, listConversations,
  OAUTH_NEEDED_CODES, setConversationStatus,
  type ConversationQueryRow, type ConversationRow, type ConversationStatus,
} from "../lib/mcp";
import { formatDateTime, localDateFilterBounds, type SortDir } from "@tollbooth-dpyc/web";
import {
  PageControls,
  QuoteScroller,
  SortHeader,
  TableFilter,
  TableShell,
  useTimezone,
} from "@tollbooth-dpyc/web/react";
import {
  actionsHeaderStyles,
  pageControlsStyles,
  sortHeaderStyles,
  tableFilterStyles,
  tableShellStyles,
} from "../lib/packageStyles";
import { QUOTES } from "../lib/quotes";
import { quoteStyles } from "../lib/quoteStyles";
import {
  compactCount, MAX_CLAUSE, normalizePgTimestamp, runSummary, scoreTone, SIGNAL_TITLES, STATUSES,
} from "../lib/conversationsPresentation";
import ConversationQueriesPanel from "./ConversationQueriesPanel";
import ConversationQueryEditor, { emptyQuery } from "./ConversationQueryEditor";

const DATE_FIELDS = [
  { value: "found", label: "Found" },
  { value: "posted", label: "Posted" },
];
const PAGE_SIZE = 25;

const TONE_CLASS = {
  hot: "bg-amber-500 text-zinc-950",
  warm: "bg-amber-200 text-amber-900 dark:bg-amber-500/30 dark:text-amber-200",
  cool: "bg-stone-200 text-stone-600 dark:bg-zinc-800 dark:text-zinc-400",
} as const;

const STATUS_ACTIONS: { status: ConversationStatus; Icon: typeof Eye; title: string }[] = [
  { status: "seen", Icon: Eye, title: "Seen" },
  { status: "engaged", Icon: MessageCircle, title: "Engaged — I replied by hand" },
  { status: "dismissed", Icon: X, title: "Dismiss" },
];

function when(iso: string | null | undefined, timeZone: string): string {
  return iso ? formatDateTime(normalizePgTimestamp(iso), timeZone) : "—";
}

export default function ConversationsPage() {
  const nav = useNavigate();
  const [rows, setRows] = useState<ConversationRow[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [sortCol, setSortCol] = useState("score");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [search, setSearch] = useState("");
  const [dateField, setDateField] = useState("found");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [statuses, setStatuses] = useState<ConversationStatus[]>(["new", "seen"]);
  const [queries, setQueries] = useState<ConversationQueryRow[]>([]);
  const [selectedQuery, setSelectedQuery] = useState<string>("");
  const [adhoc, setAdhoc] = useState("");
  const [runningId, setRunningId] = useState<string | null>(null);
  const [lastRun, setLastRun] = useState<string | null>(null);
  const [needsXConnect, setNeedsXConnect] = useState(false);
  const [editing, setEditing] = useState<ConversationQueryRow | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [, timeZone] = useTimezone();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refreshQueries = useCallback(async () => {
    try {
      setQueries(await listConversationQueries());
    } catch (e) {
      setError((e as Error).message);
    }
  }, []);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const bounds = localDateFilterBounds(dateFrom, dateTo, timeZone);
      const r = await listConversations({
        queryId: selectedQuery, statuses, sortCol, sortDir, page, pageSize: PAGE_SIZE, search,
        dateFrom: bounds.dateFrom, dateTo: bounds.dateTo, dateField,
      });
      if (r.error) setError(r.error);
      setRows(r.conversations ?? []);
      setTotal(r.total ?? 0);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [selectedQuery, statuses, sortCol, sortDir, page, search, dateFrom, dateTo, dateField, timeZone]);

  useEffect(() => { refreshQueries(); }, [refreshQueries]);
  useEffect(() => { refresh(); }, [refresh]);

  function onSort(col: string, dir: SortDir) {
    setSortCol(col);
    setSortDir(dir);
    setPage(0);
  }

  function toggleStatus(s: ConversationStatus) {
    setStatuses((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]));
    setPage(0);
  }

  function handleRunResult(r: Awaited<ReturnType<typeof findConversations>>): boolean {
    if (r.error || r.success === false) {
      if (r.error_code && OAUTH_NEEDED_CODES.has(r.error_code)) {
        setNeedsXConnect(true);
        setError("Connect your X account before searching.");
      } else {
        setError(r.message || r.error || "Search failed.");
      }
      return false;
    }
    setLastRun(runSummary(r));
    return true;
  }

  async function runSaved(q: ConversationQueryRow) {
    setRunningId(q.id);
    setError(null);
    setLastRun(null);
    try {
      if (handleRunResult(await findConversations({ queryId: q.id }))) {
        setSelectedQuery(q.id);
        setPage(0);
        await Promise.all([refresh(), refreshQueries()]);
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRunningId(null);
    }
  }

  async function runAdhoc() {
    const q = adhoc.trim();
    if (!q) return;
    setRunningId("adhoc");
    setError(null);
    setLastRun(null);
    try {
      if (handleRunResult(await findConversations({ query: q }))) {
        setSelectedQuery("adhoc");
        setPage(0);
        await refresh();
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRunningId(null);
    }
  }

  async function mark(e: React.MouseEvent, row: ConversationRow, status: ConversationStatus) {
    e.stopPropagation();
    e.preventDefault();
    setError(null);
    try {
      await setConversationStatus(row.id, status === row.status ? "new" : status);
      await refresh();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function removeQuery(q: ConversationQueryRow) {
    if (!window.confirm(`Delete "${q.name}"? Its leads are kept.`)) return;
    setError(null);
    try {
      await deleteConversationQuery(q.id);
      if (selectedQuery === q.id) setSelectedQuery("");
      if (editing?.id === q.id) setEditing(null);
      await refreshQueries();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  const running = runningId !== null;
  const queryName = (id: string | null) => queries.find((q) => q.id === id)?.name ?? "ad hoc";

  return (
    <div className="mx-auto w-[90%] max-w-[1600px] px-4 py-6">
      <div className="flex items-center mb-4">
        <h1 className="text-lg font-semibold">Leads</h1>
        {needsXConnect && (
          <button
            onClick={() => nav("/profile")}
            className="ml-auto rounded-sm bg-amber-400 px-2.5 py-1 text-xs font-medium text-zinc-950 hover:bg-amber-300"
          >
            Connect X →
          </button>
        )}
      </div>

      {editing && (
        <ConversationQueryEditor
          row={editing}
          onClose={() => setEditing(null)}
          onSaved={async (saved) => {
            const isNew = !editing.id;
            setEditing(null);
            await refreshQueries();
            setSelectedQuery(saved.id);
            // A query the patron just wrote is a question they want answered now;
            // saving without running left them staring at "no leads match".
            if (isNew) await runSaved(saved);
          }}
          onDelete={editing.id ? () => removeQuery(editing) : undefined}
        />
      )}

      <ConversationQueriesPanel
        queries={queries}
        selected={selectedQuery}
        runningId={runningId}
        onSelect={(id) => { setSelectedQuery(id); setPage(0); }}
        onRun={runSaved}
        onEdit={setEditing}
        onDelete={removeQuery}
        onNew={() => setEditing(emptyQuery())}
      />

      <div className="flex flex-wrap items-center gap-2 mb-3">
        <input
          value={adhoc}
          onChange={(e) => setAdhoc(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter" && !running && adhoc.trim()) runAdhoc(); }}
          placeholder='One-off search, e.g. ("MCP server" OR "MCP tool") (monetize OR billing)'
          maxLength={MAX_CLAUSE}
          className="min-w-72 flex-1 rounded-lg border border-stone-300 bg-white px-3 py-1.5 text-sm dark:border-zinc-700 dark:bg-zinc-900"
        />
        <button
          onClick={runAdhoc}
          disabled={running || !adhoc.trim()}
          className="inline-flex items-center gap-1.5 rounded-lg bg-amber-600 px-3 py-1.5 text-sm text-white hover:bg-amber-500 disabled:opacity-40"
          title="Search X's last 7 days without saving the query"
        >
          {runningId === "adhoc" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Radar className="h-4 w-4" />}
          Run
        </button>
        {lastRun && <span className="text-xs text-stone-500 dark:text-zinc-400">{lastRun}</span>}
      </div>

      <div className="flex flex-wrap items-center gap-1.5 mb-3">
        {STATUSES.map((s) => {
          const on = statuses.includes(s);
          return (
            <button
              key={s}
              onClick={() => toggleStatus(s)}
              className={`rounded-full px-2.5 py-0.5 text-xs border ${
                on
                  ? "border-amber-500 bg-amber-100 text-amber-900 dark:bg-amber-500/20 dark:text-amber-200"
                  : "border-stone-300 text-stone-500 dark:border-zinc-700 dark:text-zinc-400"
              }`}
            >
              {s}
            </button>
          );
        })}
        {selectedQuery && (
          <button
            onClick={() => { setSelectedQuery(""); setPage(0); }}
            className="ml-2 inline-flex items-center gap-1 rounded-full border border-amber-500 bg-amber-100 px-2.5 py-0.5 text-xs text-amber-900 dark:bg-amber-500/20 dark:text-amber-200"
            title="Showing leads from this query only — click to show all"
          >
            {queryName(selectedQuery)} <X className="h-3 w-3" />
          </button>
        )}
      </div>

      <TableFilter
        search={{
          value: search,
          onSearch: (t) => { setSearch(t); setPage(0); },
          placeholder: "Search text or @handle (regex)…",
          title: "Case-insensitive regular expression matched against the post text or author handle",
        }}
        dates={{
          from: dateFrom,
          to: dateTo,
          onFrom: (v) => { setDateFrom(v); setPage(0); },
          onTo: (v) => { setDateTo(v); setPage(0); },
          field: dateField,
          fields: DATE_FIELDS,
          onField: (v) => { setDateField(v); setPage(0); },
        }}
        onClear={() => { setSearch(""); setDateFrom(""); setDateTo(""); setDateField("found"); setPage(0); }}
        searchIcon={<Search className="h-3.5 w-3.5" />}
        clearLabel={<><X className="h-3.5 w-3.5" /> Clear</>}
        classNames={tableFilterStyles}
      />

      {error && (
        <div className="rounded-lg p-3 mb-3 text-xs bg-red-50 border border-red-200 text-red-700 dark:bg-red-500/10 dark:border-red-500/30 dark:text-red-400">
          {error}
        </div>
      )}

      {loading && rows.length === 0 ? (
        <div className="py-16">
          <QuoteScroller quotes={QUOTES} spinner heading="Loading your leads…" classNames={quoteStyles} />
        </div>
      ) : rows.length === 0 ? (
        <div className="text-center py-12">
          <p className="text-sm text-stone-400 dark:text-zinc-500">
            {selectedQuery && selectedQuery !== "adhoc" && !queries.find((q) => q.id === selectedQuery)?.last_run_at
              ? "This query hasn't run yet."
              : total === 0 && !search && !dateFrom && !dateTo && !selectedQuery && statuses.length === STATUSES.length
                ? "No leads yet — run a search."
                : "No leads match this filter."}
          </p>
        </div>
      ) : (
        <>
          <TableShell classNames={tableShellStyles}>
            <thead className="border-b border-stone-200 dark:border-zinc-800">
              <tr>
                <SortHeader label="Score" col="score" activeCol={sortCol} dir={sortDir} onSort={onSort} classNames={sortHeaderStyles} />
                <SortHeader label="Post" activeCol={sortCol} dir={sortDir} onSort={onSort} classNames={sortHeaderStyles} />
                <SortHeader label="Author" col="followers" activeCol={sortCol} dir={sortDir} onSort={onSort} classNames={sortHeaderStyles} />
                <SortHeader label="Replies" col="replies" activeCol={sortCol} dir={sortDir} onSort={onSort} classNames={sortHeaderStyles} />
                <SortHeader label="Posted" col="posted" activeCol={sortCol} dir={sortDir} onSort={onSort} classNames={sortHeaderStyles} />
                <SortHeader label="" activeCol={sortCol} dir={sortDir} onSort={onSort} classNames={actionsHeaderStyles} />
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => {
                const expanded = open === r.id;
                return (
                  <LeadRow
                    key={r.id}
                    row={r}
                    expanded={expanded}
                    timeZone={timeZone}
                    queryName={queryName(r.query_id)}
                    onToggle={() => setOpen(expanded ? null : r.id)}
                    onMark={mark}
                  />
                );
              })}
            </tbody>
          </TableShell>
          <PageControls page={page} pageSize={PAGE_SIZE} total={total} onPage={setPage} classNames={pageControlsStyles} />
        </>
      )}
    </div>
  );
}

function LeadRow({ row: r, expanded, timeZone, queryName, onToggle, onMark }: {
  row: ConversationRow;
  expanded: boolean;
  timeZone: string;
  queryName: string;
  onToggle: () => void;
  onMark: (e: React.MouseEvent, row: ConversationRow, status: ConversationStatus) => void;
}) {
  const dim = r.status === "dismissed" ? "opacity-50" : "";
  return (
    <>
      <tr
        onClick={onToggle}
        className={`cursor-pointer border-b border-stone-100 dark:border-zinc-900 hover:bg-stone-50 dark:hover:bg-zinc-900/60 ${dim} ${expanded ? "bg-stone-50 dark:bg-zinc-900/40" : ""}`}
      >
        <td className="px-3 py-2.5 align-top whitespace-nowrap">
          <span className="mr-1 inline-block align-middle text-stone-300 dark:text-zinc-600">
            {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
          </span>
          <span className={`inline-block rounded-md px-2 py-0.5 text-xs font-semibold tabular-nums ${TONE_CLASS[scoreTone(r.score)]}`}>
            {r.score}
          </span>
          <span className="ml-1.5 inline-flex gap-1 align-middle text-stone-400 dark:text-zinc-500">
            {r.signals.includes("need") && <MessageSquare className="h-3.5 w-3.5" aria-label={SIGNAL_TITLES.need} />}
            {r.has_media && <Image className="h-3.5 w-3.5" aria-label="Has a photo" />}
          </span>
        </td>
        <td className="px-3 py-2.5 align-top max-w-xl">
          <p className={`text-stone-700 dark:text-zinc-300 ${expanded ? "" : "line-clamp-2"}`}>{r.text}</p>
        </td>
        <td className="px-3 py-2.5 align-top text-xs whitespace-nowrap">
          <a
            href={r.url}
            target="_blank"
            rel="noopener noreferrer"
            onClick={(e) => e.stopPropagation()}
            className="inline-flex items-center gap-1 text-stone-600 hover:text-amber-600 dark:text-zinc-300 dark:hover:text-amber-400"
          >
            @{r.author_username}
            <ExternalLink className="h-3 w-3" />
          </a>
          <div className="mt-0.5 inline-flex items-center gap-1 text-stone-400 dark:text-zinc-500">
            <Users className="h-3 w-3" />
            {compactCount(r.author_followers)}
          </div>
        </td>
        <td className="px-3 py-2.5 align-top text-xs text-stone-500 dark:text-zinc-400 tabular-nums">
          {r.reply_count}
        </td>
        <td className="px-3 py-2.5 align-top text-xs text-stone-400 dark:text-zinc-500 whitespace-nowrap">
          {when(r.posted_at, timeZone)}
        </td>
        <td className="px-3 py-2.5 align-top text-right whitespace-nowrap">
          <span className="inline-flex gap-2">
            {STATUS_ACTIONS.map(({ status, Icon, title }) => (
              <button
                key={status}
                onClick={(e) => onMark(e, r, status)}
                title={title}
                className={r.status === status ? "text-amber-500" : "text-stone-300 hover:text-amber-500 dark:text-zinc-600"}
              >
                <Icon className="h-4 w-4" />
              </button>
            ))}
          </span>
        </td>
      </tr>
      {expanded && (
        <tr className={`border-b border-stone-100 dark:border-zinc-900 ${dim}`}>
          <td colSpan={6} className="px-3 pb-3 pt-0">
            <div className="ml-6 grid gap-x-8 gap-y-1 rounded-lg bg-stone-50 p-3 text-xs text-stone-500 dark:bg-zinc-900/60 dark:text-zinc-400 sm:grid-cols-2">
              <div className="flex flex-wrap gap-1.5 sm:col-span-2">
                {r.signals.length === 0 && <span>no signals fired</span>}
                {r.signals.map((s) => (
                  <span key={s} className="rounded-full border border-stone-300 px-2 py-0.5 dark:border-zinc-700" title={SIGNAL_TITLES[s] ?? s}>
                    {SIGNAL_TITLES[s] ?? s}
                  </span>
                ))}
              </div>
              {r.author_location && (
                <div className="inline-flex items-center gap-1"><MapPin className="h-3 w-3" /> {r.author_location}</div>
              )}
              <div>♥ {r.like_count} · {r.is_reply ? "a reply in the thread" : "top of the thread"}</div>
              <div>Found {when(r.found_at, timeZone)} · last seen {when(r.last_seen_at, timeZone)}</div>
              <div>From <span className="text-stone-700 dark:text-zinc-300">{queryName}</span>{r.status_at && <> · {r.status} {when(r.status_at, timeZone)}</>}</div>
              <a
                href={r.url}
                target="_blank"
                rel="noopener noreferrer"
                onClick={(e) => e.stopPropagation()}
                className="inline-flex items-center gap-1 text-amber-600 hover:underline dark:text-amber-400 sm:col-span-2"
              >
                Open on X <ExternalLink className="h-3 w-3" />
              </a>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
