import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Eye, ExternalLink, Image, Loader2, MessageCircle, MessageSquare, Plus, Radar,
  Search, Trash2, Users, X,
} from "lucide-react";
import {
  deleteConversationQuery, findConversations, listConversationQueries, listConversations,
  OAUTH_NEEDED_CODES, saveConversationQuery, setConversationStatus,
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
  compactCount, runSummary, scoreTone, SIGNAL_TITLES, STATUSES,
} from "../lib/conversationsPresentation";

const DATE_FIELDS = [
  { value: "found", label: "Found" },
  { value: "posted", label: "Posted" },
];
const PAGE_SIZE = 25;
const ALL = "";
const ADHOC = "adhoc";
const NEW_QUERY = "__new__";

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
  const [queryPick, setQueryPick] = useState<string>(ALL);
  const [adhoc, setAdhoc] = useState("");
  const [running, setRunning] = useState(false);
  const [lastRun, setLastRun] = useState<string | null>(null);
  const [needsXConnect, setNeedsXConnect] = useState(false);
  const [editing, setEditing] = useState<ConversationQueryRow | null>(null);
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
        queryId: queryPick === NEW_QUERY ? ALL : queryPick,
        statuses, sortCol, sortDir, page, pageSize: PAGE_SIZE, search,
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
  }, [queryPick, statuses, sortCol, sortDir, page, search, dateFrom, dateTo, dateField, timeZone]);

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

  async function run() {
    const saved = queries.find((q) => q.id === queryPick);
    const q = adhoc.trim();
    if (!saved && !q) return;
    setRunning(true);
    setError(null);
    setLastRun(null);
    try {
      const r = saved
        ? await findConversations({ queryId: saved.id })
        : await findConversations({ query: q });
      if (r.error || r.success === false) {
        if (r.error_code && OAUTH_NEEDED_CODES.has(r.error_code)) {
          setNeedsXConnect(true);
          setError("Connect your X account before searching.");
        } else {
          setError(r.message || r.error || "Search failed.");
        }
        return;
      }
      setLastRun(runSummary(r));
      setPage(0);
      await Promise.all([refresh(), refreshQueries()]);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRunning(false);
    }
  }

  async function mark(e: React.MouseEvent, row: ConversationRow, status: ConversationStatus) {
    e.stopPropagation();
    e.preventDefault();
    setError(null);
    try {
      const next = status === row.status ? "new" : status;
      await setConversationStatus(row.id, next);
      await refresh();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function removeQuery(id: string) {
    if (!window.confirm("Delete this saved query? Its leads are kept.")) return;
    setError(null);
    try {
      await deleteConversationQuery(id);
      if (queryPick === id) setQueryPick(ALL);
      setEditing(null);
      await refreshQueries();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  const picked = queries.find((q) => q.id === queryPick);
  const canRun = !running && (Boolean(picked) || adhoc.trim().length > 0);

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

      <div className="flex flex-wrap items-center gap-2 mb-3">
        <select
          value={queryPick}
          onChange={(e) => {
            const v = e.target.value;
            if (v === NEW_QUERY) {
              setEditing({ id: "", name: "", query: "", weights: {}, safe_defaults: true,
                since_id: null, last_run_at: null, last_run_posts_read: null, created_at: "", updated_at: "" });
              return;
            }
            setQueryPick(v);
            setPage(0);
          }}
          className="rounded-lg border border-stone-300 bg-white px-2 py-1.5 text-sm dark:border-zinc-700 dark:bg-zinc-900"
          title="Which leads to show, and which saved query Run uses"
        >
          <option value={ALL}>All leads</option>
          <option value={ADHOC}>Ad hoc</option>
          {queries.map((q) => (
            <option key={q.id} value={q.id}>{q.name}</option>
          ))}
          <option value={NEW_QUERY}>+ New saved query</option>
        </select>
        {picked ? (
          <button
            onClick={() => setEditing(picked)}
            className="text-xs text-stone-500 hover:text-amber-600 dark:text-zinc-400 dark:hover:text-amber-400"
            title={picked.query}
          >
            edit
          </button>
        ) : (
          <input
            value={adhoc}
            onChange={(e) => setAdhoc(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter" && canRun) run(); }}
            placeholder='X search clause, e.g. ("MCP server" OR "MCP tool") (monetize OR billing)'
            className="min-w-72 flex-1 rounded-lg border border-stone-300 bg-white px-3 py-1.5 text-sm dark:border-zinc-700 dark:bg-zinc-900"
          />
        )}
        <button
          onClick={run}
          disabled={!canRun}
          className="inline-flex items-center gap-1.5 rounded-lg bg-amber-600 px-3 py-1.5 text-sm text-white hover:bg-amber-500 disabled:opacity-40"
          title="Search X's last 7 days"
        >
          {running ? <Loader2 className="h-4 w-4 animate-spin" /> : <Radar className="h-4 w-4" />}
          Run
        </button>
        {lastRun && <span className="text-xs text-stone-500 dark:text-zinc-400">{lastRun}</span>}
      </div>

      {editing && (
        <QueryEditor
          row={editing}
          onClose={() => setEditing(null)}
          onSaved={async (id) => { setEditing(null); await refreshQueries(); setQueryPick(id); }}
          onDelete={removeQuery}
          onError={setError}
        />
      )}

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
            {total === 0 && !search && !dateFrom && !dateTo && statuses.length === STATUSES.length
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
              {rows.map((r) => (
                <tr
                  key={r.id}
                  className={`border-b border-stone-100 last:border-0 dark:border-zinc-900 hover:bg-stone-50 dark:hover:bg-zinc-900/60 ${
                    r.status === "dismissed" ? "opacity-50" : ""
                  }`}
                >
                  <td className="px-3 py-2.5 align-top whitespace-nowrap">
                    <span className={`inline-block rounded-md px-2 py-0.5 text-xs font-semibold tabular-nums ${TONE_CLASS[scoreTone(r.score)]}`}>
                      {r.score}
                    </span>
                    <span className="ml-1.5 inline-flex gap-1 align-middle text-stone-400 dark:text-zinc-500">
                      {r.signals.includes("need") && <MessageSquare className="h-3.5 w-3.5" aria-label={SIGNAL_TITLES.need} />}
                      {r.has_media && <Image className="h-3.5 w-3.5" aria-label="Has a photo" />}
                    </span>
                  </td>
                  <td className="px-3 py-2.5 align-top max-w-xl">
                    <a
                      href={r.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="group block"
                      title={r.signals.map((s) => SIGNAL_TITLES[s] ?? s).join(" · ")}
                    >
                      <p className="line-clamp-2 text-stone-700 group-hover:text-amber-700 dark:text-zinc-300 dark:group-hover:text-amber-300">
                        {r.text}
                      </p>
                    </a>
                  </td>
                  <td className="px-3 py-2.5 align-top text-xs whitespace-nowrap">
                    <a
                      href={r.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-stone-600 hover:text-amber-600 dark:text-zinc-300 dark:hover:text-amber-400"
                    >
                      @{r.author_username}
                      <ExternalLink className="h-3 w-3" />
                    </a>
                    <div className="mt-0.5 inline-flex items-center gap-1 text-stone-400 dark:text-zinc-500">
                      <Users className="h-3 w-3" />
                      {compactCount(r.author_followers)}
                      {r.author_location && <span className="ml-1 truncate max-w-32">· {r.author_location}</span>}
                    </div>
                  </td>
                  <td className="px-3 py-2.5 align-top text-xs text-stone-500 dark:text-zinc-400 tabular-nums">
                    {r.reply_count}
                  </td>
                  <td className="px-3 py-2.5 align-top text-xs text-stone-400 dark:text-zinc-500 whitespace-nowrap">
                    {r.posted_at ? formatDateTime(r.posted_at, timeZone) : "—"}
                  </td>
                  <td className="px-3 py-2.5 align-top text-right whitespace-nowrap">
                    <span className="inline-flex gap-2">
                      {STATUS_ACTIONS.map(({ status, Icon, title }) => (
                        <button
                          key={status}
                          onClick={(e) => mark(e, r, status)}
                          title={title}
                          className={
                            r.status === status
                              ? "text-amber-500"
                              : "text-stone-300 hover:text-amber-500 dark:text-zinc-600"
                          }
                        >
                          <Icon className="h-4 w-4" />
                        </button>
                      ))}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </TableShell>
          <PageControls page={page} pageSize={PAGE_SIZE} total={total} onPage={setPage} classNames={pageControlsStyles} />
        </>
      )}
    </div>
  );
}

function QueryEditor({ row, onClose, onSaved, onDelete, onError }: {
  row: ConversationQueryRow;
  onClose: () => void;
  onSaved: (id: string) => Promise<void>;
  onDelete: (id: string) => Promise<void>;
  onError: (msg: string) => void;
}) {
  const [name, setName] = useState(row.name);
  const [query, setQuery] = useState(row.query);
  const [safe, setSafe] = useState(row.safe_defaults);
  const [saving, setSaving] = useState(false);

  async function save() {
    setSaving(true);
    try {
      const r = await saveConversationQuery({
        id: row.id || undefined, name, query, safeDefaults: safe,
      });
      if (r.error || r.success === false || !r.query) {
        onError(r.message || r.error || "Couldn't save the query.");
        return;
      }
      await onSaved(r.query.id);
    } catch (e) {
      onError((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="mb-3 rounded-lg border border-stone-200 bg-stone-50 p-3 dark:border-zinc-800 dark:bg-zinc-900/60">
      <div className="flex flex-wrap items-center gap-2">
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Name"
          className="w-48 rounded-lg border border-stone-300 bg-white px-3 py-1.5 text-sm dark:border-zinc-700 dark:bg-zinc-950"
        />
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder='X search clause — your own nouns, e.g. ("sound money" OR mises) (recommend OR "what should I read")'
          className="min-w-72 flex-1 rounded-lg border border-stone-300 bg-white px-3 py-1.5 text-sm dark:border-zinc-700 dark:bg-zinc-950"
        />
        <label className="inline-flex items-center gap-1.5 text-xs text-stone-500 dark:text-zinc-400" title="Append -is:retweet -has:links -has:cashtags lang:en">
          <input type="checkbox" checked={safe} onChange={(e) => setSafe(e.target.checked)} />
          safe defaults
        </label>
        <button
          onClick={save}
          disabled={saving || !name.trim() || !query.trim()}
          className="inline-flex items-center gap-1 rounded-lg bg-amber-600 px-3 py-1.5 text-sm text-white hover:bg-amber-500 disabled:opacity-40"
        >
          <Plus className="h-4 w-4" /> Save
        </button>
        {row.id && (
          <button onClick={() => onDelete(row.id)} title="Delete saved query" className="text-stone-400 hover:text-red-500">
            <Trash2 className="h-4 w-4" />
          </button>
        )}
        <button onClick={onClose} title="Close" className="text-stone-400 hover:text-stone-600">
          <X className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}
