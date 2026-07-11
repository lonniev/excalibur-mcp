import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  createPost, deletePost, getPost, listPosts, postTweet, updatePost,
  type PostSummary, type Recurrence, type SortDir,
} from "../lib/mcp";
import { uid } from "../lib/editorDoc";
import TweetPreviewModal from "./TweetPreviewModal";
import { PageControls, SortHeader, TableShell } from "./PagedTable";
import TableFilter from "./TableFilter";
import QuoteScroller from "./QuoteScroller";
import SchedulerHealth from "./SchedulerHealth";

// The status toggle-chiclets. Each is an independent include filter: toggled ON
// means "show posts with this status", OFF means "exclude them" — together they
// form a select/reject chain. `sending` is the transient state the scheduler
// stamps when it claims a due post to fire it; it's a chiclet so a claimed (or
// stuck) post is never invisible. The "All" chiclet (rendered separately) selects
// or clears the whole set. Default is everything selected — equivalent to the old
// unfiltered view.
const POST_STATUSES = ["draft", "scheduled", "sending", "paused", "sent", "archived"] as const;
const DATE_FIELDS = [
  { value: "created", label: "Created" },
  { value: "updated", label: "Updated" },
  { value: "scheduled", label: "Scheduled" },
  { value: "sent", label: "Posted" },
];
const PAGE_SIZE = 25;

const statusStyle: Record<string, string> = {
  draft: "bg-stone-100 text-stone-600 dark:bg-zinc-800 dark:text-zinc-300",
  scheduled: "bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-400",
  // Transient: the scheduler has claimed this post and is resolving its dynamic
  // blocks / posting it right now. Pulses so it reads as in-progress, not idle.
  sending: "bg-sky-100 text-sky-700 dark:bg-sky-500/15 dark:text-sky-400 animate-pulse",
  // A "needs attention" stop-state: the scheduler paused this post after a
  // non-transient failure (e.g. a lapsed X subscription). Distinct from the
  // grey draft fallback so it reads as actionable, not idle.
  paused: "bg-rose-100 text-rose-700 dark:bg-rose-500/15 dark:text-rose-400",
  sent: "bg-green-100 text-green-700 dark:bg-green-500/15 dark:text-green-400",
  archived: "bg-stone-100 text-stone-400 dark:bg-zinc-800 dark:text-zinc-500",
};

// Friendly labels for a held-attempt reason recorded by the scheduler Worker.
// Anything unmapped (e.g. a raw x_api_error string) shows verbatim.
function attemptLabel(reason: string): string {
  if (reason.startsWith("x_api_error")) {
    // An X 402 is a lapsed developer subscription / access tier — a billing fix
    // at X, not a transient network blip. Call it out distinctly so the human
    // knows where to act.
    if (reason.includes("402") || /subscription|access tier/i.test(reason)) {
      return "X subscription/tier";
    }
    return "X network error";
  }
  return (
    {
      insufficient_balance: "out of credits",
      oauth_token_expired: "X access expired",
      oauth_unavailable: "X not connected",
      empty_text_cache: "empty content",
      pricing_unavailable: "pricing unavailable",
    } as Record<string, string>
  )[reason] ?? reason;
}

// Material Design action glyphs (Apache-2.0), inlined as `currentColor` paths
// so each button's hover color flows straight through — one concept, one icon.
const ICONS = {
  // content_copy
  duplicate: "M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z",
  // play_arrow
  resume: "M8 5v14l11-7z",
  // event_busy (calendar with ✕ — "remove from schedule")
  toDraft: "M9.31 17l2.44-2.44L14.19 17l1.06-1.06-2.44-2.44 2.44-2.44L14.19 10l-2.44 2.44L9.31 10l-1.06 1.06 2.44 2.44-2.44 2.44L9.31 17zM19 3h-1V1h-2v2H8V1H6v2H5c-1.11 0-1.99.9-1.99 2L3 19c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 16H5V8h14v11z",
  // repeat
  repost: "M7 7h10v3l4-4-4-4v3H5v6h2V7zm10 10H7v-3l-4 4 4 4v-3h12v-6h-2v4z",
  // archive
  archive: "M20.54 5.23l-1.39-1.68C18.88 3.21 18.47 3 18 3H6c-.47 0-.88.21-1.16.55L3.46 5.23C3.17 5.57 3 6.02 3 6.5V19c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V6.5c0-.48-.17-.93-.46-1.27zM12 17.5L6.5 12H10v-2h4v2h3.5L12 17.5zM5.12 5l.81-1h12l.94 1H5.12z",
  // delete
  delete: "M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z",
  // visibility (peek at the posted tweet)
  visibility: "M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z",
};

/// One row-action icon button. Muted by default; `hover` supplies the accent on
/// hover. `busy` pulses the glyph and disables the click while in flight (the
/// old text affordance showed "…" — the pulse reads the same, without a layout
/// shift). Keeps a `title`/`aria-label` so the action name survives the icon.
function ActionIcon({
  path, title, onClick, hover, busy = false,
}: {
  path: string;
  title: string;
  onClick: (e: React.MouseEvent) => void;
  hover: string;
  busy?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={busy}
      title={title}
      aria-label={title}
      className={`p-1 rounded text-stone-400 dark:text-zinc-500 transition-colors disabled:cursor-not-allowed ${hover}`}
    >
      <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" className={busy ? "animate-pulse" : ""} aria-hidden>
        <path d={path} />
      </svg>
    </button>
  );
}

export default function PostsPage() {
  const nav = useNavigate();
  const [posts, setPosts] = useState<PostSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  // The set of statuses to include. Starts fully selected (== the old "all" tab).
  const [selected, setSelected] = useState<Set<string>>(() => new Set(POST_STATUSES));
  const [sortCol, setSortCol] = useState("created");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [search, setSearch] = useState("");
  const [dateField, setDateField] = useState("created");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [loading, setLoading] = useState(false);
  // True once the first fetch has completed — the search/date filter controls
  // only appear with the table after loading, not before it (they aren't needed
  // to load the first table).
  const [hasLoaded, setHasLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [reposting, setReposting] = useState<string | null>(null);
  const [resuming, setResuming] = useState<string | null>(null);
  const [returningToDraft, setReturningToDraft] = useState<string | null>(null);
  const [duplicating, setDuplicating] = useState<string | null>(null);
  const [preview, setPreview] = useState<{ url: string; text: string } | null>(null);

  const refresh = useCallback(async () => {
    // An empty include-set matches nothing by definition — render the empty state
    // without troubling the backend (whose bare `status` means "all", not "none").
    if (selected.size === 0) {
      setPosts([]);
      setTotal(0);
      setHasLoaded(true);
      setError(null);
      return;
    }
    // Full set == unfiltered; a strict subset is sent comma-joined for `status IN`.
    const status =
      selected.size === POST_STATUSES.length
        ? undefined
        : POST_STATUSES.filter((s) => selected.has(s)).join(",");
    setLoading(true);
    setError(null);
    try {
      const r = await listPosts({
        status, sortCol, sortDir, page, pageSize: PAGE_SIZE,
        search, dateFrom, dateTo, dateField,
      });
      if (r.error) setError(r.error);
      setPosts(r.posts ?? []);
      setTotal(r.total ?? 0);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setHasLoaded(true);
      setLoading(false);
    }
  }, [selected, sortCol, sortDir, page, search, dateFrom, dateTo, dateField]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  function onSort(col: string, dir: SortDir) {
    setSortCol(col);
    setSortDir(dir);
    setPage(0);
  }

  // Toggle a single status in/out of the include-set.
  function toggleStatus(s: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
    setPage(0);
  }

  // "All" is a convenience: when everything is already selected it clears the set
  // (reject-all); otherwise it selects the whole set.
  const allSelected = selected.size === POST_STATUSES.length;
  function toggleAll() {
    setSelected(allSelected ? new Set() : new Set(POST_STATUSES));
    setPage(0);
  }

  async function handleDelete(e: React.MouseEvent, id: string, hard: boolean) {
    e.stopPropagation();
    e.preventDefault();
    if (hard && !window.confirm("Permanently delete this post? This cannot be undone.")) return;
    setError(null);
    try {
      await deletePost(id, hard);
      await refresh();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function handleRepost(e: React.MouseEvent, id: string) {
    e.stopPropagation();
    e.preventDefault();
    setError(null);
    setNotice(null);
    setReposting(id);
    try {
      const row = await getPost(id);
      const text = (row.text_cache ?? "").trim();
      if (!text) { setError("Nothing to repost."); return; }
      const r = await postTweet(text);
      if (r.error || r.success === false) setError(r.message || r.error || "Repost failed.");
      else setNotice("Reposted to X.");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setReposting(null);
    }
  }

  // Resume a paused post: flip it back to `scheduled` so the next scheduler
  // tick picks it up. Its publish_at is in the past, so it fires on the very
  // next tick (and recurrence resumes from there). Use once the cause of the
  // pause (e.g. a lapsed X subscription) is fixed at the provider.
  async function handleResume(e: React.MouseEvent, id: string) {
    e.stopPropagation();
    e.preventDefault();
    setError(null);
    setNotice(null);
    setResuming(id);
    try {
      const r = await updatePost({ postId: id, patch: { status: "scheduled" }, clientReqId: uid() });
      if (r.error) setError(r.error);
      else {
        setNotice("Resumed — rescheduled. The next scheduler tick will post it.");
        await refresh();
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setResuming(null);
    }
  }

  // Return a post to Draft — the universal rescue for a post that left the table's
  // active views: a scheduled/paused one you want to pull back, or one the
  // scheduler claimed (`sending`) and couldn't finish. Draft is excluded from the
  // scheduler's due set, so this cleanly unschedules it for editing.
  async function handleReturnToDraft(e: React.MouseEvent, id: string) {
    e.stopPropagation();
    e.preventDefault();
    setError(null);
    setNotice(null);
    setReturningToDraft(id);
    try {
      const r = await updatePost({ postId: id, patch: { status: "draft" }, clientReqId: uid() });
      if (r.error) setError(r.error);
      else {
        setNotice("Returned to Draft — it won't post until you schedule it again.");
        await refresh();
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setReturningToDraft(null);
    }
  }

  // Duplicate a post: a deep copy of its content AND schedule (publish time,
  // recurrence cadence, cease date) into a fresh draft, then open it in the
  // editor. The copy lands as `draft`, so even with a publish time carried over
  // it never fires until the user reviews and schedules it — no double-posting
  // alongside the original. Works from any source status (draft, scheduled, …).
  async function handleDuplicate(e: React.MouseEvent, id: string) {
    e.stopPropagation();
    e.preventDefault();
    setError(null);
    setNotice(null);
    setDuplicating(id);
    try {
      const row = await getPost(id);
      const r = await createPost({
        doc: row.doc,
        textCache: row.text_cache ?? "",
        status: "draft",
        title: row.title || undefined,
        publishAt: row.publish_at ?? undefined,
        recurrence: row.recurrence ? (row.recurrence as Recurrence) : undefined,
        ceaseAt: row.cease_at ?? undefined,
        clientReqId: uid(),
      });
      if (r.error || !r.post_id) { setError(r.error || "Duplicate failed."); return; }
      nav(`/post/${r.post_id}`);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setDuplicating(null);
    }
  }

  return (
    <div className="mx-auto w-[90%] max-w-[1600px] px-4 py-6">
      {preview && (
        <TweetPreviewModal url={preview.url} text={preview.text} onClose={() => setPreview(null)} />
      )}
      <div className="flex items-center gap-3 mb-4">
        <h1 className="text-lg font-semibold">Posts</h1>
        <SchedulerHealth />
        <Link
          to="/new"
          className="ml-auto bg-amber-600 hover:bg-amber-500 text-white text-sm px-4 py-2 rounded-lg transition-colors"
        >
          + Compose
        </Link>
      </div>

      <div className="flex flex-wrap gap-1.5 mb-4 text-xs">
        <button
          onClick={toggleAll}
          disabled={loading}
          className={`px-2.5 py-1 rounded-lg capitalize border transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
            allSelected
              ? "bg-amber-100 text-amber-800 border-amber-200 dark:bg-amber-500/15 dark:text-amber-400 dark:border-amber-500/30"
              : "text-stone-500 border-transparent hover:bg-stone-100 dark:text-zinc-400 dark:hover:bg-zinc-800"
          }`}
        >
          all
        </button>
        {POST_STATUSES.map((s) => {
          const on = selected.has(s);
          return (
            <button
              key={s}
              onClick={() => toggleStatus(s)}
              disabled={loading}
              aria-pressed={on}
              title={on ? `Showing ${s} posts — click to hide` : `Hiding ${s} posts — click to show`}
              className={`px-2.5 py-1 rounded-lg capitalize border transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
                on
                  ? "bg-amber-100 text-amber-800 border-amber-200 dark:bg-amber-500/15 dark:text-amber-400 dark:border-amber-500/30"
                  : "text-stone-400 border-dashed border-stone-300 line-through hover:bg-stone-100 hover:no-underline dark:text-zinc-500 dark:border-zinc-700 dark:hover:bg-zinc-800"
              }`}
            >
              {s}
            </button>
          );
        })}
        <button
          onClick={refresh}
          disabled={loading}
          className="ml-auto px-2.5 py-1 rounded-lg text-stone-400 hover:bg-stone-100 dark:text-zinc-500 dark:hover:bg-zinc-800 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          title="Refresh"
        >
          <span className={loading ? "inline-block animate-spin" : ""}>↻</span>
        </button>
      </div>

      {hasLoaded && (
        <TableFilter
          search={search}
          onSearch={(t) => { setSearch(t); setPage(0); }}
          dateField={dateField}
          dateFieldOptions={DATE_FIELDS}
          onDateField={(v) => { setDateField(v); setPage(0); }}
          dateFrom={dateFrom}
          dateTo={dateTo}
          onDateFrom={(v) => { setDateFrom(v); setPage(0); }}
          onDateTo={(v) => { setDateTo(v); setPage(0); }}
          onClear={() => { setSearch(""); setDateFrom(""); setDateTo(""); setDateField("created"); setPage(0); }}
        />
      )}

      {error && (
        <div className="rounded-lg p-3 mb-3 text-xs bg-red-50 border border-red-200 text-red-700 dark:bg-red-500/10 dark:border-red-500/30 dark:text-red-400">
          {error}
        </div>
      )}
      {notice && (
        <div className="rounded-lg p-3 mb-3 text-xs bg-green-50 border border-green-200 text-green-700 dark:bg-green-500/10 dark:border-green-500/30 dark:text-green-400">
          {notice}
        </div>
      )}

      {loading ? (
        // Show the loading entertainment on ANY in-flight query — not just the
        // first load. A filter/tab switch keeps the prior posts in state, so
        // without this the stale table just sits there (no feedback) and the
        // human click-spams the tabs while the MCP cold-starts.
        <QuoteScroller heading="Loading your posts…" className="py-16" />
      ) : posts.length === 0 ? (
        <div className="text-center py-12">
          <p className="text-sm text-stone-400 dark:text-zinc-500 mb-3">
            {search || dateFrom || dateTo || !allSelected
              ? "No posts match this filter."
              : "No posts yet."}
          </p>
          <Link to="/new" className="text-sm text-amber-600 dark:text-amber-400 hover:underline">
            Compose a new post →
          </Link>
        </div>
      ) : (
        <>
          <TableShell>
            <thead className="border-b border-stone-200 dark:border-zinc-800">
              <tr>
                <SortHeader label="Status" col="status" activeCol={sortCol} dir={sortDir} onSort={onSort} />
                <SortHeader label="Post" activeCol={sortCol} dir={sortDir} onSort={onSort} />
                <SortHeader label="Scheduled" col="scheduled" activeCol={sortCol} dir={sortDir} onSort={onSort} />
                <SortHeader label="Edited" col="updated" activeCol={sortCol} dir={sortDir} onSort={onSort} />
                <SortHeader label="Posted" activeCol={sortCol} dir={sortDir} onSort={onSort} />
                <SortHeader label="" activeCol={sortCol} dir={sortDir} onSort={onSort} className="text-right" />
              </tr>
            </thead>
            <tbody>
              {posts.map((p) => (
                <tr
                  key={p.post_id}
                  onClick={() => nav(`/post/${p.post_id}`)}
                  className="border-b border-stone-100 last:border-0 dark:border-zinc-900 hover:bg-stone-50 dark:hover:bg-zinc-900/60 cursor-pointer"
                >
                  <td className="px-3 py-2.5 align-top">
                    <span className={`text-xs px-2 py-0.5 rounded-full capitalize ${statusStyle[p.status] ?? statusStyle.draft}`}>
                      {p.status}
                    </span>
                    {p.status === "scheduled" && p.last_attempt_reason && (
                      <span
                        className="mt-1 flex items-center gap-1 text-[11px] text-rose-600 dark:text-rose-400"
                        title={`Scheduler tried to post${p.last_attempt_at ? ` at ${fmt(p.last_attempt_at)}` : ""} but held it back: ${p.last_attempt_reason}. It will retry on the next tick.`}
                      >
                        ⚠ {attemptLabel(p.last_attempt_reason)}
                      </span>
                    )}
                    {p.status === "paused" && p.last_attempt_reason && (
                      <span
                        className="mt-1 flex items-center gap-1 text-[11px] text-rose-600 dark:text-rose-400"
                        title={`Scheduler paused this post${p.last_attempt_at ? ` at ${fmt(p.last_attempt_at)}` : ""}: ${p.last_attempt_reason}. Fix the cause at the provider, then Resume to reschedule it.`}
                      >
                        ⏸ {attemptLabel(p.last_attempt_reason)}
                      </span>
                    )}
                    {p.status === "sending" && (
                      <span
                        className="mt-1 flex items-center gap-1 text-[11px] text-sky-600 dark:text-sky-400"
                        title={`The scheduler claimed this post${p.last_attempt_at ? ` at ${fmt(p.last_attempt_at)}` : ""} and is posting it. If it lingers here, use "to draft" to rescue it.`}
                      >
                        ⟳ working…
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2.5 align-top max-w-md">
                    {p.title ? (
                      <>
                        <p className="truncate font-medium text-stone-900 dark:text-zinc-100">{p.title}</p>
                        {p.excerpt && <p className="truncate text-xs text-stone-500 dark:text-zinc-400">{p.excerpt}</p>}
                      </>
                    ) : (
                      <p className="truncate text-stone-800 dark:text-zinc-200">{p.excerpt || "(empty draft)"}</p>
                    )}
                  </td>
                  <td className="px-3 py-2.5 align-top text-xs text-stone-400 dark:text-zinc-500 whitespace-nowrap">
                    {p.publish_at ? fmt(p.publish_at) : "—"}
                  </td>
                  <td className="px-3 py-2.5 align-top text-xs text-stone-400 dark:text-zinc-500 whitespace-nowrap">
                    {p.updated_at ? fmt(p.updated_at) : "—"}
                  </td>
                  <td className="px-3 py-2.5 align-top text-xs whitespace-nowrap">
                    {p.last_sent_at ? (
                      p.tweet_url ? (
                        <button
                          onClick={(e) => { e.stopPropagation(); e.preventDefault(); setPreview({ url: p.tweet_url!, text: p.excerpt || "" }); }}
                          className="inline-flex items-center gap-1 text-green-600 hover:underline dark:text-green-400"
                          title={`Peek at the posted tweet (${fmt(p.last_sent_at)})`}
                        >
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" aria-hidden>
                            <path d={ICONS.visibility} />
                          </svg>
                          {fmt(p.last_sent_at)}
                        </button>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-green-600 dark:text-green-400" title={`Posted to X at ${fmt(p.last_sent_at)}`}>
                          ✓ {fmt(p.last_sent_at)}
                        </span>
                      )
                    ) : (
                      <span className="text-stone-400 dark:text-zinc-500">—</span>
                    )}
                  </td>
                  <td className="px-3 py-2.5 align-top text-right whitespace-nowrap">
                    <span className="inline-flex items-center gap-1 justify-end">
                      <ActionIcon
                        path={ICONS.duplicate}
                        title="Duplicate — open an editable draft copy of this post (unscheduled)"
                        onClick={(e) => handleDuplicate(e, p.post_id)}
                        busy={duplicating === p.post_id}
                        hover="hover:text-amber-600 dark:hover:text-amber-400"
                      />
                      {p.status === "paused" && (
                        <ActionIcon
                          path={ICONS.resume}
                          title="Resume — reschedule this post so the next scheduler tick posts it"
                          onClick={(e) => handleResume(e, p.post_id)}
                          busy={resuming === p.post_id}
                          hover="hover:text-amber-600 dark:hover:text-amber-400"
                        />
                      )}
                      {(p.status === "sending" || p.status === "scheduled" || p.status === "paused") && (
                        <ActionIcon
                          path={ICONS.toDraft}
                          title="Return to Draft — unschedule this post so you can edit it (rescues a post stuck mid-send)"
                          onClick={(e) => handleReturnToDraft(e, p.post_id)}
                          busy={returningToDraft === p.post_id}
                          hover="hover:text-amber-600 dark:hover:text-amber-400"
                        />
                      )}
                      {p.status === "sent" && (
                        <ActionIcon
                          path={ICONS.repost}
                          title="Repost to X now"
                          onClick={(e) => handleRepost(e, p.post_id)}
                          busy={reposting === p.post_id}
                          hover="hover:text-green-600 dark:hover:text-green-400"
                        />
                      )}
                      {p.status !== "archived" && (
                        <ActionIcon
                          path={ICONS.archive}
                          title="Archive"
                          onClick={(e) => handleDelete(e, p.post_id, false)}
                          hover="hover:text-amber-600 dark:hover:text-amber-400"
                        />
                      )}
                      <ActionIcon
                        path={ICONS.delete}
                        title="Delete permanently"
                        onClick={(e) => handleDelete(e, p.post_id, true)}
                        hover="hover:text-red-500 dark:hover:text-red-400"
                      />
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </TableShell>
          <PageControls page={page} pageSize={PAGE_SIZE} total={total} onPage={setPage} />
        </>
      )}
    </div>
  );
}

function fmt(iso: string): string {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString();
}
