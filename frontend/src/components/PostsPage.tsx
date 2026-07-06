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

// `sending` is the transient state the scheduler stamps when it claims a due post
// to fire it. It's included here so a claimed (or stuck) post is never invisible —
// a post that leaves `scheduled` but hasn't reached `sent` can always be found.
const STATUS_FILTERS = ["", "draft", "scheduled", "sending", "paused", "sent", "archived"] as const;
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

export default function PostsPage() {
  const nav = useNavigate();
  const [posts, setPosts] = useState<PostSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [filter, setFilter] = useState("");
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
    setLoading(true);
    setError(null);
    try {
      const r = await listPosts({
        status: filter || undefined, sortCol, sortDir, page, pageSize: PAGE_SIZE,
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
  }, [filter, sortCol, sortDir, page, search, dateFrom, dateTo, dateField]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  function onSort(col: string, dir: SortDir) {
    setSortCol(col);
    setSortDir(dir);
    setPage(0);
  }

  function onFilter(s: string) {
    setFilter(s);
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

  const action = "hover:text-amber-600 dark:hover:text-amber-400 cursor-pointer";

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

      <div className="flex gap-1.5 mb-4 text-xs">
        {STATUS_FILTERS.map((s) => (
          <button
            key={s || "all"}
            onClick={() => onFilter(s)}
            disabled={loading}
            className={`px-2.5 py-1 rounded-lg capitalize transition-colors disabled:cursor-not-allowed ${
              filter === s
                ? "bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-400"
                : "text-stone-500 hover:bg-stone-100 dark:text-zinc-400 dark:hover:bg-zinc-800 disabled:hover:bg-transparent disabled:opacity-50"
            }`}
          >
            {s || "all"}
          </button>
        ))}
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
        (search || dateFrom || dateTo) ? (
          <div className="text-center py-12">
            <p className="text-sm text-stone-400 dark:text-zinc-500">No posts match this filter.</p>
          </div>
        ) : (
          <div className="text-center py-12">
            <p className="text-sm text-stone-400 dark:text-zinc-500 mb-3">No posts yet.</p>
            <Link to="/new" className="text-sm text-amber-600 dark:text-amber-400 hover:underline">
              Compose your first post →
            </Link>
          </div>
        )
      ) : (
        <>
          <TableShell>
            <thead className="border-b border-stone-200 dark:border-zinc-800">
              <tr>
                <SortHeader label="Status" col="status" activeCol={sortCol} dir={sortDir} onSort={onSort} />
                <SortHeader label="Post" activeCol={sortCol} dir={sortDir} onSort={onSort} />
                <SortHeader label="Scheduled" col="scheduled" activeCol={sortCol} dir={sortDir} onSort={onSort} />
                <SortHeader label="Edited" col="updated" activeCol={sortCol} dir={sortDir} onSort={onSort} />
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
                    {p.last_sent_at && (p.tweet_url ? (
                      <button
                        onClick={(e) => { e.stopPropagation(); e.preventDefault(); setPreview({ url: p.tweet_url!, text: p.excerpt || "" }); }}
                        className="mt-0.5 inline-flex items-center gap-1 text-[11px] text-green-600 hover:underline dark:text-green-400"
                        title={`Peek at the posted tweet (${fmt(p.last_sent_at)})`}
                      >
                        ✓ posted {fmt(p.last_sent_at)} 👁
                      </button>
                    ) : (
                      <p
                        className="mt-0.5 text-[11px] text-green-600 dark:text-green-400"
                        title={`Posted to X at ${fmt(p.last_sent_at)}`}
                      >
                        ✓ posted {fmt(p.last_sent_at)}
                      </p>
                    ))}
                  </td>
                  <td className="px-3 py-2.5 align-top text-xs text-stone-400 dark:text-zinc-500 whitespace-nowrap">
                    {p.publish_at ? fmt(p.publish_at) : "—"}
                  </td>
                  <td className="px-3 py-2.5 align-top text-xs text-stone-400 dark:text-zinc-500 whitespace-nowrap">
                    {p.updated_at ? fmt(p.updated_at) : "—"}
                  </td>
                  <td className="px-3 py-2.5 align-top text-right whitespace-nowrap">
                    <span className="inline-flex gap-2 text-xs text-stone-400 dark:text-zinc-500">
                      <span role="button" onClick={(e) => handleDuplicate(e, p.post_id)} className={action} title="Duplicate: open an editable draft copy of this post (unscheduled)">
                        {duplicating === p.post_id ? "…" : "duplicate"}
                      </span>
                      {p.status === "paused" && (
                        <span role="button" onClick={(e) => handleResume(e, p.post_id)} className="hover:text-amber-600 dark:hover:text-amber-400 cursor-pointer" title="Resume: reschedule this post so the next scheduler tick posts it">
                          {resuming === p.post_id ? "…" : "resume"}
                        </span>
                      )}
                      {(p.status === "sending" || p.status === "scheduled" || p.status === "paused") && (
                        <span role="button" onClick={(e) => handleReturnToDraft(e, p.post_id)} className={action} title="Return to Draft — unschedule this post so you can edit it (rescues a post stuck mid-send)">
                          {returningToDraft === p.post_id ? "…" : "to draft"}
                        </span>
                      )}
                      {p.status === "sent" && (
                        <span role="button" onClick={(e) => handleRepost(e, p.post_id)} className="hover:text-green-600 dark:hover:text-green-400 cursor-pointer" title="Repost to X now">
                          {reposting === p.post_id ? "…" : "repost"}
                        </span>
                      )}
                      {p.status !== "archived" && (
                        <span role="button" onClick={(e) => handleDelete(e, p.post_id, false)} className={action} title="Archive">
                          archive
                        </span>
                      )}
                      <span role="button" onClick={(e) => handleDelete(e, p.post_id, true)} className="hover:text-red-500 dark:hover:text-red-400 cursor-pointer" title="Delete permanently">
                        delete
                      </span>
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
