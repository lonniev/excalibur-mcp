import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  deletePost, getPost, listPosts, postTweet,
  type PostSummary, type SortDir,
} from "../lib/mcp";
import TweetPreviewModal from "./TweetPreviewModal";
import { PageControls, SortHeader, TableShell } from "./PagedTable";

const STATUS_FILTERS = ["", "draft", "scheduled", "sent", "archived"] as const;
const PAGE_SIZE = 25;

const statusStyle: Record<string, string> = {
  draft: "bg-stone-100 text-stone-600 dark:bg-zinc-800 dark:text-zinc-300",
  scheduled: "bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-400",
  sent: "bg-green-100 text-green-700 dark:bg-green-500/15 dark:text-green-400",
  archived: "bg-stone-100 text-stone-400 dark:bg-zinc-800 dark:text-zinc-500",
};

// Friendly labels for a held-attempt reason recorded by the scheduler Worker.
// Anything unmapped (e.g. a raw x_api_error string) shows verbatim.
function attemptLabel(reason: string): string {
  if (reason.startsWith("x_api_error")) return "X network error";
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
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [reposting, setReposting] = useState<string | null>(null);
  const [preview, setPreview] = useState<{ url: string; text: string } | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await listPosts({
        status: filter || undefined, sortCol, sortDir, page, pageSize: PAGE_SIZE,
      });
      if (r.error) setError(r.error);
      setPosts(r.posts ?? []);
      setTotal(r.total ?? 0);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [filter, sortCol, sortDir, page]);

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

  const action = "hover:text-amber-600 dark:hover:text-amber-400 cursor-pointer";

  return (
    <div className="max-w-4xl mx-auto px-4 py-6">
      {preview && (
        <TweetPreviewModal url={preview.url} text={preview.text} onClose={() => setPreview(null)} />
      )}
      <div className="flex items-center mb-4">
        <h1 className="text-lg font-semibold">Posts</h1>
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
            className={`px-2.5 py-1 rounded-lg capitalize transition-colors ${
              filter === s
                ? "bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-400"
                : "text-stone-500 hover:bg-stone-100 dark:text-zinc-400 dark:hover:bg-zinc-800"
            }`}
          >
            {s || "all"}
          </button>
        ))}
        <button
          onClick={refresh}
          className="ml-auto px-2.5 py-1 rounded-lg text-stone-400 hover:bg-stone-100 dark:text-zinc-500 dark:hover:bg-zinc-800 transition-colors"
        >
          ↻
        </button>
      </div>

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

      {loading && posts.length === 0 ? (
        <p className="text-sm text-stone-400 dark:text-zinc-500 py-10 text-center">Loading…</p>
      ) : posts.length === 0 ? (
        <div className="text-center py-12">
          <p className="text-sm text-stone-400 dark:text-zinc-500 mb-3">No posts yet.</p>
          <Link to="/new" className="text-sm text-amber-600 dark:text-amber-400 hover:underline">
            Compose your first post →
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
                  </td>
                  <td className="px-3 py-2.5 align-top max-w-md">
                    <p className="truncate text-stone-800 dark:text-zinc-200">{p.excerpt || "(empty draft)"}</p>
                    {p.last_sent_at && (
                      <p
                        className="mt-0.5 text-[11px] text-green-600 dark:text-green-400"
                        title={`Last posted to X by the scheduler at ${fmt(p.last_sent_at)}`}
                      >
                        ✓ last posted {fmt(p.last_sent_at)}
                      </p>
                    )}
                  </td>
                  <td className="px-3 py-2.5 align-top text-xs text-stone-400 dark:text-zinc-500 whitespace-nowrap">
                    {p.publish_at ? fmt(p.publish_at) : "—"}
                  </td>
                  <td className="px-3 py-2.5 align-top text-xs text-stone-400 dark:text-zinc-500 whitespace-nowrap">
                    {p.updated_at ? fmt(p.updated_at) : "—"}
                  </td>
                  <td className="px-3 py-2.5 align-top text-right whitespace-nowrap">
                    <span className="inline-flex gap-2 text-xs text-stone-400 dark:text-zinc-500">
                      {p.tweet_url && (
                        <span
                          role="button"
                          onClick={(e) => { e.stopPropagation(); e.preventDefault(); setPreview({ url: p.tweet_url!, text: p.excerpt || "" }); }}
                          className="hover:text-sky-600 dark:hover:text-sky-400 cursor-pointer"
                          title="Preview the last posted tweet on X"
                        >
                          preview
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
