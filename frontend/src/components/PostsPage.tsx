import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { deletePost, listPosts, type PostSummary } from "../lib/mcp";

const STATUS_FILTERS = ["", "draft", "scheduled", "sent", "archived"] as const;

const statusStyle: Record<string, string> = {
  draft: "bg-stone-100 text-stone-600 dark:bg-zinc-800 dark:text-zinc-300",
  scheduled: "bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-400",
  sent: "bg-green-100 text-green-700 dark:bg-green-500/15 dark:text-green-400",
  archived: "bg-stone-100 text-stone-400 dark:bg-zinc-800 dark:text-zinc-500",
};

export default function PostsPage() {
  const nav = useNavigate();
  const [posts, setPosts] = useState<PostSummary[]>([]);
  const [filter, setFilter] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await listPosts({ status: filter || undefined, limit: 50 });
      if (r.error) setError(r.error);
      setPosts(r.posts ?? []);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => {
    refresh();
  }, [refresh]);

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

  return (
    <div className="max-w-3xl mx-auto px-4 py-6">
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
            onClick={() => setFilter(s)}
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
        <ul className="space-y-2">
          {posts.map((p) => (
            <li key={p.post_id}>
              <button
                onClick={() => nav(`/post/${p.post_id}`)}
                className="w-full text-left rounded-lg border border-stone-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-3 flex items-start gap-3 hover:border-amber-300 dark:hover:border-amber-500/40 transition-colors"
              >
                <span className={`text-xs px-2 py-0.5 rounded-full shrink-0 capitalize ${statusStyle[p.status] ?? statusStyle.draft}`}>
                  {p.status}
                </span>
                <div className="min-w-0 flex-1">
                  <p className="text-sm truncate">{p.excerpt || "(empty draft)"}</p>
                  <p className="text-xs text-stone-400 dark:text-zinc-500 mt-0.5">
                    {p.publish_at ? `scheduled → ${fmt(p.publish_at)}` : p.updated_at ? `edited ${fmt(p.updated_at)}` : ""}
                  </p>
                </div>
                <span className="flex gap-2 shrink-0 text-xs text-stone-400 dark:text-zinc-500">
                  {p.status !== "archived" && (
                    <span
                      role="button"
                      onClick={(e) => handleDelete(e, p.post_id, false)}
                      className="hover:text-amber-600 dark:hover:text-amber-400"
                      title="Archive"
                    >
                      archive
                    </span>
                  )}
                  <span
                    role="button"
                    onClick={(e) => handleDelete(e, p.post_id, true)}
                    className="hover:text-red-500 dark:hover:text-red-400"
                    title="Delete permanently"
                  >
                    delete
                  </span>
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function fmt(iso: string): string {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString();
}
