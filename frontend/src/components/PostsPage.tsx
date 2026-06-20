import { useCallback, useEffect, useState } from "react";
import {
  checkBalance,
  createPost,
  deletePost,
  listPosts,
  type PostSummary,
} from "../lib/mcp";

const STATUS_FILTERS = ["", "draft", "scheduled", "sent", "archived"] as const;

export default function PostsPage() {
  const [posts, setPosts] = useState<PostSummary[]>([]);
  const [filter, setFilter] = useState<string>("");
  const [balance, setBalance] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const [creating, setCreating] = useState(false);

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

  useEffect(() => {
    checkBalance()
      .then((b) => setBalance(b.balance_api_sats ?? null))
      .catch(() => setBalance(null));
  }, [posts.length]);

  async function handleCreate() {
    const text = draft.trim();
    if (!text) return;
    setCreating(true);
    setError(null);
    try {
      const blocks = text.split(/\n\n+/).map((t) => t.trim()).filter(Boolean);
      const r = await createPost({
        doc: { blocks },
        textCache: text,
        status: "draft",
      });
      if (r.error) {
        setError(r.error);
      } else {
        setDraft("");
        await refresh();
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setCreating(false);
    }
  }

  async function handleDelete(postId: string, hard: boolean) {
    setError(null);
    try {
      await deletePost(postId, hard);
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <div className="max-w-3xl mx-auto px-4 py-6">
      <div className="flex items-center mb-4">
        <h1 className="text-lg font-semibold text-stone-800">Posts</h1>
        <span className="ml-auto text-sm text-stone-500">
          {balance === null ? "—" : `${balance.toLocaleString()} sats`}
        </span>
      </div>

      {/* Compose */}
      <div className="bg-white border border-stone-200 rounded-xl p-4 mb-5">
        <textarea
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          rows={3}
          placeholder="Draft a post… (blank lines separate blocks)"
          className="w-full border border-stone-200 rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:border-amber-400"
        />
        <div className="flex justify-end mt-2">
          <button
            onClick={handleCreate}
            disabled={creating || !draft.trim()}
            className="bg-amber-600 text-white text-sm px-4 py-2 rounded-lg hover:bg-amber-500 disabled:opacity-40 transition-colors"
          >
            {creating ? "Saving…" : "Save draft"}
          </button>
        </div>
      </div>

      {/* Filter */}
      <div className="flex gap-1.5 mb-3 text-xs">
        {STATUS_FILTERS.map((s) => (
          <button
            key={s || "all"}
            onClick={() => setFilter(s)}
            className={`px-2.5 py-1 rounded transition-colors ${
              filter === s ? "bg-amber-100 text-amber-800" : "text-stone-500 hover:bg-stone-100"
            }`}
          >
            {s || "all"}
          </button>
        ))}
        <button
          onClick={refresh}
          className="ml-auto px-2.5 py-1 rounded text-stone-400 hover:bg-stone-100 transition-colors"
        >
          ↻ refresh
        </button>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-3 mb-3 text-xs text-red-700">
          {error}
        </div>
      )}

      {/* List */}
      {loading && posts.length === 0 ? (
        <p className="text-sm text-stone-400 py-8 text-center">Loading…</p>
      ) : posts.length === 0 ? (
        <p className="text-sm text-stone-400 py-8 text-center">No posts yet.</p>
      ) : (
        <ul className="space-y-2">
          {posts.map((p) => (
            <li
              key={p.post_id}
              className="bg-white border border-stone-200 rounded-lg p-3 flex items-start gap-3"
            >
              <span className="text-xs px-2 py-0.5 rounded-full bg-stone-100 text-stone-600 shrink-0">
                {p.status}
              </span>
              <div className="min-w-0 flex-1">
                <p className="text-sm text-stone-700 truncate">{p.excerpt || "(empty)"}</p>
                <p className="text-xs text-stone-400 mt-0.5">
                  {p.publish_at ? `→ ${p.publish_at}` : p.updated_at || ""}
                </p>
              </div>
              <div className="flex gap-2 shrink-0 text-xs">
                {p.status !== "archived" && (
                  <button
                    onClick={() => handleDelete(p.post_id, false)}
                    className="text-stone-400 hover:text-amber-600 transition-colors"
                    title="Archive (soft delete)"
                  >
                    archive
                  </button>
                )}
                <button
                  onClick={() => handleDelete(p.post_id, true)}
                  className="text-stone-400 hover:text-red-500 transition-colors"
                  title="Delete permanently"
                >
                  delete
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
