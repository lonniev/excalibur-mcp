import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  createPost,
  deletePost,
  getPost,
  updatePost,
  type PostRow,
} from "../lib/mcp";

// X-style fold weighting (editorial spec): URLs count 23, emoji 2, others 1.
const URL_RE = /https?:\/\/\S+/g;
const EMOJI_RE = /\p{Extended_Pictographic}/gu;
const FOLD_BUDGET = 280;

function weightedLength(text: string): number {
  const urls = text.match(URL_RE) ?? [];
  let body = text;
  for (const u of urls) body = body.replace(u, "");
  const emoji = (body.match(EMOJI_RE) ?? []).length;
  const rest = [...body.replace(EMOJI_RE, "")].length;
  return urls.length * 23 + emoji * 2 + rest;
}

const card = "rounded-xl border border-stone-200 dark:border-zinc-800 bg-white dark:bg-zinc-900";
const input =
  "w-full rounded-lg px-3 py-2.5 text-sm bg-white dark:bg-zinc-950 border border-stone-300 dark:border-zinc-700 focus:outline-none focus:border-amber-400 dark:focus:border-amber-500";
const primary =
  "bg-amber-600 hover:bg-amber-500 text-white text-sm px-4 py-2 rounded-lg disabled:opacity-40 transition-colors";

export default function PostEditorPage() {
  const { postId } = useParams();
  const nav = useNavigate();
  const isNew = !postId;

  const [text, setText] = useState("");
  const [status, setStatus] = useState<"draft" | "scheduled">("draft");
  const [publishAt, setPublishAt] = useState(""); // datetime-local value
  const [loading, setLoading] = useState(!isNew);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  // Stable client_req_id for the create call so a double-submit can't
  // double-charge (backend rolls back the duplicate debit).
  const createReqId = useRef<string>(cryptoId());

  useEffect(() => {
    if (isNew) return;
    let live = true;
    setLoading(true);
    getPost(postId!)
      .then((row: PostRow) => {
        if (!live) return;
        if (row.error) {
          setError(row.error);
          return;
        }
        setText(row.text_cache ?? blocksToText(row.doc));
        if (row.status === "scheduled") setStatus("scheduled");
        if (row.publish_at) setPublishAt(toLocalInput(row.publish_at));
      })
      .catch((e) => live && setError((e as Error).message))
      .finally(() => live && setLoading(false));
    return () => {
      live = false;
    };
  }, [postId, isNew]);

  const weight = useMemo(() => weightedLength(text), [text]);
  const overFold = weight > FOLD_BUDGET;

  async function handleSave() {
    if (!text.trim()) {
      setError("Write something first.");
      return;
    }
    if (status === "scheduled" && !publishAt) {
      setError("Pick a publish time for a scheduled post.");
      return;
    }
    setSaving(true);
    setError(null);
    setNotice(null);
    const blocks = text.split(/\n\n+/).map((t) => t.trim()).filter(Boolean);
    const publishIso = status === "scheduled" && publishAt ? new Date(publishAt).toISOString() : undefined;

    try {
      if (isNew) {
        const r = await createPost({
          doc: { blocks },
          textCache: text,
          status,
          publishAt: publishIso,
          clientReqId: createReqId.current,
        });
        if (r.error) {
          setError(r.error);
        } else if (r.post_id) {
          nav(`/post/${r.post_id}`, { replace: true });
        }
      } else {
        const patch: Record<string, unknown> = { doc: { blocks }, status };
        if (publishIso) patch.publish_at = publishIso;
        const r = await updatePost({
          postId: postId!,
          patch,
          textCache: text,
          clientReqId: cryptoId(),
        });
        if (r.error) setError(r.error);
        else setNotice(r.idempotent ? "No changes." : "Saved.");
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(hard: boolean) {
    if (isNew) {
      nav("/");
      return;
    }
    if (hard && !window.confirm("Permanently delete this post?")) return;
    try {
      await deletePost(postId!, hard);
      nav("/");
    } catch (e) {
      setError((e as Error).message);
    }
  }

  if (loading) {
    return <p className="text-center text-sm text-stone-400 dark:text-zinc-500 py-12">Loading…</p>;
  }

  return (
    <div className="max-w-2xl mx-auto px-4 py-6">
      <div className="flex items-center mb-4">
        <h1 className="text-lg font-semibold">{isNew ? "Compose" : "Edit post"}</h1>
        <button
          onClick={() => nav("/")}
          className="ml-auto text-sm text-stone-400 dark:text-zinc-500 hover:text-stone-700 dark:hover:text-zinc-200 transition-colors"
        >
          ← Posts
        </button>
      </div>

      <div className={`${card} p-4 space-y-4`}>
        <div>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={8}
            placeholder="Write your post… (blank lines separate blocks)"
            className={`${input} resize-y`}
            autoFocus
          />
          <div className="flex items-center justify-between mt-1.5 text-xs">
            <span className="text-stone-400 dark:text-zinc-500">
              {text.split(/\n\n+/).filter((t) => t.trim()).length} block(s)
            </span>
            <span className={overFold ? "text-red-500 dark:text-red-400" : "text-stone-400 dark:text-zinc-500"}>
              {weight}/{FOLD_BUDGET} {overFold ? "· past the fold" : ""}
            </span>
          </div>
          <div className="h-1 mt-1 rounded-full bg-stone-100 dark:bg-zinc-800 overflow-hidden">
            <div
              className={`h-full transition-all ${overFold ? "bg-red-500" : "bg-amber-500"}`}
              style={{ width: `${Math.min(100, (weight / FOLD_BUDGET) * 100)}%` }}
            />
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <label className="text-sm text-stone-500 dark:text-zinc-400">
            Status{" "}
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value as "draft" | "scheduled")}
              className="ml-1 rounded-lg px-2 py-1.5 text-sm bg-white dark:bg-zinc-950 border border-stone-300 dark:border-zinc-700"
            >
              <option value="draft">Draft</option>
              <option value="scheduled">Scheduled</option>
            </select>
          </label>
          {status === "scheduled" && (
            <label className="text-sm text-stone-500 dark:text-zinc-400">
              Publish at{" "}
              <input
                type="datetime-local"
                value={publishAt}
                onChange={(e) => setPublishAt(e.target.value)}
                className="ml-1 rounded-lg px-2 py-1.5 text-sm bg-white dark:bg-zinc-950 border border-stone-300 dark:border-zinc-700"
              />
            </label>
          )}
        </div>

        {error && (
          <div className="rounded-lg p-3 text-xs bg-red-50 border border-red-200 text-red-700 dark:bg-red-500/10 dark:border-red-500/30 dark:text-red-400">
            {error}
          </div>
        )}
        {notice && (
          <div className="rounded-lg p-3 text-xs bg-green-50 border border-green-200 text-green-700 dark:bg-green-500/10 dark:border-green-500/30 dark:text-green-400">
            {notice}
          </div>
        )}

        <div className="flex items-center gap-2 pt-1">
          <button onClick={handleSave} disabled={saving} className={primary}>
            {saving ? "Saving…" : isNew ? "Save draft" : "Save"}
          </button>
          <button
            onClick={() => handleDelete(false)}
            className="text-sm px-3 py-2 rounded-lg text-stone-500 dark:text-zinc-400 hover:bg-stone-100 dark:hover:bg-zinc-800 transition-colors"
          >
            {isNew ? "Discard" : "Archive"}
          </button>
          {!isNew && (
            <button
              onClick={() => handleDelete(true)}
              className="ml-auto text-sm px-3 py-2 rounded-lg text-stone-400 dark:text-zinc-500 hover:text-red-500 dark:hover:text-red-400 transition-colors"
            >
              Delete
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function cryptoId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) return crypto.randomUUID();
  return `req-${Date.now()}-${Math.floor(Math.random() * 1e9)}`;
}

function blocksToText(doc: unknown): string {
  if (doc && typeof doc === "object" && Array.isArray((doc as { blocks?: unknown }).blocks)) {
    return ((doc as { blocks: unknown[] }).blocks)
      .map((b) => (typeof b === "string" ? b : String((b as { text?: string }).text ?? "")))
      .join("\n\n");
  }
  return "";
}

function toLocalInput(iso: string): string {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "";
  // datetime-local wants local time without timezone suffix.
  const off = d.getTimezoneOffset();
  const local = new Date(d.getTime() - off * 60000);
  return local.toISOString().slice(0, 16);
}
