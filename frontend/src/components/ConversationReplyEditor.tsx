import { useEffect, useRef, useState } from "react";
import { Loader2, Send, X } from "lucide-react";
import { OAUTH_NEEDED_CODES, replyToConversation, type ConversationRow } from "../lib/mcp";
import { REPLY_MAX, replyCharsLeft } from "../lib/conversationsPresentation";

/// Inline reply box under a lead row. The patron writes the words and presses
/// Post; eXcalibur carries them with the patron's token. Only X's confirmation
/// flips the lead to engaged — a refused post leaves the row as it was.
export default function ConversationReplyEditor({ row, onClose, onPosted, onNeedsXConnect }: {
  row: ConversationRow;
  onClose: () => void;
  onPosted: (updated: ConversationRow | undefined) => void;
  onNeedsXConnect: () => void;
}) {
  const [text, setText] = useState("");
  const [posting, setPosting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const box = useRef<HTMLTextAreaElement>(null);

  useEffect(() => { box.current?.focus(); }, []);

  const left = replyCharsLeft(text);
  const canPost = !posting && text.trim().length > 0 && left >= 0;

  async function post() {
    if (!canPost) return;
    setPosting(true);
    setError(null);
    try {
      const r = await replyToConversation(row.id, text.trim());
      if (r.error || r.success === false) {
        if (r.error_code && OAUTH_NEEDED_CODES.has(r.error_code)) {
          onNeedsXConnect();
          setError("Connect your X account before replying.");
        } else {
          setError(r.message || r.error || "Couldn't post the reply.");
        }
        return;
      }
      onPosted(r.conversation);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setPosting(false);
    }
  }

  return (
    <div className="ml-6 mt-2 rounded-lg border border-amber-300 bg-amber-50/60 p-3 dark:border-amber-500/40 dark:bg-amber-500/10">
      <div className="mb-1.5 text-xs text-stone-500 dark:text-zinc-400">
        Replying to <span className="text-stone-700 dark:text-zinc-200">@{row.author_username}</span>
      </div>
      <textarea
        ref={box}
        value={text}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Escape") onClose();
          if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) post();
        }}
        rows={3}
        maxLength={REPLY_MAX + 40}
        placeholder="Your reply, in your own words"
        className="w-full resize-y rounded-lg border border-stone-300 bg-white px-3 py-2 text-sm dark:border-zinc-700 dark:bg-zinc-950"
      />
      <div className="mt-1.5 flex items-center gap-2">
        <span className={`text-xs tabular-nums ${left < 0 ? "text-red-600 dark:text-red-400" : "text-stone-400 dark:text-zinc-500"}`}>
          {left}
        </span>
        {error && <span className="text-xs text-red-600 dark:text-red-400">{error}</span>}
        <button
          onClick={post}
          disabled={!canPost}
          className="ml-auto inline-flex items-center gap-1.5 rounded-lg bg-amber-600 px-3 py-1.5 text-sm text-white hover:bg-amber-500 disabled:opacity-40"
          title="Post the reply to X with your account (⌘↵)"
        >
          {posting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
          Post
        </button>
        <button onClick={onClose} title="Close" className="text-stone-400 hover:text-stone-600">
          <X className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}
