import { useEffect, useRef, useState } from "react";
import { Check, ExternalLink, Loader2, Send, X } from "lucide-react";
import { OAUTH_NEEDED_CODES, replyToConversation, setConversationStatus, type ConversationRow } from "../lib/mcp";
import { REPLY_MAX, replyCharsLeft, replyIntentUrl } from "../lib/conversationsPresentation";

/// Inline reply box under a lead row. The patron writes the words and presses
/// Post; eXcalibur carries them with the patron's token. Only X's confirmation
/// flips the lead to engaged — a refused post leaves the row as it was.
///
/// X's standing rule (self-serve tiers, since 2026-02-23) lets the API reply
/// only where the author already mentioned or quoted you. When X refuses on
/// that ground, the box hands the same text to X's own composer in a new tab;
/// the patron presses Post there and confirms here, which marks it engaged.
export default function ConversationReplyEditor({ row, onClose, onPosted, onNeedsXConnect }: {
  row: ConversationRow;
  onClose: () => void;
  onPosted: (updated: ConversationRow | undefined) => void;
  onNeedsXConnect: () => void;
}) {
  const [text, setText] = useState("");
  const [posting, setPosting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [handedOff, setHandedOff] = useState(false);
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
        if (r.error_code === "x_reply_not_permitted") {
          // X only lets the API reply where the author mentioned you first;
          // hand the words to X's composer and let the patron press Post there.
          window.open(replyIntentUrl(row.tweet_id, text.trim()), "_blank", "noopener,noreferrer");
          setHandedOff(true);
        } else if (r.error_code && OAUTH_NEEDED_CODES.has(r.error_code)) {
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

  async function confirmPostedOnX() {
    setPosting(true);
    setError(null);
    try {
      const updated = await setConversationStatus(row.id, "engaged");
      onPosted(updated ?? undefined);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setPosting(false);
    }
  }

  if (handedOff) {
    return (
      <div className="ml-6 mt-2 rounded-lg border border-amber-300 bg-amber-50/60 p-3 dark:border-amber-500/40 dark:bg-amber-500/10">
        <div className="text-xs text-stone-600 dark:text-zinc-300">
          X only lets us reply through the API where the author has mentioned you — so your words are waiting in X's composer. Press Post there, then confirm here.
        </div>
        <div className="mt-2 flex items-center gap-2">
          <a
            href={replyIntentUrl(row.tweet_id, text.trim())}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs text-amber-600 hover:underline dark:text-amber-400"
          >
            Open X again <ExternalLink className="h-3 w-3" />
          </a>
          {error && <span className="text-xs text-red-600 dark:text-red-400">{error}</span>}
          <button
            onClick={confirmPostedOnX}
            disabled={posting}
            className="ml-auto inline-flex items-center gap-1.5 rounded-lg bg-amber-600 px-3 py-1.5 text-sm text-white hover:bg-amber-500 disabled:opacity-40"
            title="Mark this lead engaged"
          >
            {posting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />}
            I posted it
          </button>
          <button onClick={onClose} title="Close" className="text-stone-400 hover:text-stone-600">
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>
    );
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
