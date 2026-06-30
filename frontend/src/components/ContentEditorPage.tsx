import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { HTMLAttributes, ReactNode, SetStateAction } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  MessageCircle, Repeat2, Heart, BarChart2, Bookmark, Share, BadgeCheck,
  Sparkles, Flag, GripVertical, Pencil, Trash2, Plus, Calendar, Repeat,
  Octagon, Check, ChevronUp, ChevronDown, Eye, EyeOff,
  Wand2, Loader2, Swords, Save, Bold, Italic, Code, Smile, Star, Minus,
  CopyPlus,
} from "lucide-react";
import { useSession } from "../App";
import Avatar from "./Avatar";
import { avatarFor } from "../lib/avatar";
import { cachedXProfile, ensureXProfile } from "../lib/xProfile";
import type { XProfile } from "../lib/mcp";
import { styleText, type UnicodeStyle } from "../lib/unicodeFormat";
import {
  addSnippet, loadSnippets, removeSnippet, snippetIsDynamic,
  toggleDynamic, toggleFavorite, type Snippet,
} from "../lib/snippets";
import QuoteScroller from "./QuoteScroller";

// Categorized symbols + emoji for the picker. X renders the full Unicode/Twemoji
// set, so this is a broad curated palette (authors shouldn't memorize code
// points). Insertion is plain text, so everything posts as-is.
const EMOJI_GROUPS: { label: string; emojis: string[] }[] = [
  { label: "Typographic", emojis: ["™", "©", "®", "→", "←", "↑", "↓", "•", "★", "☆", "✓", "✗", "—", "–", "…", "₿", "§", "¶", "°", "×", "÷", "±", "≈", "≠", "™", "✦", "✧", "✶", "❝", "❞"] },
  { label: "Smileys", emojis: ["😀", "😁", "😂", "🤣", "😅", "😊", "😍", "😎", "🤩", "😏", "😉", "🙃", "😴", "🤔", "🧐", "🤨", "😬", "😅", "😭", "😤", "😡", "🥳", "🥺", "😱", "🤯", "🙄", "😇", "🤗", "🫡", "🫠"] },
  { label: "Gestures & People", emojis: ["👍", "👎", "👏", "🙌", "🙏", "🤝", "👇", "👆", "👉", "👈", "✊", "✌️", "🤞", "🤙", "💪", "🫵", "👀", "🧠", "🗣️", "👤", "👥", "🧑‍💻", "🦸", "🫶", "👋"] },
  { label: "Nature", emojis: ["🔥", "⚡", "🌟", "✨", "💥", "☀️", "🌈", "🌊", "🌍", "🌙", "⭐", "❄️", "🍀", "🌱", "🌹", "🌸", "🌳", "🐝", "🦋", "🐢"] },
  { label: "Food & Drink", emojis: ["☕", "🍵", "🍺", "🍷", "🥂", "🍾", "🍕", "🍔", "🌮", "🍩", "🍪", "🎂", "🍎", "🍊", "🍓", "🥑", "🧂", "🍫", "🍿", "🧊"] },
  { label: "Activity & Objects", emojis: ["🚀", "🎯", "💡", "🔑", "🗝️", "🔒", "🔓", "📌", "📎", "✂️", "🛠️", "⚙️", "🧰", "🔧", "🔨", "⚔️", "🛡️", "🏆", "🎖️", "🥇", "🎁", "🎉", "🎊", "🔔", "📣", "📢", "🔍", "🔎", "💼", "📚"] },
  { label: "Travel & Places", emojis: ["✈️", "🚗", "🚢", "🚆", "🗺️", "🧭", "🏔️", "🏝️", "🏛️", "🏗️", "🏠", "🌆", "🗽", "⛩️", "🚦", "⚓", "🛰️", "🛸", "🧳", "🪧"] },
  { label: "Symbols", emojis: ["✅", "❌", "⭕", "❗", "❓", "⚠️", "♻️", "✳️", "❇️", "🔆", "🆕", "🆗", "🔝", "🔚", "©️", "®️", "™️", "💯", "🚫", "⛔", "🔴", "🟢", "🟡", "🔵", "⚫", "⚪", "🟠", "🟣", "🔺", "🔻"] },
  { label: "Money & Crypto", emojis: ["₿", "💰", "💸", "💵", "💴", "💶", "💷", "🪙", "💳", "📈", "📉", "📊", "💹", "🧾", "🏦", "⚖️", "🤑", "💲", "🏧", "💎"] },
];
import {
  createPost, deletePost, getPost, getSnippet, getVoice, listPosts, postTweet, refinePostRegion,
  resolveDynamicBlock, saveSnippet, saveVoice, updatePost,
  OAUTH_NEEDED_CODES, type PostRow, type PostSummary, type Recurrence,
} from "../lib/mcp";
import { debugPush } from "../lib/debugLog";
import TweetPreviewModal from "./TweetPreviewModal";
import {
  charOffset, composeText, DEFAULT_BANS, DEFAULT_VOICE, hasDynamic, overlaps, paletteOf,
  parsePostDoc, segmentize, serializeBlocks, uid,
  type Ban, type Block, type Flag as FlagT,
} from "../lib/editorDoc";

type Kind = "post" | "snippet";
type Freq = "none" | "daily" | "weekdays" | "weekly" | "monthly";
interface Sel { blockId: string; start: number; end: number; x: number; y: number }
interface ActiveFlag { blockId: string; flagId: string }
interface PillPos { blockId: string; flagId: string; x: number; y: number }
// Cached resolution of a dynamic block, keyed by block id. `promptKey` is the
// prompt text it was resolved for, so re-entering Preview reuses an
// already-paid-for result and only a changed prompt triggers a fresh (paid) run.
interface ResolvedState { promptKey: string; text: string; loading: boolean; error: string }

// Parse a dynamic block's author-entered domain allowlist (comma/newline) into a
// clean list for web_fetch. Blank → [] (the resolver treats that as "any URL").
function splitDomains(raw?: string): string[] {
  return (raw ?? "").split(/[\n,]/).map((d) => d.trim()).filter(Boolean);
}

// The two content kinds share the entire block editor; they differ only in
// where they load/save and which actions (post/schedule) are offered. A Post is
// tweet content (postable + schedulable); a Snippet is reusable content.
export default function ContentEditorPage({ kind }: { kind: Kind }) {
  const isSnippet = kind === "snippet";
  const { postId, snippetId } = useParams();
  const id = isSnippet ? snippetId : postId;
  const isNew = !id;
  const listPath = isSnippet ? "/snippets" : "/";
  const nav = useNavigate();
  const { npub } = useSession();
  const createReqId = useRef(uid());

  const [blocks, setBlocks] = useState<Block[]>([{ id: uid(), text: "", flags: [] }]);
  const [name, setName] = useState(""); // snippet-only
  const [title, setTitle] = useState(""); // post-only — optional human label
  const [activeFlag, setActiveFlag] = useState<ActiveFlag | null>(null);
  const [preview, setPreview] = useState(false);
  const [tab, setTab] = useState<"flags" | "voice" | "schedule" | "snippets">("flags");
  const [editingBlock, setEditingBlock] = useState<string | null>(null);
  const [snippets, setSnippets] = useState<Snippet[]>([]);
  useEffect(() => {
    loadSnippets().then(setSnippets);
  }, []);
  const [sel, setSel] = useState<Sel | null>(null);
  const [clearPill, setClearPill] = useState<PillPos | null>(null);
  const [hint, setHint] = useState("");
  // Resolved dynamic blocks (Preview dry-run output), keyed by block id.
  const [resolved, setResolved] = useState<Record<string, ResolvedState>>({});

  // Voice is server-persisted (per-npub, free + proof-gated). It loads async on
  // mount; until then we show the defaults as a non-dirty placeholder so the
  // editor still has a voice to send to refine. `voiceDirty` gates the Save
  // button; `voiceSaving`/`voiceSaved` drive its status.
  const [voice, setVoice] = useState(DEFAULT_VOICE);
  const [bans, setBans] = useState<Ban[]>(() => DEFAULT_BANS.map((b) => ({ text: b, on: true })));
  const [voiceLoaded, setVoiceLoaded] = useState(false);
  const [voiceDirty, setVoiceDirty] = useState(false);
  const [voiceSaving, setVoiceSaving] = useState(false);
  const [voiceSaved, setVoiceSaved] = useState(false);
  const [voiceError, setVoiceError] = useState("");

  const [publishAt, setPublishAt] = useState("");
  const [freq, setFreq] = useState<Freq>("none");
  const [interval, setIntervalN] = useState(1);
  const [ceaseAt, setCeaseAt] = useState("");

  const [loading, setLoading] = useState(!isNew);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [needsXConnect, setNeedsXConnect] = useState(false);
  const [postedUrl, setPostedUrl] = useState<string | null>(null);
  // The tweet URL of a post that has already gone out — hydrated on load and on
  // a fresh Post-now — so a Sent post always shows its actual X link.
  const [tweetUrl, setTweetUrl] = useState<string | null>(null);
  // Peek at the posted tweet in a modal (no navigation), distinct from postedUrl
  // (the post-now flow whose modal returns to the list on close).
  const [peekUrl, setPeekUrl] = useState<string | null>(null);
  // Connected X identity for the tweet-card preview (cached, revalidated on open).
  const [xProfile, setXProfile] = useState<XProfile | null>(() => (npub ? cachedXProfile(npub) : null));

  // ── prev/next navigation (swipe + chevrons) ───────────────────────────────
  // Sibling posts in the Posts-table ordering let the editor swipe/step to the
  // adjacent post. Fetched once per session (best-effort; post kind only).
  const [neighbors, setNeighbors] = useState<PostSummary[]>([]);
  const touchStart = useRef<{ x: number; y: number } | null>(null);
  // First load shows the full-screen QuoteScroller gate; stepping to a sibling
  // keeps the editor mounted and shows only a thin progress hint (soft swap),
  // so prev/next reads as in-place content change, not a page reload.
  const firstLoad = useRef(true);
  const [stepping, setStepping] = useState(false);
  // Baseline signature of the loaded document; `dirty` compares the live state to
  // it so a swipe away from unsaved edits can prompt first. Voice/bans are global
  // prefs, not post content, so they're excluded from the signature.
  const baseline = useRef<string | null>(null);
  const sigOf = useCallback(
    (blks: Block[], pub: string, fq: Freq, iv: number, cz: string, ttl: string) =>
      JSON.stringify([serializeBlocks(blks), pub, fq, iv, cz, ttl.trim()]),
    [],
  );
  // Full PostRow cache keyed by post_id. The adjacent posts are prefetched so a
  // step lands instantly with no fetch wait; an entry is dropped on save so a
  // revisit never serves stale content. (Posts are tiny; caching ±1 is plenty.)
  const postCache = useRef<Map<string, PostRow>>(new Map());
  const applyPostRow = useCallback((row: PostRow) => {
    // Set every field explicitly (not just when present) so a post without a
    // schedule clears the prior post's schedule state.
    const loaded = parsePostDoc(row.doc, row.text_cache);
    const rec = row.recurrence as Recurrence | undefined;
    const pub = row.publish_at ? toLocalInput(row.publish_at) : "";
    const fq: Freq = rec?.freq ?? "none";
    const iv = rec?.interval || 1;
    const cz = row.cease_at ? toLocalInput(row.cease_at) : "";
    const ttl = row.title ?? "";
    setBlocks(loaded);
    setPublishAt(pub);
    setFreq(fq);
    setIntervalN(iv);
    setCeaseAt(cz);
    setTitle(ttl);
    setTweetUrl(row.tweet_url ?? null);
    baseline.current = sigOf(loaded, pub, fq, iv, cz, ttl);
  }, [sigOf]);

  // ── load ────────────────────────────────────────────────────────────────
  useEffect(() => {
    if (isNew) {
      const init: Block[] = [{ id: uid(), text: "", flags: [] }];
      setBlocks(init);
      baseline.current = sigOf(init, "", "none", 1, "", "");
      setLoading(false);
      return;
    }
    let live = true;
    const finishLoad = () => { setLoading(false); setStepping(false); firstLoad.current = false; };
    // Stepping to a sibling reuses this component, so clear per-post transients.
    setError(null);
    setNeedsXConnect(false);
    setActiveFlag(null);
    setEditingBlock(null);
    if (isSnippet) {
      if (firstLoad.current) setLoading(true); else setStepping(true);
      getSnippet(id!)
        .then((row) => {
          if (!live) return;
          if (!row) { setError("Snippet not found."); finishLoad(); return; }
          setBlocks(parsePostDoc(row.doc, row.text));
          setName(row.name ?? "");
          finishLoad();
        })
        .catch((e) => { if (live) { setError((e as Error).message); finishLoad(); } });
      return () => { live = false; };
    }
    // A prefetched neighbor lands instantly — no gate, no spinner, no fetch.
    const hit = postCache.current.get(id!);
    if (hit) {
      applyPostRow(hit);
      finishLoad();
      return () => { live = false; };
    }
    // First mount → full-screen gate; an uncached sibling step → soft swap.
    if (firstLoad.current) setLoading(true); else setStepping(true);
    getPost(id!)
      .then((row: PostRow) => {
        if (!live) return;
        if (row.error) { setError(row.error); finishLoad(); return; }
        postCache.current.set(id!, row);
        applyPostRow(row);
        finishLoad();
      })
      .catch((e) => { if (live) { setError((e as Error).message); finishLoad(); } });
    return () => { live = false; };
  }, [id, isNew, isSnippet, applyPostRow]);

  // Revalidate the connected X identity for the preview card (best-effort).
  useEffect(() => {
    if (isSnippet || !npub) return;
    let live = true;
    ensureXProfile(npub).then((p) => { if (live && p) setXProfile(p); });
    return () => { live = false; };
  }, [npub, isSnippet]);

  // Sibling posts for swipe/step navigation — same default ordering as the Posts
  // table. Fetched once per session; failures simply leave swipe disabled.
  useEffect(() => {
    if (isSnippet || isNew) return;
    let live = true;
    listPosts({ sortCol: "created", sortDir: "desc", page: 0, pageSize: 500 })
      .then((r) => { if (live) setNeighbors(r.posts ?? []); })
      .catch(() => { /* swipe stays disabled */ });
    return () => { live = false; };
  }, [isSnippet, isNew]);

  // Load the persisted Voice once. An empty server Voice (first-run) keeps the
  // local defaults but leaves them dirty so the first Save seeds the server.
  useEffect(() => {
    let live = true;
    getVoice()
      .then((v) => {
        if (!live) return;
        if (v.profile || v.bans.length) {
          setVoice(v.profile);
          setBans(v.bans);
          setVoiceDirty(false);
        } else {
          setVoiceDirty(true); // nothing saved yet → offer to persist the seed
        }
      })
      .catch(() => { if (live) setVoiceDirty(true); })
      .finally(() => { if (live) setVoiceLoaded(true); });
    return () => { live = false; };
  }, []);

  // Any voice/bans change after load marks the Voice dirty and clears the
  // transient "Saved" badge.
  const markVoiceDirty = useCallback(() => {
    if (!voiceLoaded) return;
    setVoiceDirty(true);
    setVoiceSaved(false);
    setVoiceError("");
  }, [voiceLoaded]);

  const editVoice = useCallback((v: string) => { setVoice(v); markVoiceDirty(); }, [markVoiceDirty]);
  const editBans = useCallback((updater: SetStateAction<Ban[]>) => {
    setBans(updater);
    markVoiceDirty();
  }, [markVoiceDirty]);

  const saveVoiceNow = useCallback(async () => {
    setVoiceSaving(true);
    setVoiceError("");
    try {
      const stored = await saveVoice({ profile: voice, bans });
      setVoice(stored.profile);
      setBans(stored.bans);
      setVoiceDirty(false);
      setVoiceSaved(true);
    } catch (e) {
      setVoiceError((e as Error).message || "Could not save Voice");
    } finally {
      setVoiceSaving(false);
    }
  }, [voice, bans]);

  useEffect(() => {
    if (!hint) return;
    const t = window.setTimeout(() => setHint(""), 2200);
    return () => window.clearTimeout(t);
  }, [hint]);

  useEffect(() => {
    const clear = () => { setSel(null); setClearPill(null); };
    window.addEventListener("scroll", clear, true);
    return () => window.removeEventListener("scroll", clear, true);
  }, []);

  const composed = useMemo(() => composeText(blocks), [blocks]);
  const charCount = composed.length;
  // Text offered to "save as snippet": the block being edited, else the
  // selected block, else the whole composed content.
  const focusedBlockText =
    (editingBlock ? blocks.find((b) => b.id === editingBlock)?.text : undefined) ??
    (sel ? blocks.find((b) => b.id === sel.blockId)?.text : undefined) ??
    composed;
  // The block the "Save the focused block" gesture targets — so saving a dynamic
  // block carries its full settings (dynamic/fallback/domains/maxFetches) into
  // the snippet doc, not just its text.
  const focusedBlock =
    (editingBlock ? blocks.find((b) => b.id === editingBlock) : undefined) ??
    (sel ? blocks.find((b) => b.id === sel.blockId) : undefined) ??
    (blocks.length === 1 ? blocks[0] : undefined);
  const allFlags = useMemo(
    () => blocks.flatMap((b) => b.flags.map((f) => ({ ...f, blockId: b.id, blockText: b.text }))),
    [blocks],
  );

  // Has the live document diverged from what we loaded? (Drives the swipe guard.)
  const dirty = useMemo(
    () => baseline.current !== null
      && sigOf(blocks, publishAt, freq, interval, ceaseAt, title) !== baseline.current,
    [blocks, publishAt, freq, interval, ceaseAt, title, sigOf],
  );
  const curIndex = useMemo(
    () => (isNew ? -1 : neighbors.findIndex((p) => p.post_id === id)),
    [neighbors, id, isNew],
  );

  // Step to a sibling post (dir −1 prev / +1 next), guarding unsaved edits.
  const goToNeighbor = useCallback((dir: number) => {
    if (isSnippet || curIndex < 0) return;
    const target = curIndex + dir;
    if (target < 0 || target >= neighbors.length) return;
    if (dirty && !window.confirm("Discard unsaved changes and move to the adjacent post?")) return;
    nav(`/post/${neighbors[target].post_id}`);
  }, [isSnippet, curIndex, neighbors, dirty, nav]);

  // ←/→ step between sibling posts, but never while typing in a field.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.altKey || e.ctrlKey || e.metaKey) return;
      const el = document.activeElement as HTMLElement | null;
      const tag = el?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || el?.isContentEditable) return;
      if (e.key === "ArrowLeft") { e.preventDefault(); goToNeighbor(-1); }
      else if (e.key === "ArrowRight") { e.preventDefault(); goToNeighbor(1); }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [goToNeighbor]);

  // Prefetch the immediately adjacent posts so a step lands instantly. Re-runs as
  // the current index moves, warming the new neighbors. Best-effort and cheap.
  useEffect(() => {
    if (isSnippet || curIndex < 0) return;
    let live = true;
    [curIndex - 1, curIndex + 1]
      .filter((i) => i >= 0 && i < neighbors.length)
      .map((i) => neighbors[i].post_id)
      .filter((pid) => !postCache.current.has(pid))
      .forEach((pid) => {
        getPost(pid)
          .then((row) => { if (live && !row.error) postCache.current.set(pid, row); })
          .catch(() => { /* prefetch is best-effort */ });
      });
    return () => { live = false; };
  }, [curIndex, neighbors, isSnippet]);

  function onStageTouchStart(e: React.TouchEvent) {
    const t = e.touches[0];
    touchStart.current = { x: t.clientX, y: t.clientY };
  }
  function onStageTouchEnd(e: React.TouchEvent) {
    const start = touchStart.current;
    touchStart.current = null;
    if (!start || curIndex < 0) return;
    // A drag that selected block text isn't a swipe.
    if (!window.getSelection()?.isCollapsed) return;
    const t = e.changedTouches[0];
    const dx = t.clientX - start.x;
    const dy = t.clientY - start.y;
    // Require decisive, mostly-horizontal travel so vertical scrolls pass through.
    if (Math.abs(dx) < 80 || Math.abs(dx) < Math.abs(dy) * 1.5) return;
    goToNeighbor(dx > 0 ? 1 : -1); // swipe right → next, left → prev (matches →/← arrows)
  }

  // ── selection → flag ──────────────────────────────────────────────────────
  const onBlockMouseUp = useCallback((blockId: string, el: HTMLElement | null) => {
    const s = window.getSelection();
    if (!el || !s || s.isCollapsed || !s.rangeCount) { setSel(null); return; }
    const range = s.getRangeAt(0);
    if (!el.contains(range.startContainer) || !el.contains(range.endContainer)) { setSel(null); return; }
    let start = charOffset(el, range.startContainer, range.startOffset);
    let end = charOffset(el, range.endContainer, range.endOffset);
    if (start > end) [start, end] = [end, start];
    if (end - start < 1) { setSel(null); return; }
    const rect = range.getBoundingClientRect();
    setClearPill(null);
    setSel({ blockId, start, end, x: rect.left + rect.width / 2, y: rect.top });
  }, []);

  function flagSelection() {
    if (!sel) return;
    setBlocks((prev) => {
      const total = prev.reduce((n, b) => n + b.flags.length, 0);
      return prev.map((b) => {
        if (b.id !== sel.blockId) return b;
        const candidate = { start: sel.start, end: sel.end };
        if (b.flags.some((f) => overlaps(f, candidate))) {
          setHint("That region overlaps an existing flag.");
          return b;
        }
        const flag: FlagT = { id: uid(), start: sel.start, end: sel.end, note: "", suggestions: [], loading: false, error: "", colorIdx: total };
        setActiveFlag({ blockId: b.id, flagId: flag.id });
        setTab("flags");
        return { ...b, flags: [...b.flags, flag] };
      });
    });
    window.getSelection()?.removeAllRanges();
    setSel(null);
  }

  function removeFlag(blockId: string, flagId: string) {
    setBlocks((prev) => prev.map((b) => (b.id === blockId ? { ...b, flags: b.flags.filter((f) => f.id !== flagId) } : b)));
    setActiveFlag((a) => (a && a.flagId === flagId ? null : a));
    setClearPill((p) => (p && p.flagId === flagId ? null : p));
  }

  function updateFlag(blockId: string, flagId: string, patch: Partial<FlagT>) {
    setBlocks((prev) => prev.map((b) =>
      b.id === blockId ? { ...b, flags: b.flags.map((f) => (f.id === flagId ? { ...f, ...patch } : f)) } : b));
  }

  // ── refine (server-side: MCP calls Claude with the operator's vaulted key) ──
  async function refine(blockId: string, flag: FlagT) {
    const block = blocks.find((b) => b.id === blockId);
    if (!block) return;
    const region = block.text.slice(flag.start, flag.end);
    const activeBans = bans.filter((b) => b.on).map((b) => b.text);
    updateFlag(blockId, flag.id, { loading: true, error: "", suggestions: [] });
    try {
      const r = await refinePostRegion({
        region,
        fullText: block.text,
        instruction: flag.note,
        voice,
        bans: activeBans,
      });
      if (!r.success) {
        updateFlag(blockId, flag.id, {
          loading: false,
          error: r.message || r.error || "Refine is unavailable right now.",
        });
        return;
      }
      // Dedup identical suggestions (the model sometimes repeats), keep order.
      const suggestions = [...new Set((r.suggestions ?? []).map((s) => s.trim()).filter(Boolean))];
      if (!suggestions.length) throw new Error("No suggestions returned.");
      updateFlag(blockId, flag.id, { loading: false, suggestions });
    } catch (e) {
      updateFlag(blockId, flag.id, { loading: false, error: (e as Error).message });
    }
  }

  function applySuggestion(blockId: string, flag: FlagT, text: string) {
    setBlocks((prev) => prev.map((b) => {
      if (b.id !== blockId) return b;
      const newText = b.text.slice(0, flag.start) + text + b.text.slice(flag.end);
      const delta = text.length - (flag.end - flag.start);
      const flags = b.flags
        .filter((f) => f.id !== flag.id)
        .map((f) => (f.start >= flag.end ? { ...f, start: f.start + delta, end: f.end + delta } : f));
      return { ...b, text: newText, flags };
    }));
    setActiveFlag((a) => (a && a.flagId === flag.id ? null : a));
    setHint("Region updated.");
  }

  // ── blocks: edit / reorder / add / delete ────────────────────────────────
  const setBlockText = (blockId: string, text: string) =>
    setBlocks((prev) => prev.map((b) => (b.id === blockId ? { ...b, text, flags: [] } : b)));

  const moveBlock = (idx: number, dir: number) =>
    setBlocks((prev) => {
      const next = [...prev];
      const j = idx + dir;
      if (j < 0 || j >= next.length) return prev;
      [next[idx], next[j]] = [next[j], next[idx]];
      return next;
    });

  const dragIndex = useRef<number | null>(null);
  const [overIndex, setOverIndex] = useState<number | null>(null);
  const onDrop = (idx: number) => {
    const from = dragIndex.current;
    dragIndex.current = null;
    setOverIndex(null);
    if (from == null || from === idx) return;
    setBlocks((prev) => {
      const next = [...prev];
      const [moved] = next.splice(from, 1);
      next.splice(idx, 0, moved);
      return next;
    });
  };

  const addBlock = () => setBlocks((prev) => [...prev, { id: uid(), text: "New line…", flags: [] }]);
  // Insert a snippet as a new block. A dynamic snippet lands as a dynamic block
  // (its text is a prompt) carrying its fallback; a static one lands as-is.
  const insertSnippetRow = (s: Snippet) => {
    // A snippet is a saved doc of blocks — append it faithfully. parsePostDoc
    // pulls the real content from the doc (a dynamic block's prompt + fallback +
    // domains/maxFetches), NOT the composed `text` body (which for a dynamic
    // snippet is just the ⟨dynamic⟩ placeholder), and falls back to `text` for
    // legacy text-only snippets. Fresh ids are assigned.
    const inserted = parsePostDoc(s.doc, s.text);
    setBlocks((prev) => [...prev, ...inserted]);
    setHint(inserted.some((b) => b.dynamic)
      ? "Dynamic snippet added — its prompt runs at post time."
      : "Snippet added as a block — drag it where you want.");
  };

  // Flip a block between static text and a dynamic prompt, in place. Turning it
  // dynamic clears any flags (a prompt isn't flaggable copy); turning it static
  // drops the dynamic/fallback fields. Either way, clear its cached resolution.
  const toggleBlockDynamic = useCallback((blockId: string) => {
    let nowDynamic = false;
    setBlocks((prev) => prev.map((b) => {
      if (b.id !== blockId) return b;
      if (b.dynamic) return { id: b.id, text: b.text, flags: [] };
      nowDynamic = true;
      return { ...b, dynamic: true, flags: [] };
    }));
    setResolved((r) => { const { [blockId]: _drop, ...rest } = r; return rest; });
    setHint(nowDynamic
      ? "Now a dynamic prompt — it runs at post time. Edit the prompt and fallback below, then Run to preview."
      : "Back to a static text block.");
  }, []);

  // Edit a dynamic block's fallback (posted if resolution fails) inline.
  const setBlockFallback = useCallback((blockId: string, fallback: string) => {
    setBlocks((prev) => prev.map((b) =>
      b.id === blockId ? { ...b, fallback: fallback || undefined } : b));
  }, []);

  // Author web-access controls for a dynamic block: an optional fetch-domain
  // allowlist (blank = any URL the prompt references) and a lookup budget.
  const setBlockDomains = useCallback((blockId: string, domains: string) => {
    setBlocks((prev) => prev.map((b) =>
      b.id === blockId ? { ...b, domains: domains || undefined } : b));
  }, []);
  const setBlockMaxFetches = useCallback((blockId: string, n: number) => {
    setBlocks((prev) => prev.map((b) =>
      b.id === blockId ? { ...b, maxFetches: n > 0 ? n : undefined } : b));
  }, []);
  // Author time budget (seconds) for resolving a dynamic block: bounds runtime,
  // sets the poll cadence, and is priceable ad valorem by the operator.
  const setBlockRuntimeLimit = useCallback((blockId: string, n: number) => {
    setBlocks((prev) => prev.map((b) =>
      b.id === blockId ? { ...b, runtimeLimit: n > 0 ? n : undefined } : b));
  }, []);

  // Resolve one dynamic block via the (paid) server-side dry-run. Context is the
  // tweet around it, with this slot marked and other blocks shown resolved /
  // fallback so the fragment reads in place.
  const resolveDynamic = useCallback(async (block: Block) => {
    const promptKey = block.text;
    const context = blocks
      .map((b) => {
        if (b.id === block.id) return "⟨HERE⟩";
        if (b.dynamic) return resolved[b.id]?.text || b.fallback || "";
        return b.text;
      })
      .filter(Boolean)
      .join("\n\n");
    const activeBans = bans.filter((b) => b.on).map((b) => b.text);
    setResolved((r) => ({ ...r, [block.id]: { promptKey, text: r[block.id]?.text ?? "", loading: true, error: "" } }));
    try {
      const res = await resolveDynamicBlock({
        prompt: block.text, context, voice, bans: activeBans,
        allowedDomains: splitDomains(block.domains), maxFetches: block.maxFetches,
        runtimeLimitSeconds: block.runtimeLimit,
      });
      if (!res.success) {
        setResolved((r) => ({ ...r, [block.id]: {
          promptKey, text: block.fallback ?? "", loading: false,
          error: res.message || res.error || "Couldn't resolve this prompt.",
        } }));
        return;
      }
      setResolved((r) => ({ ...r, [block.id]: { promptKey, text: res.text ?? "", loading: false, error: "" } }));
    } catch (e) {
      setResolved((r) => ({ ...r, [block.id]: {
        promptKey, text: block.fallback ?? "", loading: false, error: (e as Error).message,
      } }));
    }
  }, [blocks, resolved, voice, bans]);
  // A 20-char U+2500 horizontal-rule block. X renders no markdown, so a row of
  // box-drawing chars is how a divider survives to the timeline.
  const DIVIDER = "─".repeat(20);
  const insertDivider = () => {
    setBlocks((prev) => [...prev, { id: uid(), text: DIVIDER, flags: [] }]);
    setHint("Divider added — X left-aligns text, so it sits at the line start.");
  };
  const deleteBlock = (blockId: string) =>
    setBlocks((prev) => (prev.length > 1 ? prev.filter((b) => b.id !== blockId) : prev));

  // Entering Preview resolves each dynamic block (the priced dry-run), reusing a
  // cached result when its prompt is unchanged so toggling Preview never re-bills.
  useEffect(() => {
    if (!preview) return;
    for (const b of blocks) {
      if (!b.dynamic) continue;
      const cached = resolved[b.id];
      if (cached?.loading) continue;
      if (cached && cached.promptKey === b.text && !cached.error) continue;
      void resolveDynamic(b);
    }
    // resolveDynamic/resolved intentionally omitted: re-run on Preview open or a
    // block edit, not on every cache write (which would loop).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [preview, blocks]);

  // ── persistence ───────────────────────────────────────────────────────────
  async function persist(scheduled: boolean) {
    if (!composed.trim()) { setError("Write something first."); return; }
    if (scheduled && !publishAt) { setError("Set a publish time to schedule."); setTab("schedule"); return; }
    setSaving(true);
    setError(null);
    const status = scheduled ? "scheduled" : "draft";
    const docPayload = serializeBlocks(blocks);
    const publishIso = scheduled && publishAt ? new Date(publishAt).toISOString() : undefined;
    const recurrence: Recurrence | undefined =
      scheduled && freq !== "none" ? { freq, interval: Math.max(1, Number(interval) || 1) } : undefined;
    const ceaseIso = ceaseAt ? new Date(ceaseAt).toISOString() : undefined;
    try {
      if (isNew) {
        const r = await createPost({
          doc: docPayload, textCache: composed, status,
          publishAt: publishIso, recurrence, ceaseAt: ceaseIso, clientReqId: createReqId.current,
          title: title.trim() || undefined,
        });
        if (r.error) setError(r.error);
        else if (r.post_id) nav(`/post/${r.post_id}`, { replace: true });
      } else {
        // Always send title (even blank) so clearing it persists as NULL.
        const patch: Record<string, unknown> = { doc: docPayload, status, title: title.trim() };
        if (publishIso) patch.publish_at = publishIso;
        if (recurrence) patch.recurrence = recurrence;
        if (ceaseIso) patch.cease_at = ceaseIso;
        const r = await updatePost({ postId: id!, patch, textCache: composed, clientReqId: uid() });
        if (r.error) setError(r.error);
        else {
          setHint(scheduled ? "Scheduled." : "Saved.");
          baseline.current = sigOf(blocks, publishAt, freq, interval, ceaseAt, title);
          postCache.current.delete(id!); // saved content differs from any cached row
        }
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  // Save the document as a named snippet (snippet kind's primary action).
  async function persistSnippet() {
    if (!name.trim()) { setError("Name your snippet first."); return; }
    if (!composed.trim()) { setError("Write something first."); return; }
    setSaving(true);
    setError(null);
    try {
      const row = await saveSnippet({
        id: isNew ? undefined : id,
        name: name.trim(),
        text: composed,
        doc: serializeBlocks(blocks),
      });
      if (!row) { setError("Couldn't save the snippet."); return; }
      if (isNew) nav(`/snippet/${row.id}`, { replace: true });
      else setHint("Saved.");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  // "Save as…" — fork the current body into a NEW item of the same kind,
  // leaving the original untouched. A post copy is a fresh draft (title
  // optional); a snippet copy needs a name. Lands in the new item's editor.
  async function saveAsCopy() {
    if (!composed.trim()) { setError("Write something first."); return; }
    const docPayload = serializeBlocks(blocks);
    if (isSnippet) {
      const newName = window.prompt("Save as a new snippet named:", `${name.trim() || "Snippet"} copy`);
      if (newName === null) return; // cancelled
      if (!newName.trim()) { setError("Name your snippet copy."); return; }
      setSaving(true);
      setError(null);
      try {
        const row = await saveSnippet({ name: newName.trim(), text: composed, doc: docPayload });
        if (!row) { setError("Couldn't save the copy."); return; }
        nav(`/snippet/${row.id}`);
      } catch (e) {
        setError((e as Error).message);
      } finally {
        setSaving(false);
      }
    } else {
      const newTitle = window.prompt("Save as a new draft post titled:", `${title.trim() || "Untitled"} copy`);
      if (newTitle === null) return; // cancelled
      setSaving(true);
      setError(null);
      try {
        const r = await createPost({
          doc: docPayload, textCache: composed, status: "draft",
          title: newTitle.trim() || undefined, clientReqId: uid(),
        });
        if (r.error) { setError(r.error); return; }
        if (r.post_id) nav(`/post/${r.post_id}`);
      } catch (e) {
        setError((e as Error).message);
      } finally {
        setSaving(false);
      }
    }
  }

  async function handleDiscard() {
    if (isSnippet) {
      if (isNew) { nav(listPath); return; }
      if (!window.confirm("Delete this snippet?")) return;
      try { await removeSnippet(id!); nav(listPath); } catch (e) { setError((e as Error).message); }
      return;
    }
    if (isNew) { nav(listPath); return; }
    if (!window.confirm("Archive this post?")) return;
    try { await deletePost(id!, false); nav(listPath); } catch (e) { setError((e as Error).message); }
  }

  // Compose the text to actually post: static blocks verbatim, each dynamic block
  // resolved now (reusing a current Preview result, else a fresh paid run). A
  // dynamic block that fails with no fallback aborts the post — never a gap.
  async function buildFinalText(): Promise<{ text: string; error?: string }> {
    if (!hasDynamic(blocks)) return { text: composed };
    const activeBans = bans.filter((b) => b.on).map((b) => b.text);
    // Context for each dynamic block: static siblings + OTHER dynamics as their
    // fallback (we resolve in parallel, so none sees another's resolved value).
    const contextFor = (i: number) =>
      blocks
        .map((x, j) => (j === i ? "⟨HERE⟩" : x.dynamic ? (x.fallback ?? "") : x.text))
        .filter(Boolean)
        .join("\n\n");

    // Resolve every dynamic block concurrently (reusing a current Preview result).
    const rendered = await Promise.all(blocks.map(async (b, i): Promise<string | null> => {
      if (!b.dynamic) return b.text;
      const cached = resolved[b.id];
      if (cached && cached.promptKey === b.text && !cached.error) return cached.text;
      try {
        const res = await resolveDynamicBlock({
          prompt: b.text, context: contextFor(i), voice, bans: activeBans,
          allowedDomains: splitDomains(b.domains), maxFetches: b.maxFetches,
          runtimeLimitSeconds: b.runtimeLimit,
        });
        if (res.success) return res.text ?? "";
        return b.fallback ?? null;  // null = failed with no fallback
      } catch {
        return b.fallback ?? null;
      }
    }));

    if (rendered.some((v) => v === null)) {
      return { text: "", error: "A dynamic block couldn't be resolved and has no fallback." };
    }
    return { text: rendered.filter(Boolean).join("\n\n").trim() };
  }

  // Post to X now (paid), then save the post as sent so it lands in the list.
  async function handlePostNow() {
    debugPush("info", `Post It clicked (${composed.trim().length} chars)`);
    if (!composed.trim()) { setError("Write something first."); return; }
    setSaving(true);
    setError(null);
    setNeedsXConnect(false);
    try {
      // Long dynamic blocks (LLM + web search) resolve slowly — don't hold the
      // editor hostage. If any dynamic block's budget exceeds ~30s, defer to the
      // scheduler: save the post UNRESOLVED, due in ~10s, and hand control back.
      // The cron worker resolves the blocks server-side (each with its own
      // runtime budget, which rides in the saved doc) and posts.
      const dynamicBudgets = blocks.filter((b) => b.dynamic).map((b) => b.runtimeLimit ?? 210);
      const maxBudget = dynamicBudgets.length ? Math.max(...dynamicBudgets) : 0;
      if (maxBudget > 30) {
        const publishIso = new Date(Date.now() + 10_000).toISOString();
        const docPayload = serializeBlocks(blocks);
        const saved = isNew
          ? await createPost({
              doc: docPayload, textCache: composed, status: "scheduled",
              publishAt: publishIso, clientReqId: createReqId.current,
              title: title.trim() || undefined,
            })
          : await updatePost({
              postId: id!, patch: { doc: docPayload, status: "scheduled", publish_at: publishIso, title: title.trim() },
              textCache: composed, clientReqId: uid(),
            });
        if (!saved.post_id || saved.success === false || saved.error) {
          const why = saved.error_code || saved.error || saved.message || "unknown error";
          debugPush("error", `schedule-for-resolve failed: ${why}`);
          setError(`Couldn't schedule the post (${why}).`);
          return;
        }
        debugPush("info", `Deferred to scheduler (budget ${maxBudget}s) — due ~now+10s`);
        setHint("Scheduled — its blocks resolve in the background and it posts shortly.");
        baseline.current = sigOf(blocks, publishAt, freq, interval, ceaseAt, title);
        if (isNew && saved.post_id) nav(`/post/${saved.post_id}`, { replace: true });
        return;
      }

      const { text: finalText, error: buildErr } = await buildFinalText();
      if (buildErr) { setError(buildErr); return; }
      if (!finalText.trim()) { setError("Nothing to post after resolving the dynamic blocks."); return; }
      const r = await postTweet(finalText);
      if (r.error || r.success === false) {
        if (r.error_code && OAUTH_NEEDED_CODES.has(r.error_code)) {
          debugPush("info", `post_tweet needs X connect (${r.error_code})`);
          setNeedsXConnect(true);
          setError("Connect your X account before posting.");
        } else {
          setError(r.message || r.error || "Couldn't post to X.");
        }
        return;
      }
      const tweetUrl = r.tweet_url ?? "";
      const docPayload = serializeBlocks(blocks);
      // The tweet is live; now record it as Sent. A soft-fail here (the tool's
      // catch_errors returns {success:false,…} rather than throwing) was
      // previously swallowed — a new post got only a quiet hint and an existing
      // post's result was ignored outright — so the row silently stayed a draft
      // while the UI said "Posted." Surface it loudly and log it instead.
      const saved = isNew
        ? await createPost({
            doc: docPayload, textCache: finalText, status: "sent",
            clientReqId: createReqId.current, tweetUrl, title: title.trim() || undefined,
          })
        : await updatePost({
            postId: id!, patch: { doc: docPayload, status: "sent", tweet_url: tweetUrl, title: title.trim() },
            textCache: finalText, clientReqId: uid(),
          });
      // Always surface the live tweet, even if recording it as Sent failed.
      setTweetUrl(tweetUrl);
      setPostedUrl(tweetUrl);
      if (!saved.post_id || saved.success === false || saved.error) {
        const why = saved.error_code || saved.error || saved.message || "unknown error";
        debugPush("error", `${isNew ? "create_post" : "update_post"} after send failed: ${why}`);
        setError(`Posted to X, but couldn't record it as Sent (${why}). The tweet is live — try Save again to record it.`);
        return;
      }
      setHint("Posted to X.");
      baseline.current = sigOf(blocks, publishAt, freq, interval, ceaseAt, title);
      if (id) postCache.current.delete(id); // sent status differs from any cached row
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-zinc-950 flex items-center justify-center">
        <QuoteScroller heading={isSnippet ? "Opening the snippet…" : "Opening the editor…"} />
      </div>
    );
  }

  const openFlagCount = allFlags.length;
  const handle = xProfile?.username
    ? `@${xProfile.username}`
    : npub ? `@${npub.slice(4, 13)}…` : "@excalibur";
  const displayName = xProfile?.name || "eXcalibur";
  const cardAvatar = xProfile?.profile_image_url || avatarFor(npub);
  const railTabs = isSnippet
    ? ([["flags", `Flags ${openFlagCount ? `(${openFlagCount})` : ""}`], ["voice", "Voice"], ["snippets", "Snippets"]] as const)
    : ([["flags", `Flags ${openFlagCount ? `(${openFlagCount})` : ""}`], ["voice", "Voice"], ["snippets", "Snippets"], ["schedule", "Schedule"]] as const);

  return (
    <div className="min-h-screen w-full bg-zinc-950 text-zinc-200 flex flex-col">
      {/* Soft-swap progress strip — shown while stepping to a sibling post so the
          in-place content change reads as motion, not a frozen pause. */}
      {stepping && (
        <div className="fixed inset-x-0 top-0 z-[60] h-0.5 overflow-hidden bg-amber-400/15">
          <div className="h-full w-2/5 animate-pulse bg-amber-400" />
        </div>
      )}
      {postedUrl !== null && (
        <TweetPreviewModal
          url={postedUrl}
          text={composed}
          onClose={() => { setPostedUrl(null); nav(listPath); }}
        />
      )}
      {peekUrl !== null && (
        <TweetPreviewModal url={peekUrl} text={composed} onClose={() => setPeekUrl(null)} />
      )}
      {sel && !preview && (
        <button
          onClick={flagSelection}
          style={{ position: "fixed", left: sel.x, top: sel.y - 44, transform: "translateX(-50%)", zIndex: 50 }}
          className="flex items-center gap-1.5 rounded-full bg-amber-400 px-3 py-1.5 text-sm font-medium text-zinc-950 shadow-xl ring-1 ring-amber-300 hover:bg-amber-300 transition-colors"
        >
          <Flag className="h-3.5 w-3.5" /> Flag for AI
        </button>
      )}
      {clearPill && !preview && (
        <button
          onClick={() => removeFlag(clearPill.blockId, clearPill.flagId)}
          style={{ position: "fixed", left: clearPill.x, top: clearPill.y - 44, transform: "translateX(-50%)", zIndex: 50 }}
          className="flex items-center gap-1.5 rounded-full bg-zinc-900 px-3 py-1.5 text-sm font-medium text-white shadow-xl ring-1 ring-zinc-700 hover:bg-zinc-800 transition-colors"
        >
          <Trash2 className="h-3.5 w-3.5" /> Clear flag
        </button>
      )}

      {/* top bar */}
      <header className="flex items-center justify-between gap-4 border-b border-zinc-800 px-5 py-3">
        <div className="flex items-center gap-3">
          <button onClick={() => nav(listPath)} className="flex h-8 w-8 items-center justify-center rounded-md bg-amber-400 text-zinc-950" title={isSnippet ? "Back to snippets" : "Back to posts"}>
            <Swords className="h-5 w-5" />
          </button>
          <div className="leading-tight">
            <div className="font-serif text-lg text-zinc-50">
              {isSnippet ? "eXcalibur Snippet" : "eXcalibur Posts Manager"}
            </div>
            <div className="font-mono text-[11px] uppercase tracking-widest text-zinc-500">
              {isSnippet ? "reusable content" : "draft → refine → schedule"}
            </div>
          </div>
          {!isSnippet && curIndex >= 0 && neighbors.length > 1 && (
            <div className="ml-1 flex items-center gap-1 font-mono text-[11px] text-zinc-500">
              <button
                onClick={() => goToNeighbor(-1)}
                disabled={curIndex <= 0}
                title="Previous post (← arrow or swipe left)"
                className="rounded px-1.5 py-0.5 text-base leading-none hover:text-amber-300 disabled:opacity-30"
              >
                ‹
              </button>
              <span className="flex items-center gap-1 tabular-nums">
                {stepping && <Loader2 className="h-3 w-3 animate-spin text-amber-400" />}
                {curIndex + 1} / {neighbors.length}
              </span>
              <button
                onClick={() => goToNeighbor(1)}
                disabled={curIndex >= neighbors.length - 1}
                title="Next post (→ arrow or swipe right)"
                className="rounded px-1.5 py-0.5 text-base leading-none hover:text-amber-300 disabled:opacity-30"
              >
                ›
              </button>
            </div>
          )}
        </div>
        <div className="flex items-center gap-3">
          <div className="font-mono text-sm tabular-nums text-zinc-400">
            {charCount.toLocaleString()}<span className="ml-1 text-zinc-600">chars</span>
          </div>
          {isSnippet ? (
            <button
              onClick={() => void persistSnippet()}
              disabled={saving}
              className="flex items-center gap-1.5 rounded-md bg-amber-400 px-3 py-1.5 text-sm font-medium text-zinc-950 hover:bg-amber-300 disabled:opacity-40 transition-colors"
            >
              <Save className="h-4 w-4" /> {saving ? "Saving…" : "Save snippet"}
            </button>
          ) : (
            <>
              <button
                onClick={() => persist(false)}
                disabled={saving}
                className="flex items-center gap-1.5 rounded-md border border-zinc-700 px-3 py-1.5 text-sm text-zinc-300 hover:border-zinc-500 hover:text-zinc-100 disabled:opacity-40 transition-colors"
              >
                <Save className="h-4 w-4" /> {saving ? "Saving…" : "Save draft"}
              </button>
              <button
                onClick={() => void handlePostNow()}
                disabled={saving}
                title="Post to X now and mark this post sent"
                className="flex items-center gap-1.5 rounded-md bg-amber-400 px-3 py-1.5 text-sm font-medium text-zinc-950 hover:bg-amber-300 disabled:opacity-40 transition-colors"
              >
                <Share className="h-4 w-4" /> Post now
              </button>
            </>
          )}
          <button
            onClick={() => void saveAsCopy()}
            disabled={saving}
            title={isSnippet ? "Save the current body as a new snippet" : "Save the current body as a new draft post"}
            className="flex items-center gap-1.5 rounded-md border border-zinc-700 px-3 py-1.5 text-sm text-zinc-300 hover:border-zinc-500 hover:text-zinc-100 disabled:opacity-40 transition-colors"
          >
            <CopyPlus className="h-4 w-4" /> Save as…
          </button>
          <button
            onClick={() => { setPreview((p) => !p); setSel(null); setClearPill(null); }}
            className="flex items-center gap-1.5 rounded-md border border-zinc-700 px-3 py-1.5 text-sm text-zinc-300 hover:border-zinc-500 hover:text-zinc-100 transition-colors"
          >
            {preview ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            {preview ? "Edit" : "Preview"}
          </button>
        </div>
      </header>

      {/* Posted-to-X banner: a Sent post always shows its actual X link; clicking
          peeks at the tweet in a modal (no jumping out of the site). */}
      {!isSnippet && tweetUrl && (
        <div className="flex items-center gap-2 border-b border-zinc-800 bg-green-500/10 px-5 py-2 text-sm">
          <Check className="h-4 w-4 shrink-0 text-green-400" />
          <span className="text-green-400">Posted to X:</span>
          <button
            onClick={() => setPeekUrl(tweetUrl)}
            className="inline-flex items-center gap-1 truncate font-mono text-xs text-sky-400 hover:text-sky-300 hover:underline"
            title={`Peek at ${tweetUrl}`}
          >
            {tweetUrl} <Eye className="h-3.5 w-3.5 shrink-0" />
          </button>
        </div>
      )}

      <div className="flex flex-1 flex-col lg:flex-row">
        {/* stage */}
        <main
          onTouchStart={onStageTouchStart}
          onTouchEnd={onStageTouchEnd}
          className="relative flex flex-1 items-start justify-center overflow-y-auto px-4 py-10"
        >
          <div className="pointer-events-none absolute inset-x-0 top-0 h-64 bg-gradient-to-b from-amber-400 to-transparent opacity-5" />
          <div className="relative w-full max-w-xl">
            {isSnippet && !preview && (
              <div className="mb-3">
                <label className="mb-1.5 block font-mono text-[11px] uppercase tracking-widest text-zinc-500">Snippet name</label>
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="My CTA Footer"
                  className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-600 outline-none focus:border-amber-400"
                />
              </div>
            )}
            {!isSnippet && !preview && (
              <div className="mb-3">
                <label className="mb-1.5 block font-mono text-[11px] uppercase tracking-widest text-zinc-500">Title <span className="text-zinc-600">(optional)</span></label>
                <input
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  maxLength={200}
                  placeholder="Untitled — the list shows the first line"
                  className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-600 outline-none focus:border-amber-400"
                />
              </div>
            )}
            <div className="mb-3 flex items-center justify-between">
              <span className="font-mono text-[11px] uppercase tracking-widest text-zinc-500">
                {preview ? "as it appears on X" : "editing stage"}
              </span>
              {!preview && (
                <span className="font-mono text-[11px] text-zinc-600">
                  {openFlagCount} flag{openFlagCount === 1 ? "" : "s"} · drag to reorder
                </span>
              )}
            </div>

            <div className={`rounded-2xl bg-white p-4 text-zinc-900 shadow-2xl transition-all ${preview ? "ring-1 ring-zinc-700" : "ring-2 ring-amber-400"}`}>
              <div className="flex gap-3">
                <Avatar value={cardAvatar} size={44} className="flex-none" />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1 text-[15px]">
                    <span className="truncate font-bold text-zinc-900">{displayName}</span>
                    <BadgeCheck className="h-4 w-4 flex-none text-amber-500" />
                    <span className="truncate text-zinc-500">{handle} · now</span>
                  </div>
                  <div className="mt-1 space-y-3">
                    {blocks.map((b, idx) => (
                      <BlockView
                        key={b.id}
                        block={b}
                        idx={idx}
                        preview={preview}
                        editing={editingBlock === b.id}
                        activeFlagId={activeFlag?.flagId ?? null}
                        overIndex={overIndex}
                        resolved={resolved[b.id]}
                        onResolve={() => resolveDynamic(b)}
                        onToggleDynamic={() => toggleBlockDynamic(b.id)}
                        onChangeFallback={(t) => setBlockFallback(b.id, t)}
                        onChangeDomains={(t) => setBlockDomains(b.id, t)}
                        onChangeMaxFetches={(n) => setBlockMaxFetches(b.id, n)}
                        onChangeRuntimeLimit={(n) => setBlockRuntimeLimit(b.id, n)}
                        onMouseUp={onBlockMouseUp}
                        onFlagClick={(flagId, rect) => {
                          setActiveFlag({ blockId: b.id, flagId });
                          setTab("flags");
                          setSel(null);
                          setClearPill(rect ? { blockId: b.id, flagId, x: rect.left + rect.width / 2, y: rect.top } : null);
                        }}
                        onEdit={() => setEditingBlock(b.id)}
                        onDoneEdit={() => setEditingBlock(null)}
                        onChange={(t) => setBlockText(b.id, t)}
                        onDelete={() => deleteBlock(b.id)}
                        onMoveUp={() => moveBlock(idx, -1)}
                        onMoveDown={() => moveBlock(idx, 1)}
                        canDelete={blocks.length > 1}
                        dragHandlers={{
                          onDragStart: () => { dragIndex.current = idx; },
                          onDragEnter: () => setOverIndex(idx),
                          onDragOver: (e) => e.preventDefault(),
                          onDrop: () => onDrop(idx),
                          onDragEnd: () => { dragIndex.current = null; setOverIndex(null); },
                        }}
                      />
                    ))}
                  </div>

                  {!isSnippet && (
                    <div className="mt-4 flex max-w-md items-center justify-between text-zinc-500">
                      {([[MessageCircle, "24"], [Repeat2, "18"], [Heart, "212"], [BarChart2, "9.4K"]] as const).map(([Icon, n], i) => (
                        <div key={i} className="flex items-center gap-1.5 text-[13px]"><Icon className="h-[18px] w-[18px]" /> {n}</div>
                      ))}
                      <div className="flex items-center gap-3"><Bookmark className="h-[18px] w-[18px]" /><Share className="h-[18px] w-[18px]" /></div>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {!preview && (
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <button onClick={addBlock} className="flex items-center gap-1.5 rounded-md border border-dashed border-zinc-700 px-3 py-1.5 text-sm text-zinc-400 hover:border-amber-400 hover:text-amber-300 transition-colors">
                  <Plus className="h-4 w-4" /> Add text block
                </button>
                <button
                  onClick={insertDivider}
                  title="Insert a 20-char divider (────────────────────) as a block"
                  className="flex items-center gap-1.5 rounded-md border border-dashed border-zinc-700 px-3 py-1.5 text-sm text-zinc-400 hover:border-amber-400 hover:text-amber-300 transition-colors"
                >
                  <Minus className="h-4 w-4" /> Divider
                </button>
                {snippets.filter((s) => s.favorite).map((s) => (
                  <button
                    key={s.id}
                    onClick={() => insertSnippetRow(s)}
                    title={`Insert "${s.name}"${snippetIsDynamic(s) ? " (dynamic prompt)" : ""}`}
                    className="flex items-center gap-1 rounded-full border border-amber-400/40 bg-amber-400/10 px-3 py-1.5 text-sm text-amber-300 hover:bg-amber-400/20 transition-colors"
                  >
                    {snippetIsDynamic(s) ? <Wand2 className="h-3 w-3" /> : <Star className="h-3 w-3 fill-current" />} {s.name}
                  </button>
                ))}
              </div>
            )}
            {isSnippet && !preview && (
              <button
                onClick={handleDiscard}
                className="mt-3 text-xs text-zinc-600 hover:text-rose-400 transition-colors"
              >
                {isNew ? "Discard" : "Delete snippet"}
              </button>
            )}
            {hint && <div className="mt-3 font-mono text-xs text-amber-300">{hint}</div>}
            {error && (
              <div className="mt-3 flex flex-wrap items-center gap-3 rounded-md border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-300">
                <span>{error}</span>
                {needsXConnect && (
                  <button
                    onClick={() => nav("/profile")}
                    className="ml-auto rounded bg-amber-400 px-2.5 py-1 font-medium text-zinc-950 hover:bg-amber-300"
                  >
                    Connect X →
                  </button>
                )}
              </div>
            )}
          </div>
        </main>

        {/* rail */}
        {!preview && (
          <aside className="w-full flex-none border-t border-zinc-800 lg:w-96 lg:border-l lg:border-t-0">
            <nav className="flex border-b border-zinc-800 font-mono text-xs uppercase tracking-widest">
              {railTabs.map(([k, label]) => (
                <button key={k} onClick={() => setTab(k)} className={`flex-1 px-3 py-3 transition-colors ${tab === k ? "bg-zinc-900 text-amber-300" : "text-zinc-500 hover:text-zinc-300"}`}>{label}</button>
              ))}
            </nav>
            <div className="max-h-[60vh] overflow-y-auto p-4 lg:max-h-[calc(100vh-110px)]">
              {tab === "flags" && (
                <FlagsTab
                  allFlags={allFlags}
                  active={activeFlag}
                  setActive={setActiveFlag}
                  onNote={(blockId, flagId, note) => updateFlag(blockId, flagId, { note })}
                  onRefine={refine}
                  onApply={applySuggestion}
                  onRemove={removeFlag}
                />
              )}
              {tab === "voice" && (
                <VoiceTab
                  voice={voice} setVoice={editVoice} bans={bans} setBans={editBans}
                  loaded={voiceLoaded} dirty={voiceDirty} saving={voiceSaving}
                  saved={voiceSaved} error={voiceError} onSave={saveVoiceNow}
                />
              )}
              {tab === "snippets" && (
                <SnippetsTab
                  currentText={focusedBlockText}
                  focusedBlock={focusedBlock}
                  onInsert={insertSnippetRow}
                  snippets={snippets}
                  setSnippets={setSnippets}
                />
              )}
              {tab === "schedule" && !isSnippet && (
                <ScheduleTab
                  publishAt={publishAt} setPublishAt={setPublishAt}
                  freq={freq} setFreq={setFreq}
                  interval={interval} setInterval={setIntervalN}
                  ceaseAt={ceaseAt} setCeaseAt={setCeaseAt}
                  onSchedule={() => persist(true)} saving={saving}
                  onDiscard={handleDiscard} isNew={isNew}
                />
              )}
            </div>
          </aside>
        )}
      </div>
    </div>
  );
}

// ── block view ──────────────────────────────────────────────────────────────
function BlockView({
  block, idx, preview, editing, activeFlagId, overIndex, resolved, onResolve,
  onToggleDynamic, onChangeFallback, onChangeDomains, onChangeMaxFetches, onChangeRuntimeLimit,
  onMouseUp, onFlagClick, onEdit, onDoneEdit, onChange, onDelete, onMoveUp, onMoveDown, canDelete, dragHandlers,
}: {
  block: Block; idx: number; preview: boolean; editing: boolean; activeFlagId: string | null; overIndex: number | null;
  resolved?: ResolvedState; onResolve: () => void;
  onToggleDynamic: () => void; onChangeFallback: (t: string) => void;
  onChangeDomains: (t: string) => void; onChangeMaxFetches: (n: number) => void;
  onChangeRuntimeLimit: (n: number) => void;
  onMouseUp: (blockId: string, el: HTMLElement | null) => void;
  onFlagClick: (flagId: string, rect: DOMRect) => void;
  onEdit: () => void; onDoneEdit: () => void; onChange: (t: string) => void; onDelete: () => void;
  onMoveUp: () => void; onMoveDown: () => void; canDelete: boolean;
  dragHandlers: HTMLAttributes<HTMLDivElement>;
}) {
  const ref = useRef<HTMLParagraphElement>(null);
  const editRef = useRef<HTMLTextAreaElement>(null);
  const [showEmoji, setShowEmoji] = useState(false);
  const segs = useMemo(() => segmentize(block.text, block.flags), [block.text, block.flags]);

  if (preview) {
    // A dynamic block shows its resolved (dry-run) text — loading/fallback while
    // it resolves or if it failed. The live post resolves fresh at fire time.
    if (block.dynamic) {
      if (resolved?.loading) {
        return (
          <p className="flex items-center gap-1.5 text-[15px] italic leading-normal text-zinc-400">
            <Loader2 className="h-3.5 w-3.5 animate-spin" /> resolving…
          </p>
        );
      }
      const shown = resolved?.text || block.fallback || "";
      return (
        <p className="whitespace-pre-wrap break-words text-[15px] leading-normal text-zinc-900">
          {shown || <span className="italic text-zinc-400">(dynamic block — no preview yet)</span>}
        </p>
      );
    }
    return <p className="whitespace-pre-wrap break-words text-[15px] leading-normal text-zinc-900">{block.text}</p>;
  }
  // A dynamic block is a self-contained card: its prompt and fallback are edited
  // inline, and Run resolves it in place — no separate edit mode, no global
  // Preview needed to see the result. (A prompt isn't flaggable copy, so there's
  // no text-selection / Flag affordance here.)
  if (block.dynamic) {
    const result = resolved && !resolved.loading && resolved.text && !resolved.error ? resolved.text : "";
    return (
      <div className={`group relative -ml-7 rounded-md pl-7 ${overIndex === idx ? "ring-1 ring-amber-300" : ""}`} draggable {...dragHandlers}>
        <div className="absolute left-0 top-0 flex flex-col items-center opacity-0 transition-opacity group-hover:opacity-100">
          <GripVertical className="h-4 w-4 cursor-grab text-zinc-300" />
          <button onClick={onMoveUp} className="text-zinc-300 hover:text-amber-500"><ChevronUp className="h-3.5 w-3.5" /></button>
          <button onClick={onMoveDown} className="text-zinc-300 hover:text-amber-500"><ChevronDown className="h-3.5 w-3.5" /></button>
        </div>
        <div className="rounded-md border border-dashed border-violet-400 bg-violet-50 p-2">
          <div className="mb-1.5 flex items-center justify-between gap-2">
            <span className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-widest text-violet-600">
              <Wand2 className="h-3 w-3" /> dynamic prompt · runs at post time
            </span>
            <button
              onClick={onToggleDynamic}
              title="Turn this back into a normal text block"
              className="font-mono text-[10px] uppercase tracking-widest text-violet-400 hover:text-violet-700"
            >
              make static
            </button>
          </div>
          <textarea
            value={block.text}
            onChange={(e) => onChange(e.target.value)}
            placeholder="Write the prompt to run, e.g. 'the current BTC price in USD, one short sentence'"
            rows={Math.max(2, Math.ceil(block.text.length / 42))}
            className="w-full resize-none rounded border border-violet-300 bg-white p-2 text-[13px] leading-snug text-violet-900 placeholder:text-violet-300 outline-none focus:border-violet-500"
          />
          <input
            value={block.fallback ?? ""}
            onChange={(e) => onChangeFallback(e.target.value)}
            placeholder="Fallback text if it can't resolve (optional)"
            className="mt-1.5 w-full rounded border border-violet-200 bg-white px-2 py-1 text-[12px] text-violet-800 placeholder:text-violet-300 outline-none focus:border-violet-400"
          />
          <div className="mt-1.5 flex items-center gap-1.5">
            <input
              value={block.domains ?? ""}
              onChange={(e) => onChangeDomains(e.target.value)}
              placeholder="Allowed web domains, comma-separated (blank = any)"
              className="min-w-0 flex-1 rounded border border-violet-200 bg-white px-2 py-1 text-[12px] text-violet-800 placeholder:text-violet-300 outline-none focus:border-violet-400"
            />
            <input
              type="number"
              min={1}
              max={25}
              value={block.maxFetches ?? 5}
              onChange={(e) => onChangeMaxFetches(Number(e.target.value) || 0)}
              title="Max web lookups (search + fetch) for this prompt"
              className="w-16 flex-none rounded border border-violet-200 bg-white px-2 py-1 text-[12px] text-violet-800 outline-none focus:border-violet-400"
            />
            <input
              type="number"
              min={60}
              max={900}
              step={30}
              value={block.runtimeLimit ?? 210}
              onChange={(e) => onChangeRuntimeLimit(Number(e.target.value) || 0)}
              title="Time budget in seconds (60–900). Bounds runtime and may affect the fare."
              className="w-16 flex-none rounded border border-violet-200 bg-white px-2 py-1 text-[12px] text-violet-800 outline-none focus:border-violet-400"
            />
            <span className="flex-none text-[10px] text-violet-400">sec</span>
          </div>
          <div className="mt-1.5 flex items-center gap-2">
            <button
              onClick={onResolve}
              disabled={resolved?.loading || !block.text.trim()}
              className="flex items-center gap-1 rounded bg-violet-500 px-2 py-1 text-[11px] font-medium text-white hover:bg-violet-400 disabled:opacity-40"
            >
              {resolved?.loading ? <Loader2 className="h-3 w-3 animate-spin" /> : <Sparkles className="h-3 w-3" />}
              {resolved?.loading ? "Running…" : "Run"}
            </button>
            <span className="font-mono text-[10px] text-violet-400">preview the result here</span>
          </div>
          {result && (
            <p className="mt-1.5 rounded bg-white p-1.5 text-[13px] leading-snug text-zinc-900 ring-1 ring-emerald-200">
              {result}
            </p>
          )}
          {resolved?.error && <p className="mt-1.5 text-[11px] text-rose-500">{resolved.error}</p>}
        </div>
        <div className="absolute right-1 top-1 flex gap-1 opacity-0 transition-opacity group-hover:opacity-100">
          {canDelete && <button onClick={onDelete} title="Delete block" className="rounded bg-white p-1 text-zinc-400 shadow hover:text-rose-500"><Trash2 className="h-3.5 w-3.5" /></button>}
        </div>
      </div>
    );
  }
  if (editing) {
    const applyStyle = (style: UnicodeStyle) => {
      const ta = editRef.current;
      if (!ta || ta.selectionStart === ta.selectionEnd) return;
      const s = ta.selectionStart, e = ta.selectionEnd;
      onChange(block.text.slice(0, s) + styleText(block.text.slice(s, e), style) + block.text.slice(e));
    };
    const insertAtCursor = (ins: string) => {
      const ta = editRef.current;
      const pos = ta ? ta.selectionStart : block.text.length;
      onChange(block.text.slice(0, pos) + ins + block.text.slice(pos));
      requestAnimationFrame(() => {
        if (ta) { ta.focus(); ta.selectionStart = ta.selectionEnd = pos + ins.length; }
      });
    };
    const fmtBtn = (label: ReactNode, style: UnicodeStyle, tip: string) => (
      <button
        onMouseDown={(ev) => ev.preventDefault()}
        onClick={() => applyStyle(style)}
        title={tip}
        className="rounded px-1.5 py-0.5 text-zinc-700 hover:bg-amber-200"
      >
        {label}
      </button>
    );
    return (
      <div className="rounded-md ring-1 ring-amber-400">
        <div className="relative flex items-center gap-1 rounded-t-md bg-amber-100 px-2 py-1">
          {fmtBtn(<Bold className="h-3.5 w-3.5" />, "bold", "Bold (Unicode)")}
          {fmtBtn(<Italic className="h-3.5 w-3.5" />, "italic", "Italic (Unicode)")}
          {fmtBtn(<Code className="h-3.5 w-3.5" />, "mono", "Monospace (Unicode)")}
          <button
            onMouseDown={(ev) => ev.preventDefault()}
            onClick={() => setShowEmoji((v) => !v)}
            title="Insert emoji or symbol"
            className="rounded px-1.5 py-0.5 text-zinc-700 hover:bg-amber-200"
          >
            <Smile className="h-3.5 w-3.5" />
          </button>
          <span className="ml-2 text-[10px] text-amber-700">select text to style; ☺ inserts a symbol</span>
          {showEmoji && (
            <div className="absolute left-0 top-full z-30 mt-1 max-h-72 w-80 overflow-y-auto rounded-md border border-zinc-300 bg-white p-2 shadow-xl">
              {EMOJI_GROUPS.map((group) => (
                <div key={group.label}>
                  <div className="sticky top-0 bg-white px-1 py-0.5 text-[10px] font-mono uppercase tracking-widest text-zinc-400">
                    {group.label}
                  </div>
                  <div className="grid grid-cols-10 gap-0.5">
                    {group.emojis.map((em, i) => (
                      <button
                        key={`${group.label}-${i}`}
                        onMouseDown={(ev) => ev.preventDefault()}
                        onClick={() => { insertAtCursor(em); setShowEmoji(false); }}
                        className="rounded p-1 text-lg hover:bg-amber-100"
                      >
                        {em}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
        <textarea
          ref={editRef}
          autoFocus value={block.text} onChange={(e) => onChange(e.target.value)}
          rows={Math.max(2, Math.ceil(block.text.length / 42))}
          className="w-full resize-none bg-amber-50 p-2 text-[15px] leading-normal text-zinc-900 outline-none"
        />
        <div className="flex items-center justify-between rounded-b-md bg-amber-100 px-2 py-1">
          <span className="font-mono text-[10px] text-amber-700">
            {block.dynamic ? "this is a dynamic prompt — it runs at post time" : "editing clears this block's flags"}
          </span>
          <button onClick={onDoneEdit} className="rounded bg-zinc-900 px-2 py-0.5 text-xs text-white hover:bg-zinc-700">Done</button>
        </div>
      </div>
    );
  }
  return (
    <div className={`group relative -ml-7 flex items-start gap-1 rounded-md pl-7 ${overIndex === idx ? "ring-1 ring-amber-300" : ""}`} draggable {...dragHandlers}>
      <div className="absolute left-0 top-0 flex flex-col items-center opacity-0 transition-opacity group-hover:opacity-100">
        <GripVertical className="h-4 w-4 cursor-grab text-zinc-300" />
        <button onClick={onMoveUp} className="text-zinc-300 hover:text-amber-500"><ChevronUp className="h-3.5 w-3.5" /></button>
        <button onClick={onMoveDown} className="text-zinc-300 hover:text-amber-500"><ChevronDown className="h-3.5 w-3.5" /></button>
      </div>
      <p
        ref={ref}
        onMouseUp={() => onMouseUp(block.id, ref.current)}
        onTouchEnd={() => onMouseUp(block.id, ref.current)}
        className="flex-1 cursor-text select-text whitespace-pre-wrap break-words text-[15px] leading-normal text-zinc-900"
      >
        {segs.map((s, i) => {
          if (!s.flag) return <span key={i}>{s.text}</span>;
          const c = paletteOf(s.flag.colorIdx || 0);
          const isActive = s.flag.id === activeFlagId;
          return (
            <mark key={i} onClick={(e) => onFlagClick(s.flag!.id, e.currentTarget.getBoundingClientRect())}
              className={`cursor-pointer rounded px-0.5 ${isActive ? c.active + " ring-1 ring-zinc-900" : c.mark}`}>
              {s.text}
            </mark>
          );
        })}
      </p>
      <div className="absolute right-1 top-1 flex gap-1 opacity-0 transition-opacity group-hover:opacity-100">
        <button onClick={onToggleDynamic} title="Make dynamic — turn this block's text into a prompt that runs at post time" className="rounded bg-white p-1 text-zinc-400 shadow hover:text-violet-500"><Wand2 className="h-3.5 w-3.5" /></button>
        <button onClick={onEdit} title="Edit text" className="rounded bg-white p-1 text-zinc-400 shadow hover:text-amber-500"><Pencil className="h-3.5 w-3.5" /></button>
        {canDelete && <button onClick={onDelete} title="Delete block" className="rounded bg-white p-1 text-zinc-400 shadow hover:text-rose-500"><Trash2 className="h-3.5 w-3.5" /></button>}
      </div>
    </div>
  );
}

type FlagWithBlock = FlagT & { blockId: string; blockText: string };

// ── flags tab ─────────────────────────────────────────────────────────────
function FlagsTab({
  allFlags, active, setActive, onNote, onRefine, onApply, onRemove,
}: {
  allFlags: FlagWithBlock[]; active: ActiveFlag | null; setActive: (a: ActiveFlag) => void;
  onNote: (blockId: string, flagId: string, note: string) => void;
  onRefine: (blockId: string, flag: FlagT) => void;
  onApply: (blockId: string, flag: FlagT, text: string) => void;
  onRemove: (blockId: string, flagId: string) => void;
}) {
  if (!allFlags.length) {
    return (
      <div className="rounded-lg border border-dashed border-zinc-800 p-6 text-center">
        <Flag className="mx-auto mb-2 h-5 w-5 text-zinc-600" />
        <p className="text-sm text-zinc-400">Select any text in the tweet and tap <span className="text-amber-300">Flag for AI</span> to start a refinement.</p>
        <p className="mt-2 font-mono text-[11px] text-zinc-600">swipe-select works on touch too</p>
      </div>
    );
  }
  return (
    <div className="space-y-3">
      {allFlags.map((f) => {
        const isActive = active?.flagId === f.id;
        const region = f.blockText.slice(f.start, f.end);
        const c = paletteOf(f.colorIdx || 0);
        return (
          <div key={f.id} className={`rounded-lg border p-3 transition-colors ${isActive ? "border-amber-400 bg-zinc-900" : "border-zinc-800 bg-zinc-900"}`} onClick={() => setActive({ blockId: f.blockId, flagId: f.id })}>
            <div className="mb-2 flex items-start justify-between gap-2">
              <div className="flex min-w-0 items-start gap-2">
                <span className={`mt-1 h-2.5 w-2.5 flex-none rounded-full ${c.dot}`} />
                <p className={`rounded ${c.mark} px-1.5 py-0.5 text-[13px] text-zinc-900`}>"{region}"</p>
              </div>
              <button onClick={(e) => { e.stopPropagation(); onRemove(f.blockId, f.id); }} title="Clear flag" className="flex flex-none items-center gap-1 rounded text-zinc-500 hover:text-rose-400"><Trash2 className="h-4 w-4" /></button>
            </div>
            <textarea
              value={f.note} onChange={(e) => onNote(f.blockId, f.id, e.target.value)} onClick={(e) => e.stopPropagation()}
              placeholder="What should change here? (optional)" rows={2}
              className="w-full resize-none rounded-md border border-zinc-700 bg-zinc-950 p-2 text-sm text-zinc-200 placeholder:text-zinc-600 outline-none focus:border-amber-400"
            />
            <button onClick={(e) => { e.stopPropagation(); onRefine(f.blockId, f); }} disabled={f.loading}
              className="mt-2 flex w-full items-center justify-center gap-1.5 rounded-md bg-amber-400 px-3 py-1.5 text-sm font-medium text-zinc-950 hover:bg-amber-300 disabled:opacity-60 transition-colors">
              {f.loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Wand2 className="h-4 w-4" />}
              {f.loading ? "Refining…" : "Refine with Claude"}
            </button>
            {f.error && <p className="mt-2 text-xs text-rose-400">{f.error}</p>}
            {f.suggestions.length > 0 && (
              <div className="mt-3 space-y-2">
                <div className="flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-widest text-zinc-500"><Sparkles className="h-3 w-3" /> suggestions</div>
                {f.suggestions.map((s, i) => (
                  <div key={i} className="rounded-md border border-zinc-700 bg-zinc-950 p-2">
                    <p className="text-sm text-zinc-200">{s}</p>
                    <button onClick={(e) => { e.stopPropagation(); onApply(f.blockId, f, s); }} className="mt-1.5 flex items-center gap-1 text-xs text-amber-300 hover:text-amber-200"><Check className="h-3.5 w-3.5" /> Use this</button>
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── snippets tab ────────────────────────────────────────────────────────────
function SnippetsTab({
  currentText, focusedBlock, onInsert, snippets, setSnippets,
}: {
  currentText: string;
  focusedBlock?: Block;
  onInsert: (s: Snippet) => void;
  snippets: Snippet[];
  setSnippets: (s: Snippet[]) => void;
}) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);

  // Save the focused block as a reusable snippet. If it's dynamic, serialize the
  // whole block into the snippet doc so its prompt + fallback + domains +
  // maxFetches round-trip on re-insert (not just the text).
  async function save() {
    const n = name.trim();
    const t = currentText.trim();
    if (!n || !t) return;
    setBusy(true);
    try {
      const doc = focusedBlock?.dynamic ? serializeBlocks([focusedBlock]) : undefined;
      setSnippets(await addSnippet(n, t, doc ? { doc } : {}));
      setName("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <div>
        <div className="text-xs uppercase tracking-widest text-zinc-500 mb-1">Save the focused block</div>
        <div className="flex gap-2">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="My CTA Footer 26jun2026"
            className="flex-1 rounded-md border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-sm text-zinc-200 placeholder:text-zinc-600 outline-none focus:border-amber-400"
          />
          <button
            onClick={save}
            disabled={busy || !name.trim() || !currentText.trim()}
            className="rounded-md bg-amber-400 px-3 py-1.5 text-sm font-medium text-zinc-950 hover:bg-amber-300 disabled:opacity-40 transition-colors"
          >
            {busy ? "…" : "Save"}
          </button>
        </div>
        <p className="mt-1 text-[11px] text-zinc-500 line-clamp-2">
          {currentText.trim()
            ? `Saves: "${currentText.trim().slice(0, 80)}${currentText.trim().length > 80 ? "…" : ""}"`
            : "Click into a block first, then save its text as a reusable snippet."}
        </p>
      </div>

      <div>
        <div className="text-xs uppercase tracking-widest text-zinc-500 mb-2">Library</div>
        {snippets.length === 0 ? (
          <p className="text-xs text-zinc-500">
            No snippets yet — save common openings and footers here, then click to drop them into any post.
          </p>
        ) : (
          <div className="space-y-2">
            {snippets.map((s) => {
              const dyn = snippetIsDynamic(s);
              return (
              <div key={s.id} className="rounded-lg border border-zinc-800 bg-zinc-900 p-2.5">
                <div className="flex items-center gap-2">
                  <button
                    onClick={async () => setSnippets(await toggleFavorite(s.id, !s.favorite))}
                    title={s.favorite ? "Unfavorite" : "Favorite — adds a one-click chiclet by Add text block"}
                    className={s.favorite ? "text-amber-400" : "text-zinc-600 hover:text-amber-400"}
                  >
                    <Star className={`h-3.5 w-3.5 ${s.favorite ? "fill-current" : ""}`} />
                  </button>
                  <button
                    onClick={async () => setSnippets(await toggleDynamic(s, !dyn))}
                    title={dyn ? "Dynamic — its text is a prompt run at post time. Click to make static." : "Make dynamic — treat its text as a prompt run at post time"}
                    className={`flex-none ${dyn ? "text-violet-400" : "text-zinc-600 hover:text-violet-400"}`}
                  >
                    <Wand2 className="h-3.5 w-3.5" />
                  </button>
                  <span className="flex-1 min-w-0 truncate text-sm text-zinc-200">{s.name}</span>
                  <button onClick={() => onInsert(s)} className="text-xs text-amber-300 hover:text-amber-200" title={dyn ? "Add as a dynamic block" : "Add as a block"}>
                    + Insert
                  </button>
                  <button onClick={async () => setSnippets(await removeSnippet(s.id))} className="text-zinc-500 hover:text-rose-400" title="Delete snippet">
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
                <p className="mt-1 text-[11px] text-zinc-500 line-clamp-2">{s.text}</p>
              </div>
            ); })}
          </div>
        )}
      </div>
    </div>
  );
}

function VoiceTab({
  voice, setVoice, bans, setBans, loaded, dirty, saving, saved, error, onSave,
}: {
  voice: string; setVoice: (v: string) => void;
  bans: Ban[]; setBans: (updater: SetStateAction<Ban[]>) => void;
  loaded: boolean; dirty: boolean; saving: boolean; saved: boolean;
  error: string; onSave: () => void;
}) {
  const [editing, setEditing] = useState<number | null>(null);
  const [draft, setDraft] = useState("");
  const [adding, setAdding] = useState("");

  const toggle = (i: number) => setBans((prev) => prev.map((b, j) => (j === i ? { ...b, on: !b.on } : b)));
  const remove = (i: number) => setBans((prev) => prev.filter((_, j) => j !== i));
  const startEdit = (i: number) => { setEditing(i); setDraft(bans[i].text); };
  const commitEdit = () => {
    if (editing === null) return;
    const text = draft.trim();
    const i = editing;
    setBans((prev) => (text ? prev.map((b, j) => (j === i ? { ...b, text } : b)) : prev.filter((_, j) => j !== i)));
    setEditing(null); setDraft("");
  };
  const addBan = () => {
    const text = adding.trim();
    if (!text) return;
    setBans((prev) => (prev.some((b) => b.text.toLowerCase() === text.toLowerCase())
      ? prev
      : [...prev, { text, on: true }]));
    setAdding("");
  };

  return (
    <div className="space-y-5">
      <div>
        <label className="mb-1.5 block font-mono text-[11px] uppercase tracking-widest text-zinc-500">Voice profile</label>
        <textarea value={voice} onChange={(e) => setVoice(e.target.value)} rows={5} disabled={!loaded}
          className="w-full resize-none rounded-md border border-zinc-700 bg-zinc-900 p-2 text-sm text-zinc-200 outline-none focus:border-amber-400 disabled:opacity-50"
          placeholder="Paste a few sentences in your own voice…" />
        <p className="mt-1.5 text-xs text-zinc-500">Fed to Claude on every refinement so rewrites sound like you, not like a model.</p>
      </div>
      <div>
        <label className="mb-2 block font-mono text-[11px] uppercase tracking-widest text-zinc-500">Banned constructions</label>
        <div className="flex flex-wrap gap-2">
          {bans.map((b, i) => (
            editing === i ? (
              <span key={i} className="flex items-center gap-1 rounded-full border border-amber-400 bg-zinc-900 pl-2.5 pr-1 py-0.5">
                <input autoFocus value={draft} onChange={(e) => setDraft(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") commitEdit(); if (e.key === "Escape") { setEditing(null); setDraft(""); } }}
                  className="w-32 bg-transparent text-xs text-zinc-100 outline-none" />
                <button onClick={commitEdit} title="Save chip" className="rounded-full p-0.5 text-amber-300 hover:text-amber-200">
                  <Check className="h-3 w-3" />
                </button>
              </span>
            ) : (
              <span key={i}
                className={`flex items-center gap-1 rounded-full border pl-2.5 pr-1 py-1 text-xs transition-colors ${b.on ? "border-amber-400 bg-amber-400 text-zinc-950" : "border-zinc-700 text-zinc-500 line-through"}`}>
                <button onClick={() => toggle(i)} title="Toggle constraint" className="max-w-[12rem] truncate">{b.text}</button>
                <button onClick={() => startEdit(i)} title="Edit" className={`rounded-full p-0.5 ${b.on ? "hover:bg-amber-500/40" : "hover:bg-zinc-700"}`}>
                  <Pencil className="h-2.5 w-2.5" />
                </button>
                <button onClick={() => remove(i)} title="Remove" className={`rounded-full p-0.5 ${b.on ? "hover:bg-amber-500/40" : "hover:bg-zinc-700"}`}>
                  <Minus className="h-2.5 w-2.5" />
                </button>
              </span>
            )
          ))}
        </div>
        <div className="mt-2 flex items-center gap-1.5">
          <input value={adding} onChange={(e) => setAdding(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") addBan(); }}
            placeholder="Add a construction to avoid…"
            className="flex-1 rounded-md border border-zinc-700 bg-zinc-900 px-2 py-1 text-xs text-zinc-200 outline-none focus:border-amber-400" />
          <button onClick={addBan} disabled={!adding.trim()} title="Add"
            className="flex items-center gap-1 rounded-md border border-zinc-700 px-2 py-1 text-xs text-zinc-300 hover:border-amber-400 hover:text-amber-300 disabled:opacity-40">
            <Plus className="h-3 w-3" /> Add
          </button>
        </div>
        <p className="mt-2 text-xs text-zinc-500">Active chips are passed as hard constraints. Tap a chip to disable it, the pencil to edit, the minus to remove.</p>
      </div>
      <div className="flex items-center gap-3 border-t border-zinc-800 pt-3">
        <button onClick={onSave} disabled={!loaded || saving || !dirty}
          className="flex items-center gap-1.5 rounded-md bg-amber-400 px-3 py-1.5 text-sm font-medium text-zinc-950 hover:bg-amber-300 disabled:cursor-not-allowed disabled:opacity-40">
          {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}
          {saving ? "Saving…" : "Save Voice"}
        </button>
        {error
          ? <span className="text-xs text-red-400">{error}</span>
          : saved && !dirty
            ? <span className="flex items-center gap-1 text-xs text-emerald-400"><Check className="h-3.5 w-3.5" /> Saved</span>
            : dirty
              ? <span className="text-xs text-zinc-500">Unsaved changes</span>
              : null}
      </div>
    </div>
  );
}

// ── schedule tab ────────────────────────────────────────────────────────────
function ScheduleTab({
  publishAt, setPublishAt, freq, setFreq, interval, setInterval, ceaseAt, setCeaseAt,
  onSchedule, saving, onDiscard, isNew,
}: {
  publishAt: string; setPublishAt: (v: string) => void;
  freq: Freq; setFreq: (v: Freq) => void;
  interval: number; setInterval: (v: number) => void;
  ceaseAt: string; setCeaseAt: (v: string) => void;
  onSchedule: () => void; saving: boolean; onDiscard: () => void; isNew: boolean;
}) {
  const field = "w-full rounded-md border border-zinc-700 bg-zinc-900 p-2 text-sm text-zinc-200 outline-none focus:border-amber-400";
  const canSchedule = !!publishAt;
  return (
    <div className="space-y-5">
      <div>
        <label className="mb-1.5 flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-widest text-zinc-500"><Calendar className="h-3.5 w-3.5" /> Publish at</label>
        <input type="datetime-local" value={publishAt} onChange={(e) => setPublishAt(e.target.value)} className={field} />
      </div>
      <div>
        <label className="mb-1.5 flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-widest text-zinc-500"><Repeat className="h-3.5 w-3.5" /> Republish</label>
        <div className="flex gap-2">
          <select value={freq} onChange={(e) => setFreq(e.target.value as Freq)} className={field}>
            <option value="none">Once, no repeat</option>
            <option value="daily">Daily</option>
            <option value="weekdays">Business Days (Mon–Fri)</option>
            <option value="weekly">Weekly</option>
            <option value="monthly">Monthly</option>
          </select>
          {freq !== "none" && (
            <div className="flex flex-none items-center gap-1.5">
              <span className="text-xs text-zinc-500">every</span>
              <input type="number" min={1} value={interval} onChange={(e) => setInterval(Math.max(1, Number(e.target.value) || 1))}
                className="w-14 rounded-md border border-zinc-700 bg-zinc-900 p-2 text-center text-sm text-zinc-200 outline-none focus:border-amber-400" />
            </div>
          )}
        </div>
      </div>
      <div>
        <label className="mb-1.5 flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-widest text-zinc-500"><Octagon className="h-3.5 w-3.5" /> Cease republication</label>
        <input type="datetime-local" value={ceaseAt} onChange={(e) => setCeaseAt(e.target.value)} disabled={freq === "none"} className={`${field} disabled:opacity-40`} />
      </div>

      <CalendarPreview publishAt={publishAt} freq={freq} interval={interval} ceaseAt={ceaseAt} />

      <button onClick={onSchedule} disabled={!canSchedule || saving}
        className="flex w-full items-center justify-center gap-2 rounded-md bg-amber-400 px-4 py-2.5 text-sm font-semibold text-zinc-950 hover:bg-amber-300 disabled:cursor-not-allowed disabled:opacity-40 transition-colors">
        <Swords className="h-4 w-4" /> {saving ? "Scheduling…" : "Schedule with Excalibur"}
      </button>
      <p className="text-center text-xs text-zinc-500">
        {!canSchedule ? "Set a publish time to schedule." : "Persists to Excalibur; the scheduler runs check_price → post_tweet per occurrence."}
      </p>
      <button onClick={onDiscard} className="w-full text-center text-xs text-zinc-600 hover:text-rose-400 transition-colors">
        {isNew ? "Discard draft" : "Archive post"}
      </button>
    </div>
  );
}

// Step a date forward one recurrence step (mirrors the BE scheduler's _advance:
// daily/weekly add days; weekdays adds business days skipping Sat/Sun; monthly
// adds months and clamps to the month's length).
function advance(d: Date, freq: Freq, interval: number): Date {
  const n = Math.max(1, Number(interval) || 1);
  const r = new Date(d);
  if (freq === "daily") r.setDate(r.getDate() + n);
  else if (freq === "weekdays") {
    let added = 0;
    while (added < n) {
      r.setDate(r.getDate() + 1);
      const dow = r.getDay(); // 0=Sun .. 6=Sat
      if (dow !== 0 && dow !== 6) added += 1;
    }
  }
  else if (freq === "weekly") r.setDate(r.getDate() + 7 * n);
  else if (freq === "monthly") {
    const day = r.getDate();
    r.setDate(1);
    r.setMonth(r.getMonth() + n);
    const dim = new Date(r.getFullYear(), r.getMonth() + 1, 0).getDate();
    r.setDate(Math.min(day, dim));
  }
  return r;
}

// A compact month calendar that marks a scheduled post's start, its recurrence
// occurrences, and the cease date — replaces the raw intent-JSON dump.
function CalendarPreview({ publishAt, freq, interval, ceaseAt }: {
  publishAt: string; freq: Freq; interval: number; ceaseAt: string;
}) {
  const start = publishAt ? new Date(publishAt) : null;
  const valid = !!start && !isNaN(start.getTime());
  const cease = ceaseAt ? new Date(ceaseAt) : null;
  const ceaseValid = !!cease && !isNaN(cease.getTime());

  // Month currently shown; defaults to the start month, re-centering if it moves.
  const [view, setView] = useState(() => {
    const base = valid ? start! : new Date();
    return { y: base.getFullYear(), m: base.getMonth() };
  });
  useEffect(() => {
    if (valid) setView({ y: start!.getFullYear(), m: start!.getMonth() });
    // Only re-center when the start date itself changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [publishAt]);

  const dayKey = (y: number, m: number, d: number) => `${y}-${m}-${d}`;

  // Occurrence days, stepping from start until cease (or a horizon cap).
  const occ = useMemo(() => {
    const set = new Set<string>();
    if (!valid) return set;
    if (freq === "none") {
      set.add(dayKey(start!.getFullYear(), start!.getMonth(), start!.getDate()));
      return set;
    }
    let cur = new Date(start!);
    for (let i = 0; i < 240; i++) {
      if (ceaseValid && cur > cease!) break;
      set.add(dayKey(cur.getFullYear(), cur.getMonth(), cur.getDate()));
      cur = advance(cur, freq, interval);
    }
    return set;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [publishAt, freq, interval, ceaseAt]);

  if (!valid) {
    return <p className="text-xs text-zinc-500">Set a publish time to preview the schedule.</p>;
  }

  const startKey = dayKey(start!.getFullYear(), start!.getMonth(), start!.getDate());
  const ceaseKey = ceaseValid ? dayKey(cease!.getFullYear(), cease!.getMonth(), cease!.getDate()) : null;
  const first = new Date(view.y, view.m, 1);
  const daysInMonth = new Date(view.y, view.m + 1, 0).getDate();
  const lead = first.getDay();
  const cells: (number | null)[] = [
    ...Array(lead).fill(null),
    ...Array.from({ length: daysInMonth }, (_, i) => i + 1),
  ];
  const monthLabel = first.toLocaleString(undefined, { month: "long", year: "numeric" });
  const prev = () => setView((v) => (v.m === 0 ? { y: v.y - 1, m: 11 } : { y: v.y, m: v.m - 1 }));
  const next = () => setView((v) => (v.m === 11 ? { y: v.y + 1, m: 0 } : { y: v.y, m: v.m + 1 }));

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-3">
      <div className="mb-2 flex items-center justify-between">
        <button onClick={prev} title="Previous month" className="rounded px-2 text-zinc-500 hover:text-amber-300">‹</button>
        <span className="font-mono text-[11px] uppercase tracking-widest text-zinc-400">{monthLabel}</span>
        <button onClick={next} title="Next month" className="rounded px-2 text-zinc-500 hover:text-amber-300">›</button>
      </div>
      <div className="grid grid-cols-7 gap-0.5 text-center">
        {["S", "M", "T", "W", "T", "F", "S"].map((d, i) => (
          <div key={i} className="pb-1 font-mono text-[9px] uppercase text-zinc-600">{d}</div>
        ))}
        {cells.map((day, i) => {
          if (day === null) return <div key={i} />;
          const k = dayKey(view.y, view.m, day);
          const isStart = k === startKey;
          const isOcc = occ.has(k);
          const isCease = k === ceaseKey;
          let cls = "text-zinc-500";
          if (isOcc) cls = "bg-amber-400/20 text-amber-300";
          if (isStart) cls = "bg-amber-400 font-semibold text-zinc-950";
          if (isCease) cls = `ring-1 ring-rose-400 text-rose-300${isStart || isOcc ? " bg-amber-400/20" : ""}`;
          return (
            <div key={i} className={`flex aspect-square items-center justify-center rounded text-[11px] tabular-nums ${cls}`}>
              {day}
            </div>
          );
        })}
      </div>
      <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[10px] text-zinc-500">
        <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-sm bg-amber-400" /> start</span>
        {freq !== "none" && <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-sm bg-amber-400/30" /> repeats</span>}
        {ceaseKey && <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-sm ring-1 ring-rose-400" /> cease</span>}
      </div>
    </div>
  );
}

function toLocalInput(iso: string): string {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "";
  const local = new Date(d.getTime() - d.getTimezoneOffset() * 60000);
  return local.toISOString().slice(0, 16);
}
