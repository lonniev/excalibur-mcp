import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { HTMLAttributes, ReactNode, SetStateAction } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  MessageCircle, Repeat2, Heart, BarChart2, Bookmark, Share, BadgeCheck,
  Sparkles, Flag, GripVertical, Pencil, Trash2, Plus, Calendar, Repeat,
  Octagon, Check, ChevronUp, ChevronDown, Eye, EyeOff,
  Wand2, Loader2, Swords, Save, Bold, Italic, Code, Smile, Star, Minus,
  CopyPlus, X,
} from "lucide-react";
import { getResolveBudgets } from "../lib/mcp";
import { Avatar, Tx, useAppShell, useLanguageLocale, useTimezone } from "@tollbooth-dpyc/web/react";
import { tr, useT, WORDS } from "../i18n";
import type { MessageKey } from "../i18n/en";
import { avatarFor, datetimeLocalValueToIso, debugPush, isoToDatetimeLocalValue } from "@tollbooth-dpyc/web";
import { cachedXProfile, ensureXProfile } from "../lib/xProfile";
import type { XProfile } from "../lib/mcp";
import { styleText, type UnicodeStyle } from "../lib/unicodeFormat";
import {
  addSnippet, loadSnippets, removeSnippet, snippetIsDynamic,
  toggleDynamic, toggleFavorite, type Snippet,
} from "../lib/snippets";
import { QuoteScroller } from "@tollbooth-dpyc/web/react";
import { QUOTES } from "../lib/quotes";
import { quoteStyles } from "../lib/quoteStyles";

// Categorized symbols + emoji for the picker. X renders the full Unicode/Twemoji
// set, so this is a broad curated palette (authors shouldn't memorize code
// points). Insertion is plain text, so everything posts as-is.
const EMOJI_GROUPS: { label: MessageKey; emojis: string[] }[] = [
  { label: "ui.contentEditorPage.emoji.typographic", emojis: ["™", "©", "®", "→", "←", "↑", "↓", "•", "★", "☆", "✓", "✗", "—", "–", "…", "₿", "§", "¶", "°", "×", "÷", "±", "≈", "≠", "™", "✦", "✧", "✶", "❝", "❞"] },
  { label: "ui.contentEditorPage.emoji.smileys", emojis: ["😀", "😁", "😂", "🤣", "😅", "😊", "😍", "😎", "🤩", "😏", "😉", "🙃", "😴", "🤔", "🧐", "🤨", "😬", "😅", "😭", "😤", "😡", "🥳", "🥺", "😱", "🤯", "🙄", "😇", "🤗", "🫡", "🫠"] },
  { label: "ui.contentEditorPage.emoji.people", emojis: ["👍", "👎", "👏", "🙌", "🙏", "🤝", "👇", "👆", "👉", "👈", "✊", "✌️", "🤞", "🤙", "💪", "🫵", "👀", "🧠", "🗣️", "👤", "👥", "🧑‍💻", "🦸", "🫶", "👋"] },
  { label: "ui.contentEditorPage.emoji.nature", emojis: ["🔥", "⚡", "🌟", "✨", "💥", "☀️", "🌈", "🌊", "🌍", "🌙", "⭐", "❄️", "🍀", "🌱", "🌹", "🌸", "🌳", "🐝", "🦋", "🐢"] },
  { label: "ui.contentEditorPage.emoji.food", emojis: ["☕", "🍵", "🍺", "🍷", "🥂", "🍾", "🍕", "🍔", "🌮", "🍩", "🍪", "🎂", "🍎", "🍊", "🍓", "🥑", "🧂", "🍫", "🍿", "🧊"] },
  { label: "ui.contentEditorPage.emoji.objects", emojis: ["🚀", "🎯", "💡", "🔑", "🗝️", "🔒", "🔓", "📌", "📎", "✂️", "🛠️", "⚙️", "🧰", "🔧", "🔨", "⚔️", "🛡️", "🏆", "🎖️", "🥇", "🎁", "🎉", "🎊", "🔔", "📣", "📢", "🔍", "🔎", "💼", "📚"] },
  { label: "ui.contentEditorPage.emoji.travel", emojis: ["✈️", "🚗", "🚢", "🚆", "🗺️", "🧭", "🏔️", "🏝️", "🏛️", "🏗️", "🏠", "🌆", "🗽", "⛩️", "🚦", "⚓", "🛰️", "🛸", "🧳", "🪧"] },
  { label: "ui.contentEditorPage.emoji.symbols", emojis: ["✅", "❌", "⭕", "❗", "❓", "⚠️", "♻️", "✳️", "❇️", "🔆", "🆕", "🆗", "🔝", "🔚", "©️", "®️", "™️", "💯", "🚫", "⛔", "🔴", "🟢", "🟡", "🔵", "⚫", "⚪", "🟠", "🟣", "🔺", "🔻"] },
  { label: "ui.contentEditorPage.emoji.money", emojis: ["₿", "💰", "💸", "💵", "💴", "💶", "💷", "🪙", "💳", "📈", "📉", "📊", "💹", "🧾", "🏦", "⚖️", "🤑", "💲", "🏧", "💎"] },
];
import {
  createPost, deletePost, getPost, getSnippet, getVoice, listPosts, postNostrMessage, postTweet, refinePostRegion,
  resolveDynamicBlock, saveSnippet, saveVoice, updatePost,
  OAUTH_NEEDED_CODES, type PostRow, type PostSummary, type Recurrence,
} from "../lib/mcp";
import TweetPreviewModal from "./TweetPreviewModal";
import {
  charOffset, composeText, DEFAULT_BANS, DEFAULT_VOICE, hasDynamic, overlaps, paletteOf,
  parsePostDoc, segmentize, serializeBlocks, TWEET_URL_TOKEN, uid, withTweetUrl,
  type Ban, type Block, type Flag as FlagT,
} from "../lib/editorDoc";
import {
  clearDraft, draftIsUnsaved, readDraft, saveError, writeDraft, type LocalDraft,
} from "../lib/postDraft";
import ReadinessBadge from "./ReadinessBadge";
import { archivePrompt, nextSweepSlot, type Flip } from "../lib/readiness";

type Kind = "post" | "snippet";
type Freq = "none" | "daily" | "weekdays" | "weekly" | "monthly";
// A selection to flag. `parts` is one range per spanned block (length 1 for a
// single-block selection, 2+ when it crosses block boundaries). x/y position the
// floating "Flag for AI" chiclet.
interface SelPart { blockId: string; start: number; end: number }
// A captured, PERSISTENT flag selection — one range per spanned block. It
// survives scrolls and stray taps (the flag bar is fixed to the viewport, not
// anchored to the selection), so it's not a one-shot; it clears only when
// flagged, dismissed, or replaced by a new selection.
interface Sel { parts: SelPart[] }
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
  const { npub } = useAppShell().session;
  const [, timeZone] = useTimezone();
  const t = useT();
  const locale = useLanguageLocale();
  // When the Profile zone changes, re-express wall datetime-local values so the
  // underlying UTC instant stays put (acceptance: live update, no reload).
  const prevTimeZone = useRef(timeZone);
  useEffect(() => {
    if (prevTimeZone.current === timeZone) return;
    const from = prevTimeZone.current;
    prevTimeZone.current = timeZone;
    setPublishAt((prev) => {
      if (!prev) return prev;
      const iso = datetimeLocalValueToIso(prev, from);
      return iso ? isoToDatetimeLocalValue(iso, timeZone) : prev;
    });
    setCeaseAt((prev) => {
      if (!prev) return prev;
      const iso = datetimeLocalValueToIso(prev, from);
      return iso ? isoToDatetimeLocalValue(iso, timeZone) : prev;
    });
  }, [timeZone]);
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
  // The post's currently-persisted status — what the badge shows until it is
  // flipped. Kept in sync on every confirmed save so successive saves in one
  // session stay correct.
  const [loadedStatus, setLoadedStatus] = useState<string>("draft");
  // The badge flipped but not yet saved: the wire status the next Save will
  // persist. Null means untouched, and Save then leaves the status alone — a
  // content edit to a scheduled (or paused, or resolving) post never changes
  // its state as a side effect.
  const [wanted, setWanted] = useState<Flip | null>(null);
  // Set when the opened post is a published snapshot → the recurring template it
  // fired from. Drives the "edit the template instead" banner.
  const [templateId, setTemplateId] = useState<string | null>(null);

  const [loading, setLoading] = useState(!isNew);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // A device-local autosave that is newer than the server's copy — surfaced as a
  // "restore unsaved edits" banner so a blocked save / reload / crash never
  // silently loses the author's work (posts only; snippets save elsewhere).
  const [pendingDraft, setPendingDraft] = useState<LocalDraft | null>(null);
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
    const pub = row.publish_at ? isoToDatetimeLocalValue(row.publish_at, timeZone) : "";
    const fq: Freq = rec?.freq ?? "none";
    const iv = rec?.interval || 1;
    const cz = row.cease_at ? isoToDatetimeLocalValue(row.cease_at, timeZone) : "";
    const ttl = row.title ?? "";
    setBlocks(loaded);
    setPublishAt(pub);
    setFreq(fq);
    setIntervalN(iv);
    setCeaseAt(cz);
    setTitle(ttl);
    setTweetUrl(row.tweet_url ?? null);
    setLoadedStatus(row.status ?? "draft");
    setWanted(null);
    setTemplateId(row.template_id ?? null);
    baseline.current = sigOf(loaded, pub, fq, iv, cz, ttl);
  }, [sigOf, timeZone]);

  // ── load ────────────────────────────────────────────────────────────────
  useEffect(() => {
    if (isNew) {
      const init: Block[] = [{ id: uid(), text: "", flags: [] }];
      setBlocks(init);
      baseline.current = sigOf(init, "", "none", 1, "", "");
      // A leftover autosave for a never-saved compose means the last attempt to
      // create it didn't land — offer it back rather than starting blank.
      if (!isSnippet) {
        const d = readDraft("new");
        if (draftIsUnsaved(d, null)) setPendingDraft(d);
      }
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
          if (!row) { setError(tr("ui.contentEditorPage.snippetNotFound")); finishLoad(); return; }
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
      const d = readDraft(id!);
      setPendingDraft(draftIsUnsaved(d, hit.updated_at) ? d : null);
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
        const d = readDraft(id!);
        setPendingDraft(draftIsUnsaved(d, row.updated_at) ? d : null);
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
      setVoiceError((e as Error).message || tr("ui.contentEditorPage.voiceSaveFailed"));
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
    // Only the anchored "clear flag" pill is scroll-fragile; the pending flag
    // selection persists (its bar is fixed, not anchored to the selection), so
    // a stray scroll no longer throws away what you were about to flag.
    const clear = () => setClearPill(null);
    window.addEventListener("scroll", clear, true);
    return () => window.removeEventListener("scroll", clear, true);
  }, []);

  const composed = useMemo(() => composeText(blocks), [blocks]);
  const charCount = composed.length;
  // Text offered to "save as snippet": the block being edited, else the
  // selected block, else the whole composed content.
  const focusedBlockText =
    (editingBlock ? blocks.find((b) => b.id === editingBlock)?.text : undefined) ??
    (sel ? blocks.find((b) => b.id === sel.parts[0]?.blockId)?.text : undefined) ??
    composed;
  // The block the "Save the focused block" gesture targets — so saving a dynamic
  // block carries its full settings (dynamic/fallback/domains/maxFetches) into
  // the snippet doc, not just its text.
  const focusedBlock =
    (editingBlock ? blocks.find((b) => b.id === editingBlock) : undefined) ??
    (sel ? blocks.find((b) => b.id === sel.parts[0]?.blockId) : undefined) ??
    (blocks.length === 1 ? blocks[0] : undefined);
  // One row per flag — but a multi-block region (shared regionId) collapses to a
  // SINGLE row (the earliest part is the primary; regionText is the joined span,
  // regionParts lists every block range). Highlighting still uses each block's
  // own flags, so all parts stay coloured in the tweet.
  const allFlags = useMemo<FlagWithBlock[]>(() => {
    const raw = blocks.flatMap((b, bi) => b.flags.map((f) => ({ ...f, blockId: b.id, blockText: b.text, bi })));
    const regions = new Map<string, typeof raw>();
    const out: FlagWithBlock[] = [];
    for (const f of raw) {
      if (!f.regionId) { out.push(f); continue; }
      const arr = regions.get(f.regionId) ?? [];
      arr.push(f);
      regions.set(f.regionId, arr);
    }
    for (const arr of regions.values()) {
      arr.sort((a, b) => a.bi - b.bi || a.start - b.start);
      const primary = arr[0];
      out.push({
        ...primary,
        regionText: arr.map((p) => p.blockText.slice(p.start, p.end)).join("\n\n"),
        regionParts: arr.map((p) => ({ blockId: p.blockId, start: p.start, end: p.end })),
      });
    }
    return out.sort((a, b) => (a.bi ?? 0) - (b.bi ?? 0) || a.start - b.start);
  }, [blocks]);

  // Has the live document diverged from what we loaded? (Drives the swipe guard.)
  const dirty = useMemo(
    () => baseline.current !== null
      && (wanted !== null || sigOf(blocks, publishAt, freq, interval, ceaseAt, title) !== baseline.current),
    [blocks, publishAt, freq, interval, ceaseAt, title, wanted, sigOf],
  );

  // Mirror the working post to device-local storage as the author edits — but
  // only once it diverges from the loaded copy (`dirty`), so a fresh load never
  // clobbers a genuinely-unsaved draft before the restore banner can offer it.
  // Debounced; posts only; a confirmed save clears the draft (see persist()).
  useEffect(() => {
    if (isSnippet || loading || !dirty) return;
    const key = id ?? "new";
    const t = window.setTimeout(() => {
      writeDraft(key, { doc: serializeBlocks(blocks), title, publishAt, freq, interval, ceaseAt });
    }, 800);
    return () => window.clearTimeout(t);
  }, [isSnippet, loading, dirty, id, blocks, title, publishAt, freq, interval, ceaseAt]);
  const curIndex = useMemo(
    () => (isNew ? -1 : neighbors.findIndex((p) => p.post_id === id)),
    [neighbors, id, isNew],
  );

  // Step to a sibling post (dir −1 prev / +1 next), guarding unsaved edits.
  const goToNeighbor = useCallback((dir: number) => {
    if (isSnippet || curIndex < 0) return;
    const target = curIndex + dir;
    if (target < 0 || target >= neighbors.length) return;
    if (dirty && !window.confirm(tr("ui.contentEditorPage.discardAndMove"))) return;
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
  // Reads the live selection and maps its DOM Range onto the block(s) it covers
  // (each block <p> carries data-block-id). A Range is always document-ordered,
  // so its start block is the earlier one. Single-block → one part; a selection
  // that crosses boundaries → one part per spanned block (start block's tail,
  // whole middle blocks, end block's head). Called on mouse/touch-up from any
  // block, so it works no matter where the drag ends.
  const onBlockMouseUp = useCallback((_blockId: string, _el: HTMLElement | null) => {
    const s = window.getSelection();
    if (!s || s.isCollapsed || !s.rangeCount) { return; } // keep any pending selection; only a new valid one replaces it
    const range = s.getRangeAt(0);
    const blockOf = (node: Node): HTMLElement | null =>
      ((node.nodeType === 3 ? node.parentElement : (node as HTMLElement)) ?? null)?.closest<HTMLElement>("[data-block-id]") ?? null;
    const startEl = blockOf(range.startContainer);
    const endEl = blockOf(range.endContainer);
    if (!startEl || !endEl) { return; } // keep any pending selection; only a new valid one replaces it
    const els = Array.from(document.querySelectorAll<HTMLElement>("[data-block-id]"));
    const iStart = els.indexOf(startEl);
    const iEnd = els.indexOf(endEl);
    if (iStart < 0 || iEnd < 0) { return; } // keep any pending selection; only a new valid one replaces it
    const parts: SelPart[] = [];
    if (iStart === iEnd) {
      let a = charOffset(startEl, range.startContainer, range.startOffset);
      let b = charOffset(startEl, range.endContainer, range.endOffset);
      if (a > b) [a, b] = [b, a];
      parts.push({ blockId: startEl.dataset.blockId!, start: a, end: b });
    } else {
      parts.push({ blockId: startEl.dataset.blockId!, start: charOffset(startEl, range.startContainer, range.startOffset), end: (startEl.textContent ?? "").length });
      for (let i = iStart + 1; i < iEnd; i++) {
        parts.push({ blockId: els[i].dataset.blockId!, start: 0, end: (els[i].textContent ?? "").length });
      }
      parts.push({ blockId: endEl.dataset.blockId!, start: 0, end: charOffset(endEl, range.endContainer, range.endOffset) });
    }
    const clean = parts.filter((p) => p.end - p.start >= 1);
    if (!clean.length) { return; } // keep any pending selection; only a new valid one replaces it
    setClearPill(null);
    setSel({ parts: clean });
  }, []);

  function flagSelection() {
    if (!sel) return;
    // Pre-generate the flag ids so the setBlocks updater is pure (safe under
    // StrictMode double-invoke). Skip parts that overlap an existing flag.
    // A selection crossing block boundaries becomes ONE region (shared
    // regionId) so it refines as a single LLM context, not per-block.
    const regionId = sel.parts.length > 1 ? uid() : undefined;
    const parts = sel.parts.map((p) => ({ ...p, flagId: uid() }));
    let anyOverlap = false, firstMade: ActiveFlag | null = null;
    setBlocks((prev) => {
      let total = prev.reduce((n, b) => n + b.flags.length, 0);
      return prev.map((b) => {
        const part = parts.find((p) => p.blockId === b.id);
        if (!part) return b;
        if (b.flags.some((f) => overlaps(f, { start: part.start, end: part.end }))) { anyOverlap = true; return b; }
        firstMade ??= { blockId: b.id, flagId: part.flagId };
        const flag: FlagT = { id: part.flagId, start: part.start, end: part.end, note: "", suggestions: [], loading: false, error: "", colorIdx: total++, ...(regionId ? { regionId } : {}) };
        return { ...b, flags: [...b.flags, flag] };
      });
    });
    if (firstMade) { setActiveFlag(firstMade); setTab("flags"); }
    if (anyOverlap) setHint(firstMade ? t("ui.contentEditorPage.flagSkippedOverlap") : t("ui.contentEditorPage.flagOverlaps"));
    window.getSelection()?.removeAllRanges();
    setSel(null);
  }

  /// Flag the WHOLE block for AI review (the toolbar Flag button) — same as
  /// selecting all its text. No selection needed, so it works on touch.
  function flagBlock(blockId: string) {
    setBlocks((prev) => {
      const total = prev.reduce((n, b) => n + b.flags.length, 0);
      return prev.map((b) => {
        if (b.id !== blockId) return b;
        const end = b.text.length;
        if (end === 0) { setHint(t("ui.contentEditorPage.flagEmptyBlock")); return b; }
        const candidate = { start: 0, end };
        if (b.flags.some((f) => overlaps(f, candidate))) {
          setHint(t("ui.contentEditorPage.flagOverlapsClear"));
          return b;
        }
        const flag: FlagT = { id: uid(), start: 0, end, note: "", suggestions: [], loading: false, error: "", colorIdx: total };
        setActiveFlag({ blockId: b.id, flagId: flag.id });
        setTab("flags");
        return { ...b, flags: [...b.flags, flag] };
      });
    });
  }

  function removeFlag(_blockId: string, flagId: string) {
    setBlocks((prev) => {
      // Clearing any part of a region clears the whole region.
      const rid = prev.flatMap((b) => b.flags).find((f) => f.id === flagId)?.regionId;
      return prev.map((b) => ({
        ...b,
        flags: b.flags.filter((f) => (rid ? f.regionId !== rid : f.id !== flagId)),
      }));
    });
    setActiveFlag((a) => (a && a.flagId === flagId ? null : a));
    setClearPill((p) => (p && p.flagId === flagId ? null : p));
  }

  function updateFlag(blockId: string, flagId: string, patch: Partial<FlagT>) {
    setBlocks((prev) => prev.map((b) =>
      b.id === blockId ? { ...b, flags: b.flags.map((f) => (f.id === flagId ? { ...f, ...patch } : f)) } : b));
  }

  // ── refine (server-side: MCP calls the model with the operator's vaulted key) ──
  async function refine(blockId: string, flag: FlagT) {
    // The region is ONE context: for a multi-block flag, join every part (in
    // block order) with the paragraph break the reader sees; otherwise this
    // block's slice. Either way the model gets the whole post as `fullText` —
    // blocks are an editing convenience, the reader sees the composed post.
    const bi = new Map(blocks.map((b, i) => [b.id, i] as const));
    const parts = flag.regionId
      ? blocks
          .flatMap((b) => b.flags.filter((f) => f.regionId === flag.regionId).map((f) => ({ block: b, start: f.start, end: f.end })))
          .sort((a, c) => (bi.get(a.block.id)! - bi.get(c.block.id)!) || (a.start - c.start))
      : (() => { const b = blocks.find((x) => x.id === blockId); return b ? [{ block: b, start: flag.start, end: flag.end }] : []; })();
    if (!parts.length) return;
    const region = parts.map((p) => p.block.text.slice(p.start, p.end)).join("\n\n");
    const activeBans = bans.filter((b) => b.on).map((b) => b.text);
    updateFlag(blockId, flag.id, { loading: true, error: "", suggestions: [] });
    try {
      const r = await refinePostRegion({
        region,
        fullText: composed,
        instruction: flag.note,
        voice,
        bans: activeBans,
      });
      if (!r.success) {
        updateFlag(blockId, flag.id, {
          loading: false,
          error: r.message || r.error || t("ui.contentEditorPage.refineUnavailable"),
        });
        return;
      }
      // Dedup identical suggestions (the model sometimes repeats), keep order.
      const suggestions = [...new Set((r.suggestions ?? []).map((s) => s.trim()).filter(Boolean))];
      if (!suggestions.length) throw new Error(t("ui.contentEditorPage.noSuggestions"));
      updateFlag(blockId, flag.id, { loading: false, suggestions });
    } catch (e) {
      updateFlag(blockId, flag.id, { loading: false, error: (e as Error).message });
    }
  }

  function applySuggestion(blockId: string, flag: FlagT, text: string) {
    if (!flag.regionId) {
      // Single block: replace the flagged slice in place, shift later flags.
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
      setHint(t("ui.contentEditorPage.regionUpdated"));
      return;
    }
    // Multi-block region: the revision replaces the WHOLE span as one piece.
    // Collapse the spanned blocks into one — start block's head + revision + end
    // block's tail — dropping the middle blocks (blocks are editing units; the
    // reader sees one revised passage). Region flags drop; flags entirely before
    // or after the span survive with adjusted offsets.
    const rid = flag.regionId;
    setBlocks((prev) => {
      const idx = prev
        .flatMap((b, i) => b.flags.filter((f) => f.regionId === rid).map((f) => ({ i, start: f.start, end: f.end })))
        .sort((a, c) => a.i - c.i || a.start - c.start);
      if (!idx.length) return prev;
      const first = idx[0], last = idx[idx.length - 1];
      const startBlock = prev[first.i], endBlock = prev[last.i];
      const head = startBlock.text.slice(0, first.start);
      const tail = endBlock.text.slice(last.end);
      const tailDelta = (head.length + text.length) - last.end;
      const keepStart = startBlock.flags.filter((f) => f.regionId !== rid && f.end <= first.start);
      const keepEnd = endBlock.flags
        .filter((f) => f.regionId !== rid && f.start >= last.end)
        .map((f) => ({ ...f, start: f.start + tailDelta, end: f.end + tailDelta }));
      const merged = { ...startBlock, text: head + text + tail, flags: [...keepStart, ...keepEnd] };
      return [...prev.slice(0, first.i), merged, ...prev.slice(last.i + 1)];
    });
    setActiveFlag((a) => (a && a.flagId === flag.id ? null : a));
    setHint(t("ui.contentEditorPage.regionUpdatedAcross"));
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
      ? t("ui.contentEditorPage.snippetAddedDynamic")
      : t("ui.contentEditorPage.snippetAdded"));
  };

  // Flip a block between static text and a dynamic prompt, in place. Turning it
  // dynamic clears any flags (a prompt isn't flaggable copy) and drops `nostr`
  // (the two kinds are mutually exclusive). Turning it static drops the
  // dynamic/fallback fields. Either way, clear its cached resolution.
  const toggleBlockDynamic = useCallback((blockId: string) => {
    let nowDynamic = false;
    setBlocks((prev) => prev.map((b) => {
      if (b.id !== blockId) return b;
      if (b.dynamic) return { id: b.id, text: b.text, flags: [] };
      nowDynamic = true;
      // dynamic ⇄ nostr are exclusive: promote by dropping nostr + dynamic extras.
      const { nostr: _n, fallback: _f, domains: _d, maxFetches: _m, runtimeLimit: _r, ...rest } = b;
      return { ...rest, dynamic: true, flags: [] };
    }));
    setResolved((r) => { const { [blockId]: _drop, ...rest } = r; return rest; });
    setHint(nowDynamic
      ? tr("ui.contentEditorPage.nowDynamic")
      : tr("ui.contentEditorPage.backToStatic"));
  }, []);

  // Flip a block between static text and a Nostr companion note. Turning it on
  // clears flags and drops `dynamic` (mutually exclusive); turning it off drops
  // the `nostr` flag. Nostr copy never enters the tweet.
  const toggleBlockNostr = useCallback((blockId: string) => {
    let nowNostr = false;
    setBlocks((prev) => prev.map((b) => {
      if (b.id !== blockId) return b;
      if (b.nostr) return { id: b.id, text: b.text, flags: [] };
      nowNostr = true;
      // Prefer static nostr shape — drop dynamic fields if any.
      return { id: b.id, text: b.text, flags: [], nostr: true };
    }));
    setResolved((r) => { const { [blockId]: _drop, ...rest } = r; return rest; });
    setHint(nowNostr
      ? tr("ui.contentEditorPage.nowNostr", { token: TWEET_URL_TOKEN })
      : tr("ui.contentEditorPage.backToStatic"));
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
          error: res.message || res.error || tr("ui.contentEditorPage.resolveFailed"),
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
    setHint(t("ui.contentEditorPage.dividerAdded"));
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

  // Apply an autosaved draft the load offered back. The loaded server copy stays
  // as the dirty baseline, so the restored work reads as clearly unsaved.
  const restoreDraft = useCallback((d: LocalDraft) => {
    setBlocks(parsePostDoc(d.doc));
    setTitle(d.title ?? "");
    setPublishAt(d.publishAt ?? "");
    setFreq((d.freq as Freq) ?? "none");
    setIntervalN(d.interval && d.interval > 0 ? d.interval : 1);
    setCeaseAt(d.ceaseAt ?? "");
    setPendingDraft(null);
    setHint(tr("ui.contentEditorPage.draftRestored"));
  }, []);

  const discardDraft = useCallback(() => {
    clearDraft(id ?? "new");
    setPendingDraft(null);
  }, [id]);

  // ── persistence ───────────────────────────────────────────────────────────
  // Flip the badge. Ready with no publish time takes the next sweep slot, so
  // the author sees WHEN before saving; Draft keeps its time so the flip back
  // costs nothing. Nothing persists until Save.
  function flipReadiness(next: Flip) {
    if (next === "scheduled" && !publishAt) {
      setPublishAt(isoToDatetimeLocalValue(nextSweepSlot().toISOString(), timeZone));
    }
    setWanted(next);
  }
  // What the badge shows: the flip the author made, else the stored status.
  const shownStatus = wanted ?? loadedStatus;
  // The post is in (or heading into) the queue, so its timing must travel.
  const inQueue = shownStatus === "scheduled" || shownStatus === "resolving" || shownStatus === "resolved";

  async function persist() {
    if (!composed.trim()) { setError(t("ui.contentEditorPage.writeFirst")); return; }
    if (inQueue && !publishAt) { setError(t("ui.contentEditorPage.setPublishTime")); setTab("schedule"); return; }
    setSaving(true);
    setError(null);
    const docPayload = serializeBlocks(blocks);
    // #367 — datetime-local wall values are in the patron zone; convert to UTC ISO.
    const publishIso = publishAt ? datetimeLocalValueToIso(publishAt, timeZone) ?? undefined : undefined;
    const recurrence: Recurrence | undefined =
      freq !== "none" ? { freq, interval: Math.max(1, Number(interval) || 1) } : undefined;
    const ceaseIso = ceaseAt
      ? datetimeLocalValueToIso(ceaseAt, timeZone) ?? undefined
      : undefined;
    // A schedule time already in the past won't miss — it fires on the next
    // scheduler tick. Say so, so the post isn't perceived as "not scheduled".
    const pastTime = inQueue && !!publishIso && new Date(publishIso).getTime() < Date.now();
    const savedHint = inQueue
      ? (pastTime ? t("ui.contentEditorPage.savedReadyPast") : t("ui.contentEditorPage.savedReady"))
      : t("ui.contentEditorPage.savedHint");
    try {
      if (isNew) {
        const status: Flip = wanted ?? "draft";
        const r = await createPost({
          doc: docPayload, textCache: composed, status,
          publishAt: publishIso, recurrence, ceaseAt: ceaseIso, clientReqId: createReqId.current,
          title: title.trim() || undefined,
        });
        // Treat a soft failure / unconfirmed response as failure: surface it and
        // KEEP the author's work (still autosaved, still dirty) — never navigate
        // away on an unconfirmed create.
        const fail = saveError(r);
        if (fail) { setError(fail); return; }
        clearDraft("new");
        if (r.post_id) nav(`/post/${r.post_id}`, { replace: true });
      } else {
        // Always send title (even blank) so clearing it persists as NULL. Status
        // travels only when the badge was flipped; timing always does, so an
        // edited publish time on a Ready post lands without touching its state.
        const patch: Record<string, unknown> = { doc: docPayload, title: title.trim() };
        if (wanted) patch.status = wanted;
        if (publishIso) patch.publish_at = publishIso;
        if (recurrence) patch.recurrence = recurrence;
        if (ceaseIso) patch.cease_at = ceaseIso;
        const r = await updatePost({ postId: id!, patch, textCache: composed, clientReqId: uid() });
        const fail = saveError(r);
        // On a blocked/unconfirmed save, DON'T clear the dirty baseline or the
        // cache — the edit stays put, swipe-guarded and retryable, never lost.
        if (fail) { setError(fail); return; }
        setHint(savedHint);
        if (wanted) setLoadedStatus(wanted);
        setWanted(null);
        baseline.current = sigOf(blocks, publishAt, freq, interval, ceaseAt, title);
        clearDraft(id!);
        postCache.current.delete(id!); // saved content differs from any cached row
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  // Save the document as a named snippet (snippet kind's primary action).
  async function persistSnippet() {
    if (!name.trim()) { setError(t("ui.contentEditorPage.nameSnippetFirst")); return; }
    if (!composed.trim()) { setError(t("ui.contentEditorPage.writeFirst")); return; }
    setSaving(true);
    setError(null);
    try {
      const row = await saveSnippet({
        id: isNew ? undefined : id,
        name: name.trim(),
        text: composed,
        doc: serializeBlocks(blocks),
      });
      if (!row) { setError(t("ui.contentEditorPage.snippetSaveFailed")); return; }
      if (isNew) nav(`/snippet/${row.id}`, { replace: true });
      else setHint(t("ui.contentEditorPage.savedHint"));
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
    if (!composed.trim()) { setError(t("ui.contentEditorPage.writeFirst")); return; }
    const docPayload = serializeBlocks(blocks);
    if (isSnippet) {
      const newName = window.prompt(t("ui.contentEditorPage.saveAsSnippetPrompt"), t("ui.contentEditorPage.copyName", { name: name.trim() || t("ui.contentEditorPage.defaultSnippetName") }));
      if (newName === null) return; // cancelled
      if (!newName.trim()) { setError(t("ui.contentEditorPage.nameSnippetCopy")); return; }
      setSaving(true);
      setError(null);
      try {
        const row = await saveSnippet({ name: newName.trim(), text: composed, doc: docPayload });
        if (!row) { setError(t("ui.contentEditorPage.copySaveFailed")); return; }
        nav(`/snippet/${row.id}`);
      } catch (e) {
        setError((e as Error).message);
      } finally {
        setSaving(false);
      }
    } else {
      const newTitle = window.prompt(t("ui.contentEditorPage.saveAsPostPrompt"), t("ui.contentEditorPage.copyName", { name: title.trim() || t("ui.contentEditorPage.untitled") }));
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
      if (!window.confirm(t("ui.contentEditorPage.deleteSnippetConfirm"))) return;
      try { await removeSnippet(id!); nav(listPath); } catch (e) { setError((e as Error).message); }
      return;
    }
    if (isNew) { nav(listPath); return; }
    if (!window.confirm(archivePrompt(loadedStatus))) return;
    try { await deletePost(id!, false, "Archived from the post editor"); nav(listPath); } catch (e) { setError((e as Error).message); }
  }

  // Compose the text to actually post: static blocks verbatim, each dynamic block
  // resolved now (reusing a current Preview result, else a fresh paid run). A
  // dynamic block that fails with no fallback aborts the post — never a gap.
  // Nostr blocks are skipped entirely — they never enter the tweet body.
  async function buildFinalText(): Promise<{ text: string; error?: string }> {
    const tweetBlocks = blocks.filter((b) => !b.nostr);
    if (!hasDynamic(tweetBlocks)) return { text: composed };
    const activeBans = bans.filter((b) => b.on).map((b) => b.text);
    // Context for each dynamic block: static siblings + OTHER dynamics as their
    // fallback (we resolve in parallel, so none sees another's resolved value).
    // Nostr siblings are excluded so they don't leak into the prompt context.
    const contextFor = (i: number) =>
      tweetBlocks
        .map((x, j) => (j === i ? "⟨HERE⟩" : x.dynamic ? (x.fallback ?? "") : x.text))
        .filter(Boolean)
        .join("\n\n");

    // Resolve every dynamic block concurrently (reusing a current Preview result).
    const rendered = await Promise.all(tweetBlocks.map(async (b, i): Promise<string | null> => {
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
      return { text: "", error: t("ui.contentEditorPage.dynamicNoFallback") };
    }
    return { text: rendered.filter(Boolean).join("\n\n").trim() };
  }

  // Post to X now (paid), then save the post as sent so it lands in the list.
  async function handlePostNow() {
    debugPush("info", `Post It clicked (${composed.trim().length} chars)`);
    if (!composed.trim()) { setError(t("ui.contentEditorPage.writeFirst")); return; }
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
          const why = saved.error_code || saved.error || saved.message || t("ui.contentEditorPage.unknownError");
          debugPush("error", `schedule-for-resolve failed: ${why}`);
          setError(t("ui.contentEditorPage.scheduleFailed", { why }));
          return;
        }
        debugPush("info", `Deferred to scheduler (budget ${maxBudget}s) — due ~now+10s`);
        setHint(t("ui.contentEditorPage.deferredHint"));
        setLoadedStatus("scheduled");
        setWanted(null);
        baseline.current = sigOf(blocks, publishAt, freq, interval, ceaseAt, title);
        clearDraft(id ?? "new");
        if (isNew && saved.post_id) nav(`/post/${saved.post_id}`, { replace: true });
        return;
      }

      const { text: finalText, error: buildErr } = await buildFinalText();
      if (buildErr) { setError(buildErr); return; }
      if (!finalText.trim()) { setError(t("ui.contentEditorPage.nothingAfterResolve")); return; }
      const r = await postTweet(finalText);
      if (r.error || r.success === false) {
        if (r.error_code && OAUTH_NEEDED_CODES.has(r.error_code)) {
          debugPush("info", `post_tweet needs X connect (${r.error_code})`);
          setNeedsXConnect(true);
          setError(t("ui.contentEditorPage.connectXFirst"));
        } else {
          setError(r.message || r.error || t("ui.contentEditorPage.postFailed"));
        }
        return;
      }
      const tweetUrl = r.tweet_url ?? "";
      // Companion Nostr notes fire only after the tweet succeeds AND we have a URL.
      // A relay miss is a soft hint — it never flips the "Posted" state. Save the
      // post row with the authored doc: {{tweet_url}} stays unsubstituted, same
      // way a dynamic block keeps its prompt while text_cache holds the resolved text.
      let nostrHint = "";
      if (tweetUrl) {
        const nostrBlocks = blocks.filter((b) => b.nostr && b.text.trim());
        for (const nb of nostrBlocks) {
          try {
            const note = await postNostrMessage(withTweetUrl(nb.text, tweetUrl));
            if (note.error || note.success === false) {
              const why = note.message || note.error || note.error_code || t("ui.contentEditorPage.relayRejected");
              debugPush("error", `post_nostr_message failed: ${why}`);
              nostrHint = nostrHint || t("ui.contentEditorPage.nostrDidntLand", { why });
            } else {
              debugPush("info", `post_nostr_message ok → ${note.event_id || note.note_id || "ok"}`);
            }
          } catch (e) {
            const why = (e as Error).message;
            debugPush("error", `post_nostr_message threw: ${why}`);
            nostrHint = nostrHint || t("ui.contentEditorPage.nostrDidntLand", { why });
          }
        }
      }
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
        const why = saved.error_code || saved.error || saved.message || t("ui.contentEditorPage.unknownError");
        debugPush("error", `${isNew ? "create_post" : "update_post"} after send failed: ${why}`);
        setError(t("ui.contentEditorPage.recordSentFailed", { why }));
        return;
      }
      setHint(nostrHint || t("ui.contentEditorPage.postedToX"));
      setLoadedStatus("sent");
      baseline.current = sigOf(blocks, publishAt, freq, interval, ceaseAt, title);
      clearDraft(id ?? "new");
      if (id) postCache.current.delete(id); // sent status differs from any cached row
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return (
      // Always dark: `dark` here turns on the dark: utilities inside, whatever the site theme.
      <div className="dark min-h-screen bg-zinc-950 flex items-center justify-center">
        <QuoteScroller quotes={QUOTES} spinner heading={isSnippet ? t("ui.contentEditorPage.openingSnippet") : t("ui.contentEditorPage.openingEditor")} classNames={quoteStyles} />
      </div>
    );
  }

  const openFlagCount = allFlags.length;
  const handle = xProfile?.username
    ? `@${xProfile.username}`
    : npub ? `@${npub.slice(4, 13)}…` : "@excalibur";
  const displayName = xProfile?.name || "eXcalibur";
  const cardAvatar = xProfile?.profile_image_url || avatarFor(npub);
  const flagsTab = openFlagCount ? t("ui.contentEditorPage.tabFlagsCount", { n: openFlagCount }) : t("ui.contentEditorPage.tabFlags");
  const railTabs = isSnippet
    ? ([["flags", flagsTab], ["voice", t("ui.contentEditorPage.tabVoice")], ["snippets", t("ui.contentEditorPage.tabSnippets")]] as const)
    : ([["flags", flagsTab], ["voice", t("ui.contentEditorPage.tabVoice")], ["snippets", t("ui.contentEditorPage.tabSnippets")], ["schedule", t("ui.contentEditorPage.tabSchedule")]] as const);

  return (
    <div className="min-h-screen w-full bg-zinc-950 text-zinc-200 flex flex-col">
      {/* Soft-swap progress strip — shown while stepping to a sibling post so the
          in-place content change reads as motion, not a frozen pause. */}
      {stepping && (
        <div className="fixed inset-x-0 top-0 z-60 h-0.5 overflow-hidden bg-amber-400/15">
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
      {sel && !preview && (() => {
        // A STABLE, dismissible bar pinned to the bottom of the viewport — not a
        // fleeting chiclet at the selection. The captured selection persists, so
        // you can scroll, miss a tap, or take your time and still flag it.
        const previewText = sel.parts
          .map((p) => blocks.find((b) => b.id === p.blockId)?.text.slice(p.start, p.end) ?? "")
          .join(" … ")
          .replace(/\s+/g, " ")
          .trim();
        const shown = previewText.length > 60 ? previewText.slice(0, 57) + "…" : previewText;
        return (
          <div
            style={{ position: "fixed", left: "50%", bottom: "max(1rem, env(safe-area-inset-bottom))", transform: "translateX(-50%)", zIndex: 50 }}
            className="flex max-w-[92vw] items-center gap-1 rounded-full bg-amber-400 py-1.5 pl-4 pr-1.5 shadow-2xl ring-1 ring-amber-300"
          >
            <button onClick={flagSelection} className="flex min-w-0 items-center gap-2 text-sm font-semibold text-zinc-950">
              <Flag className="h-4 w-4 flex-none" />
              <span className="flex-none">{sel.parts.length > 1 ? t("ui.contentEditorPage.flagBlocks", { count: sel.parts.length }) : t("ui.contentEditorPage.flagSelection")}</span>
              {shown && <span className="min-w-0 truncate font-normal text-zinc-800/80">{t("ui.contentEditorPage.selectionQuote", { text: shown })}</span>}
            </button>
            <button
              onClick={() => setSel(null)}
              title={t("ui.contentEditorPage.cancelFlag")}
              className="flex h-7 w-7 flex-none items-center justify-center rounded-full text-zinc-800 hover:bg-amber-300"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        );
      })()}
      {clearPill && !preview && (
        <button
          onClick={() => removeFlag(clearPill.blockId, clearPill.flagId)}
          style={{ position: "fixed", left: clearPill.x, top: clearPill.y - 44, transform: "translateX(-50%)", zIndex: 50 }}
          className="flex items-center gap-1.5 rounded-full bg-zinc-900 px-3 py-1.5 text-sm font-medium text-white shadow-xl ring-1 ring-zinc-700 hover:bg-zinc-800 transition-colors"
        >
          <Trash2 className="h-3.5 w-3.5" /> {t("ui.contentEditorPage.clearFlag")}
        </button>
      )}

      {/* top bar */}
      <header className="flex items-center justify-between gap-4 border-b border-zinc-800 px-5 py-3">
        <div className="flex items-center gap-3">
          <button onClick={() => nav(listPath)} className="flex h-8 w-8 items-center justify-center rounded-md bg-amber-400 text-zinc-950" title={isSnippet ? t("ui.contentEditorPage.backToSnippets") : t("ui.contentEditorPage.backToPosts")}>
            <Swords className="h-5 w-5" />
          </button>
          <div className="leading-tight">
            <div className="font-serif text-lg text-zinc-50">
              {isSnippet ? t("ui.contentEditorPage.headerSnippet") : t("ui.contentEditorPage.headerPosts")}
            </div>
            <div className="font-mono text-[11px] uppercase tracking-widest text-zinc-500">
              {isSnippet ? t("ui.contentEditorPage.subSnippet") : t("ui.contentEditorPage.subPosts")}
            </div>
          </div>
          {!isSnippet && curIndex >= 0 && neighbors.length > 1 && (
            <div className="ml-1 flex items-center gap-1 font-mono text-[11px] text-zinc-500">
              <button
                onClick={() => goToNeighbor(-1)}
                disabled={curIndex <= 0}
                title={t("ui.contentEditorPage.prevPost")}
                className="rounded-sm px-1.5 py-0.5 text-base leading-none hover:text-amber-300 disabled:opacity-30"
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
                title={t("ui.contentEditorPage.nextPost")}
                className="rounded-sm px-1.5 py-0.5 text-base leading-none hover:text-amber-300 disabled:opacity-30"
              >
                ›
              </button>
            </div>
          )}
        </div>
        <div className="flex items-center gap-3">
          <div className="font-mono text-sm tabular-nums text-zinc-400">
            {charCount.toLocaleString(locale)}<span className="ml-1 text-zinc-600">{t("ui.contentEditorPage.chars")}</span>
          </div>
          {isSnippet ? (
            <button
              onClick={() => void persistSnippet()}
              disabled={saving}
              className="flex items-center gap-1.5 rounded-md bg-amber-400 px-3 py-1.5 text-sm font-medium text-zinc-950 hover:bg-amber-300 disabled:opacity-40 transition-colors"
            >
              <Save className="h-4 w-4" /> {saving ? t("ui.contentEditorPage.saving") : t("ui.contentEditorPage.saveSnippet")}
            </button>
          ) : (
            <>
              <ReadinessBadge status={shownStatus} onFlip={flipReadiness} busy={saving} />
              <button
                onClick={() => void persist()}
                disabled={saving}
                title={t("ui.contentEditorPage.saveTitle")}
                className="flex items-center gap-1.5 rounded-md border border-zinc-700 px-3 py-1.5 text-sm text-zinc-300 hover:border-zinc-500 hover:text-zinc-100 disabled:opacity-40 transition-colors"
              >
                <Save className="h-4 w-4" /> {saving ? t("ui.contentEditorPage.saving") : t("ui.contentEditorPage.save")}
              </button>
              <button
                onClick={() => void handlePostNow()}
                disabled={saving}
                title={t("ui.contentEditorPage.postNowTitle")}
                className="flex items-center gap-1.5 rounded-md bg-amber-400 px-3 py-1.5 text-sm font-medium text-zinc-950 hover:bg-amber-300 disabled:opacity-40 transition-colors"
              >
                <Share className="h-4 w-4" /> {t("ui.contentEditorPage.postNow")}
              </button>
            </>
          )}
          <button
            onClick={() => void saveAsCopy()}
            disabled={saving}
            title={isSnippet ? t("ui.contentEditorPage.saveAsTitleSnippet") : t("ui.contentEditorPage.saveAsTitlePost")}
            className="flex items-center gap-1.5 rounded-md border border-zinc-700 px-3 py-1.5 text-sm text-zinc-300 hover:border-zinc-500 hover:text-zinc-100 disabled:opacity-40 transition-colors"
          >
            <CopyPlus className="h-4 w-4" /> {t("ui.contentEditorPage.saveAs")}
          </button>
          <button
            onClick={() => { setPreview((p) => !p); setSel(null); setClearPill(null); }}
            className="flex items-center gap-1.5 rounded-md border border-zinc-700 px-3 py-1.5 text-sm text-zinc-300 hover:border-zinc-500 hover:text-zinc-100 transition-colors"
          >
            {preview ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            {preview ? t("ui.contentEditorPage.edit") : t("ui.contentEditorPage.preview")}
          </button>
        </div>
      </header>

      {/* Unsaved-edits banner: a device-local autosave newer than the server copy
          means a save never landed — offer the work back instead of losing it. */}
      {pendingDraft && !isSnippet && (
        <div className="flex flex-wrap items-center gap-3 border-b border-amber-500/30 bg-amber-500/10 px-5 py-2.5 text-sm text-amber-200">
          <span className="min-w-0 flex-1">
            {t("ui.contentEditorPage.unsavedBanner", {
              when: pendingDraft.savedAt
                ? new Date(pendingDraft.savedAt).toLocaleString(locale, { timeZone })
                : t("ui.contentEditorPage.earlier"),
            })}
          </span>
          <button
            onClick={() => restoreDraft(pendingDraft)}
            className="rounded-md bg-amber-400 px-3 py-1 text-xs font-medium text-zinc-950 hover:bg-amber-300"
          >
            {t("ui.contentEditorPage.restore")}
          </button>
          <button
            onClick={discardDraft}
            className="rounded-md border border-amber-500/40 px-3 py-1 text-xs text-amber-200 hover:border-amber-400"
          >
            {t("ui.contentEditorPage.discard")}
          </button>
        </div>
      )}

      {/* Posted-to-X banner: a Sent post always shows its actual X link; clicking
          peeks at the tweet in a modal (no jumping out of the site). */}
      {!isSnippet && tweetUrl && (
        <div className="flex items-center gap-2 border-b border-zinc-800 bg-green-500/10 px-5 py-2 text-sm">
          <Check className="h-4 w-4 shrink-0 text-green-400" />
          <span className="text-green-400">{t("ui.contentEditorPage.postedToXLabel")}</span>
          <button
            onClick={() => setPeekUrl(tweetUrl)}
            className="inline-flex items-center gap-1 truncate font-mono text-xs text-sky-400 hover:text-sky-300 hover:underline"
            title={t("ui.contentEditorPage.peekAt", { url: tweetUrl })}
          >
            {tweetUrl} <Eye className="h-3.5 w-3.5 shrink-0" />
          </button>
        </div>
      )}

      {/* A published snapshot points back to its editable recurring template —
          editing THIS frozen record won't change future postings. */}
      {!isSnippet && templateId && (
        <div className="flex flex-wrap items-center gap-2 border-b border-zinc-800 bg-violet-500/10 px-5 py-2 text-sm text-violet-300">
          <span>{t("ui.contentEditorPage.publishedRecord")}</span>
          <button
            onClick={() => nav(`/post/${templateId}`)}
            className="ml-auto rounded-sm bg-violet-400 px-2.5 py-1 font-medium text-zinc-950 hover:bg-violet-300"
          >
            {t("ui.contentEditorPage.editTemplate")}
          </button>
        </div>
      )}

      {/* A live recurring template links to its published postings history. */}
      {!isSnippet && !isNew && !templateId && freq !== "none" && (
        <div className="flex flex-wrap items-center gap-2 border-b border-zinc-800 bg-zinc-900/60 px-5 py-2 text-sm text-zinc-400">
          <span>{t("ui.contentEditorPage.recurringFresh")}</span>
          <button
            onClick={() => nav(`/?template=${id}`)}
            className="ml-auto rounded-sm bg-zinc-700 px-2.5 py-1 font-medium text-zinc-100 hover:bg-zinc-600"
          >
            {t("ui.contentEditorPage.viewPostings")}
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
          <div className="pointer-events-none absolute inset-x-0 top-0 h-64 bg-linear-to-b from-amber-400 to-transparent opacity-5" />
          <div className="relative w-full max-w-xl">
            {isSnippet && !preview && (
              <div className="mb-3">
                <label className="mb-1.5 block font-mono text-[11px] uppercase tracking-widest text-zinc-500">{t("ui.contentEditorPage.snippetName")}</label>
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder={t("ui.contentEditorPage.snippetNamePlaceholder")}
                  className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-600 outline-hidden focus:border-amber-400"
                />
              </div>
            )}
            {!isSnippet && !preview && (
              <div className="mb-3">
                <label className="mb-1.5 block font-mono text-[11px] uppercase tracking-widest text-zinc-500"><Tx ns={WORDS} k="ui.contentEditorPage.titleLabel" components={{ muted: <span className="text-zinc-600" /> }} /></label>
                <input
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  maxLength={200}
                  placeholder={t("ui.contentEditorPage.titlePlaceholder")}
                  className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-600 outline-hidden focus:border-amber-400"
                />
              </div>
            )}
            <div className="mb-3 flex items-center justify-between">
              <span className="font-mono text-[11px] uppercase tracking-widest text-zinc-500">
                {preview ? t("ui.contentEditorPage.asOnX") : t("ui.contentEditorPage.editingStage")}
              </span>
              {!preview && (
                <span className="font-mono text-[11px] text-zinc-600">
                  {t("ui.contentEditorPage.flagsReorder", { count: openFlagCount })}
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
                    <span className="truncate text-zinc-500">{handle} · {t("ui.contentEditorPage.now")}</span>
                  </div>
                  <div className="mt-1 space-y-3">
                    {/* Tweet body: nostr blocks never appear inside the X card. */}
                    {(preview ? blocks.filter((b) => !b.nostr) : blocks).map((b, idx) => (
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
                        onToggleNostr={() => toggleBlockNostr(b.id)}
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
                        onEdit={() => { setEditingBlock(b.id); setSel(null); }}
                        onDoneEdit={() => setEditingBlock(null)}
                        onChange={(t) => setBlockText(b.id, t)}
                        onFlagBlock={() => flagBlock(b.id)}
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

            {/* Preview-only: companion Nostr notes render in a separate panel below
                the X card. {{tweet_url}} shows as a placeholder pill. Never hits a relay. */}
            {preview && blocks.some((b) => b.nostr) && (
              <div className="mt-4 space-y-2">
                <div className="font-mono text-[11px] uppercase tracking-widest text-sky-400/80">{t("ui.contentEditorPage.companionNotes")}</div>
                {blocks.filter((b) => b.nostr).map((b) => (
                  <div key={b.id} className="rounded-xl border border-sky-500/40 bg-sky-950/40 p-3 text-sm text-sky-100">
                    <div className="mb-1.5 flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-widest text-sky-400">
                      <Share className="h-3 w-3" /> {t("ui.contentEditorPage.nostrNote")}
                    </div>
                    <p className="whitespace-pre-wrap wrap-break-word leading-normal">
                      {b.text
                        ? b.text.split(TWEET_URL_TOKEN).map((part, i, arr) => (
                            <span key={i}>
                              {part}
                              {i < arr.length - 1 && (
                                <span className="mx-0.5 inline-flex items-center rounded-full bg-sky-400/20 px-1.5 py-0.5 font-mono text-[11px] text-sky-300 ring-1 ring-sky-400/40">
                                  {TWEET_URL_TOKEN}
                                </span>
                              )}
                            </span>
                          ))
                        : <span className="italic text-sky-400/60">{t("ui.contentEditorPage.emptyNote")}</span>}
                    </p>
                  </div>
                ))}
              </div>
            )}

            {!preview && (
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <button onClick={addBlock} className="flex items-center gap-1.5 rounded-md border border-dashed border-zinc-700 px-3 py-1.5 text-sm text-zinc-400 hover:border-amber-400 hover:text-amber-300 transition-colors">
                  <Plus className="h-4 w-4" /> {t("ui.contentEditorPage.addTextBlock")}
                </button>
                <button
                  onClick={insertDivider}
                  title={t("ui.contentEditorPage.dividerTitle")}
                  className="flex items-center gap-1.5 rounded-md border border-dashed border-zinc-700 px-3 py-1.5 text-sm text-zinc-400 hover:border-amber-400 hover:text-amber-300 transition-colors"
                >
                  <Minus className="h-4 w-4" /> {t("ui.contentEditorPage.divider")}
                </button>
                {snippets.filter((s) => s.favorite).map((s) => (
                  <button
                    key={s.id}
                    onClick={() => insertSnippetRow(s)}
                    title={snippetIsDynamic(s) ? t("ui.contentEditorPage.insertSnippetDynamic", { name: s.name }) : t("ui.contentEditorPage.insertSnippet", { name: s.name })}
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
                {isNew ? t("ui.contentEditorPage.discard") : t("ui.contentEditorPage.deleteSnippet")}
              </button>
            )}
            {hint && <div className="mt-3 font-mono text-xs text-amber-300">{hint}</div>}
            {error && (
              <div className="mt-3 flex flex-wrap items-center gap-3 rounded-md border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-300">
                <span>{error}</span>
                {needsXConnect && (
                  <button
                    onClick={() => nav("/profile")}
                    className="ml-auto rounded-sm bg-amber-400 px-2.5 py-1 font-medium text-zinc-950 hover:bg-amber-300"
                  >
                    {t("ui.contentEditorPage.connectX")}
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
                  timeZone={timeZone}
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
  onToggleDynamic, onToggleNostr, onChangeFallback, onChangeDomains, onChangeMaxFetches, onChangeRuntimeLimit,
  onMouseUp, onFlagClick, onEdit, onDoneEdit, onChange, onFlagBlock, onDelete, onMoveUp, onMoveDown, canDelete, dragHandlers,
}: {
  block: Block; idx: number; preview: boolean; editing: boolean; activeFlagId: string | null; overIndex: number | null;
  resolved?: ResolvedState; onResolve: () => void;
  onToggleDynamic: () => void; onToggleNostr: () => void; onChangeFallback: (t: string) => void;
  onChangeDomains: (t: string) => void; onChangeMaxFetches: (n: number) => void;
  onChangeRuntimeLimit: (n: number) => void;
  onMouseUp: (blockId: string, el: HTMLElement | null) => void;
  onFlagClick: (flagId: string, rect: DOMRect) => void;
  onEdit: () => void; onDoneEdit: () => void; onChange: (t: string) => void; onFlagBlock: () => void; onDelete: () => void;
  onMoveUp: () => void; onMoveDown: () => void; canDelete: boolean;
  dragHandlers: HTMLAttributes<HTMLDivElement>;
}) {
  const ref = useRef<HTMLParagraphElement>(null);
  const editRef = useRef<HTMLTextAreaElement>(null);
  const [showEmoji, setShowEmoji] = useState(false);
  const t = useT();
  // The time-budget ceiling is the SERVER's, fetched once and shared. Hardcoding it
  // here is what made the editor quietly refuse budgets the operator had already
  // raised — the input said 900 because this file said 900.
  const [budgetMax, setBudgetMax] = useState<number | null>(null);
  useEffect(() => {
    let live = true;
    getResolveBudgets().then((b) => { if (live) setBudgetMax(b?.block_max_seconds ?? null); });
    return () => { live = false; };
  }, []);
  const segs = useMemo(() => segmentize(block.text, block.flags), [block.text, block.flags]);

  if (preview) {
    // Nostr blocks are filtered out of the X card by the parent and render in a
    // separate companion panel — they never appear inside the tweet preview.
    // A dynamic block shows its resolved (dry-run) text. While it resolves we show
    // a spinner WITH the author's time budget, so the wait isn't a mystery. If it
    // FAILS we still show the fallback text — but now with a visible reason, so a
    // silent fallback never masquerades as a successful resolve. The live post
    // resolves fresh at fire time.
    if (block.dynamic) {
      if (resolved?.loading) {
        return (
          <p className="flex items-center gap-1.5 text-[15px] italic leading-normal text-zinc-400">
            <Loader2 className="h-3.5 w-3.5 animate-spin" /> {t("ui.contentEditorPage.resolvingUpTo", { s: block.runtimeLimit ?? 210 })}
          </p>
        );
      }
      const failed = !!resolved?.error;
      const shown = resolved?.text || block.fallback || "";
      return (
        <>
          {shown ? (
            <p className="whitespace-pre-wrap wrap-break-word text-[15px] leading-normal text-zinc-900">{shown}</p>
          ) : !failed ? (
            <p className="text-[15px] italic leading-normal text-zinc-400">{t("ui.contentEditorPage.noPreviewYet")}</p>
          ) : null}
          {failed && (
            <p className="mt-1 flex items-start gap-1.5 text-[12px] leading-snug text-amber-600" title={resolved!.error}>
              <span aria-hidden className="mt-px flex-none">⚠</span>
              <span>
                {shown ? t("ui.contentEditorPage.showingFallback", { error: resolved!.error }) : t("ui.contentEditorPage.didntResolve", { error: resolved!.error })}
              </span>
            </p>
          )}
        </>
      );
    }
    return <p className="whitespace-pre-wrap wrap-break-word text-[15px] leading-normal text-zinc-900">{block.text}</p>;
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
              <Wand2 className="h-3 w-3" /> {t("ui.contentEditorPage.dynamicHeader")}
            </span>
            <button
              onClick={onToggleDynamic}
              title={t("ui.contentEditorPage.makeStaticNormalTitle")}
              className="font-mono text-[10px] uppercase tracking-widest text-violet-400 hover:text-violet-700"
            >
              {t("ui.contentEditorPage.makeStaticLower")}
            </button>
          </div>
          <textarea
            value={block.text}
            onChange={(e) => onChange(e.target.value)}
            placeholder={t("ui.contentEditorPage.promptPlaceholder")}
            rows={Math.max(2, Math.ceil(block.text.length / 42))}
            className="w-full resize-none rounded-sm border border-violet-300 bg-white p-2 text-[13px] leading-snug text-violet-900 placeholder:text-violet-300 outline-hidden focus:border-violet-500"
          />
          <input
            value={block.fallback ?? ""}
            onChange={(e) => onChangeFallback(e.target.value)}
            placeholder={t("ui.contentEditorPage.fallbackPlaceholder")}
            className="mt-1.5 w-full rounded-sm border border-violet-200 bg-white px-2 py-1 text-[12px] text-violet-800 placeholder:text-violet-300 outline-hidden focus:border-violet-400"
          />
          <div className="mt-1.5 flex items-center gap-1.5">
            <input
              value={block.domains ?? ""}
              onChange={(e) => onChangeDomains(e.target.value)}
              placeholder={t("ui.contentEditorPage.domainsPlaceholder")}
              className="min-w-0 flex-1 rounded-sm border border-violet-200 bg-white px-2 py-1 text-[12px] text-violet-800 placeholder:text-violet-300 outline-hidden focus:border-violet-400"
            />
            <input
              type="number"
              min={1}
              max={25}
              value={block.maxFetches ?? 5}
              onChange={(e) => onChangeMaxFetches(Number(e.target.value) || 0)}
              title={t("ui.contentEditorPage.maxFetchesTitle")}
              className="w-16 flex-none rounded-sm border border-violet-200 bg-white px-2 py-1 text-[12px] text-violet-800 outline-hidden focus:border-violet-400"
            />
            <input
              type="number"
              min={60}
              {...(budgetMax ? { max: budgetMax } : {})}
              step={30}
              value={block.runtimeLimit ?? 210}
              onChange={(e) => onChangeRuntimeLimit(Number(e.target.value) || 0)}
              title={t("ui.contentEditorPage.budgetTitle", { range: `60${budgetMax ? `–${budgetMax}` : ""}` })}
              className="w-16 flex-none rounded-sm border border-violet-200 bg-white px-2 py-1 text-[12px] text-violet-800 outline-hidden focus:border-violet-400"
            />
            <span className="flex-none text-[10px] text-violet-400">{t("ui.contentEditorPage.sec")}</span>
          </div>
          <div className="mt-1.5 flex flex-wrap items-center gap-2">
            <button
              onClick={onResolve}
              disabled={resolved?.loading || !block.text.trim()}
              className="flex items-center gap-1 rounded-md bg-violet-500 px-3 py-2 text-[12px] font-medium text-white hover:bg-violet-400 disabled:opacity-40"
            >
              {resolved?.loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
              {resolved?.loading ? t("ui.contentEditorPage.running") : t("ui.contentEditorPage.run")}
            </button>
            <span className="font-mono text-[10px] text-violet-400">{t("ui.contentEditorPage.previewHere")}</span>
            <span className="flex-1" />
            <button onClick={onToggleDynamic} title={t("ui.contentEditorPage.makeStaticPlainTitle")} className="flex items-center gap-1.5 rounded-md px-2.5 py-2 text-[13px] font-medium text-violet-500 hover:bg-violet-100 transition-colors"><Wand2 className="h-4 w-4" /> {t("ui.contentEditorPage.makeStatic")}</button>
            {canDelete && <button onClick={onDelete} title={t("ui.contentEditorPage.deleteBlock")} className="flex items-center gap-1.5 rounded-md px-2.5 py-2 text-[13px] font-medium text-zinc-500 hover:bg-rose-50 hover:text-rose-600 transition-colors"><Trash2 className="h-4 w-4" /> {t("ui.contentEditorPage.delete")}</button>}
          </div>
          {result && (
            <p className="mt-1.5 rounded-sm bg-white p-1.5 text-[13px] leading-snug text-zinc-900 ring-1 ring-emerald-200">
              {result}
            </p>
          )}
          {resolved?.error && <p className="mt-1.5 text-[11px] text-rose-500">{resolved.error}</p>}
        </div>
      </div>
    );
  }
  // A Nostr block is a self-contained card — static formatted copy that never
  // enters the tweet. After the tweet lands, its text publishes as a companion
  // Nostr note with {{tweet_url}} substituted. One-click insert for the token;
  // no flags / refine (same as dynamic).
  if (block.nostr) {
    const insertTweetUrl = () => {
      const ta = document.getElementById(`nostr-ta-${block.id}`) as HTMLTextAreaElement | null;
      const pos = ta ? ta.selectionStart : block.text.length;
      onChange(block.text.slice(0, pos) + TWEET_URL_TOKEN + block.text.slice(pos));
      requestAnimationFrame(() => {
        if (ta) {
          ta.focus();
          ta.selectionStart = ta.selectionEnd = pos + TWEET_URL_TOKEN.length;
        }
      });
    };
    return (
      <div className={`group relative -ml-7 rounded-md pl-7 ${overIndex === idx ? "ring-1 ring-amber-300" : ""}`} draggable {...dragHandlers}>
        <div className="absolute left-0 top-0 flex flex-col items-center opacity-0 transition-opacity group-hover:opacity-100">
          <GripVertical className="h-4 w-4 cursor-grab text-zinc-300" />
          <button onClick={onMoveUp} className="text-zinc-300 hover:text-amber-500"><ChevronUp className="h-3.5 w-3.5" /></button>
          <button onClick={onMoveDown} className="text-zinc-300 hover:text-amber-500"><ChevronDown className="h-3.5 w-3.5" /></button>
        </div>
        <div className="rounded-md border border-dashed border-sky-400 bg-sky-50 p-2">
          <div className="mb-1.5 flex items-center justify-between gap-2">
            <span className="flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-widest text-sky-700">
              <Share className="h-3 w-3" /> {t("ui.contentEditorPage.nostrHeader")}
            </span>
            <button
              onClick={onToggleNostr}
              title={t("ui.contentEditorPage.makeStaticNormalTitle")}
              className="font-mono text-[10px] uppercase tracking-widest text-sky-400 hover:text-sky-700"
            >
              {t("ui.contentEditorPage.makeStaticLower")}
            </button>
          </div>
          <textarea
            id={`nostr-ta-${block.id}`}
            value={block.text}
            onChange={(e) => onChange(e.target.value)}
            placeholder={t("ui.contentEditorPage.nostrPlaceholder", { token: TWEET_URL_TOKEN })}
            rows={Math.max(2, Math.ceil(block.text.length / 42))}
            className="w-full resize-none rounded-sm border border-sky-300 bg-white p-2 text-[13px] leading-snug text-sky-900 placeholder:text-sky-300 outline-hidden focus:border-sky-500"
          />
          <div className="mt-1.5 flex flex-wrap items-center gap-2">
            <button
              onClick={insertTweetUrl}
              title={t("ui.contentEditorPage.insertTokenTitle", { token: TWEET_URL_TOKEN })}
              className="rounded-md bg-sky-500 px-3 py-2 font-mono text-[11px] font-medium text-white hover:bg-sky-400"
            >
              {TWEET_URL_TOKEN}
            </button>
            <span className="font-mono text-[10px] text-sky-500">{t("ui.contentEditorPage.neverEnters")}</span>
            <span className="flex-1" />
            <button onClick={onToggleNostr} title={t("ui.contentEditorPage.makeStaticPlainTitle")} className="flex items-center gap-1.5 rounded-md px-2.5 py-2 text-[13px] font-medium text-sky-600 hover:bg-sky-100 transition-colors"><Share className="h-4 w-4" /> {t("ui.contentEditorPage.makeStatic")}</button>
            {canDelete && <button onClick={onDelete} title={t("ui.contentEditorPage.deleteBlock")} className="flex items-center gap-1.5 rounded-md px-2.5 py-2 text-[13px] font-medium text-zinc-500 hover:bg-rose-50 hover:text-rose-600 transition-colors"><Trash2 className="h-4 w-4" /> {t("ui.contentEditorPage.delete")}</button>}
          </div>
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
        className="rounded-sm px-1.5 py-0.5 text-zinc-700 hover:bg-amber-200"
      >
        {label}
      </button>
    );
    return (
      <div className="rounded-md ring-1 ring-amber-400">
        <div className="relative flex items-center gap-1 rounded-t-md bg-amber-100 px-2 py-1">
          {fmtBtn(<Bold className="h-3.5 w-3.5" />, "bold", t("ui.contentEditorPage.bold"))}
          {fmtBtn(<Italic className="h-3.5 w-3.5" />, "italic", t("ui.contentEditorPage.italic"))}
          {fmtBtn(<Code className="h-3.5 w-3.5" />, "mono", t("ui.contentEditorPage.mono"))}
          <button
            onMouseDown={(ev) => ev.preventDefault()}
            onClick={() => setShowEmoji((v) => !v)}
            title={t("ui.contentEditorPage.insertEmoji")}
            className="rounded-sm px-1.5 py-0.5 text-zinc-700 hover:bg-amber-200"
          >
            <Smile className="h-3.5 w-3.5" />
          </button>
          <span className="ml-2 text-[10px] text-amber-700">{t("ui.contentEditorPage.styleHint")}</span>
          {showEmoji && (
            <div className="absolute left-0 top-full z-30 mt-1 max-h-72 w-80 overflow-y-auto rounded-md border border-zinc-300 bg-white p-2 shadow-xl">
              {EMOJI_GROUPS.map((group) => (
                <div key={group.label}>
                  <div className="sticky top-0 bg-white px-1 py-0.5 text-[10px] font-mono uppercase tracking-widest text-zinc-400">
                    {t(group.label)}
                  </div>
                  <div className="grid grid-cols-10 gap-0.5">
                    {group.emojis.map((em, i) => (
                      <button
                        key={`${group.label}-${i}`}
                        onMouseDown={(ev) => ev.preventDefault()}
                        onClick={() => { insertAtCursor(em); setShowEmoji(false); }}
                        className="rounded-sm p-1 text-lg hover:bg-amber-100"
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
          className="w-full resize-none bg-amber-50 p-2 text-[15px] leading-normal text-zinc-900 outline-hidden"
        />
        <div className="flex items-center justify-between rounded-b-md bg-amber-100 px-2 py-1">
          <span className="font-mono text-[10px] text-amber-700">
            {block.dynamic ? t("ui.contentEditorPage.dynamicEditing") : t("ui.contentEditorPage.editingClears")}
          </span>
          <button onClick={onDoneEdit} className="rounded-sm bg-zinc-900 px-2 py-0.5 text-xs text-white hover:bg-zinc-700">{t("ui.contentEditorPage.done")}</button>
        </div>
      </div>
    );
  }
  // Touch-sized toolbar buttons — a labelled action and an icon-only variant.
  const tBtn = "flex items-center gap-1.5 rounded-md px-2.5 py-2 text-[13px] font-medium text-zinc-500 hover:bg-zinc-100 active:bg-zinc-200 transition-colors";
  const tIcon = "flex items-center justify-center rounded-md p-2 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-700 transition-colors";
  return (
    <div className={`group relative flex flex-col gap-1 rounded-md ${overIndex === idx ? "ring-1 ring-amber-300" : ""}`} draggable {...dragHandlers}>
      <p
        ref={ref}
        data-block-id={block.id}
        onMouseUp={() => onMouseUp(block.id, ref.current)}
        onTouchEnd={() => onMouseUp(block.id, ref.current)}
        className="cursor-text select-text whitespace-pre-wrap wrap-break-word text-[15px] leading-normal text-zinc-900"
      >
        {segs.map((s, i) => {
          if (!s.flag) return <span key={i}>{s.text}</span>;
          const c = paletteOf(s.flag.colorIdx || 0);
          const isActive = s.flag.id === activeFlagId;
          return (
            <mark key={i} onClick={(e) => onFlagClick(s.flag!.id, e.currentTarget.getBoundingClientRect())}
              className={`cursor-pointer rounded-sm px-0.5 ${isActive ? c.active + " ring-1 ring-zinc-900" : c.mark}`}>
              {s.text}
            </mark>
          );
        })}
      </p>
      {/* Always-visible action bar BELOW the text — never covers it; touch-sized targets. */}
      <div className="flex flex-wrap items-center gap-0.5 border-t border-zinc-100 pt-1">
        <button onClick={onEdit} title={t("ui.contentEditorPage.editText")} className={tBtn}><Pencil className="h-4 w-4" /> {t("ui.contentEditorPage.edit")}</button>
        <button onClick={onToggleDynamic} title={t("ui.contentEditorPage.makeDynamicTitle")} className={`${tBtn} hover:text-violet-600`}><Wand2 className="h-4 w-4" /> {t("ui.contentEditorPage.dynamic")}</button>
        <button onClick={onToggleNostr} title={t("ui.contentEditorPage.makeNostrTitle")} className={`${tBtn} hover:text-sky-600`}><Share className="h-4 w-4" /> {t("ui.contentEditorPage.nostr")}</button>
        <button onClick={onFlagBlock} title={t("ui.contentEditorPage.flagBlockTitle")} className={`${tBtn} hover:text-amber-600`}><Flag className="h-4 w-4" /> {t("ui.contentEditorPage.flag")}</button>
        {canDelete && <button onClick={onDelete} title={t("ui.contentEditorPage.deleteBlock")} className={`${tBtn} hover:text-rose-600`}><Trash2 className="h-4 w-4" /> {t("ui.contentEditorPage.delete")}</button>}
        <span className="flex-1" />
        <button onClick={onMoveUp} title={t("ui.contentEditorPage.moveUp")} className={tIcon}><ChevronUp className="h-5 w-5" /></button>
        <button onClick={onMoveDown} title={t("ui.contentEditorPage.moveDown")} className={tIcon}><ChevronDown className="h-5 w-5" /></button>
        <span className="cursor-grab p-2 text-zinc-300" title={t("ui.contentEditorPage.dragReorder")}><GripVertical className="h-4 w-4" /></span>
      </div>
    </div>
  );
}

type FlagWithBlock = FlagT & {
  blockId: string;
  blockText: string;
  bi?: number;
  // Present on a multi-block region's primary row: the joined selected text and
  // every block range the region covers.
  regionText?: string;
  regionParts?: { blockId: string; start: number; end: number }[];
};

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
  const t = useT();
  if (!allFlags.length) {
    return (
      <div className="rounded-lg border border-dashed border-zinc-800 p-6 text-center">
        <Flag className="mx-auto mb-2 h-5 w-5 text-zinc-600" />
        <p className="text-sm text-zinc-400"><Tx ns={WORDS} k="ui.contentEditorPage.flagsEmpty" components={{ hl: <span className="text-amber-300" /> }} /></p>
        <p className="mt-2 font-mono text-[11px] text-zinc-600">{t("ui.contentEditorPage.swipeSelect")}</p>
      </div>
    );
  }
  return (
    <div className="space-y-3">
      {allFlags.map((f) => {
        const isActive = active?.flagId === f.id;
        const region = f.regionText ?? f.blockText.slice(f.start, f.end);
        const spanCount = f.regionParts?.length ?? 1;
        const c = paletteOf(f.colorIdx || 0);
        return (
          <div key={f.id} className={`rounded-lg border p-3 transition-colors ${isActive ? "border-amber-400 bg-zinc-900" : "border-zinc-800 bg-zinc-900"}`} onClick={() => setActive({ blockId: f.blockId, flagId: f.id })}>
            <div className="mb-2 flex items-start justify-between gap-2">
              <div className="flex min-w-0 flex-col items-start gap-1">
                <div className="flex min-w-0 items-start gap-2">
                  <span className={`mt-1 h-2.5 w-2.5 flex-none rounded-full ${c.dot}`} />
                  <p className={`whitespace-pre-wrap rounded-sm ${c.mark} px-1.5 py-0.5 text-[13px] text-zinc-900`}>"{region}"</p>
                </div>
                {spanCount > 1 && (
                  <span className="ml-4 font-mono text-[10px] uppercase tracking-wider text-zinc-500">{t("ui.contentEditorPage.spansBlocks", { count: spanCount })}</span>
                )}
              </div>
              <button onClick={(e) => { e.stopPropagation(); onRemove(f.blockId, f.id); }} title={t("ui.contentEditorPage.clearFlag")} className="flex flex-none items-center gap-1 rounded-sm text-zinc-500 hover:text-rose-400"><Trash2 className="h-4 w-4" /></button>
            </div>
            <textarea
              value={f.note} onChange={(e) => onNote(f.blockId, f.id, e.target.value)} onClick={(e) => e.stopPropagation()}
              placeholder={t("ui.contentEditorPage.notePlaceholder")} rows={2}
              className="w-full resize-none rounded-md border border-zinc-700 bg-zinc-950 p-2 text-sm text-zinc-200 placeholder:text-zinc-600 outline-hidden focus:border-amber-400"
            />
            <button onClick={(e) => { e.stopPropagation(); onRefine(f.blockId, f); }} disabled={f.loading}
              className="mt-2 flex w-full items-center justify-center gap-1.5 rounded-md bg-amber-400 px-3 py-1.5 text-sm font-medium text-zinc-950 hover:bg-amber-300 disabled:opacity-60 transition-colors">
              {f.loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Wand2 className="h-4 w-4" />}
              {f.loading ? t("ui.contentEditorPage.refining") : t("ui.contentEditorPage.refine")}
            </button>
            {f.error && <p className="mt-2 text-xs text-rose-400">{f.error}</p>}
            {f.suggestions.length > 0 && (
              <div className="mt-3 space-y-2">
                <div className="flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-widest text-zinc-500"><Sparkles className="h-3 w-3" /> {t("ui.contentEditorPage.suggestions")}</div>
                {f.suggestions.map((s, i) => (
                  <div key={i} className="rounded-md border border-zinc-700 bg-zinc-950 p-2">
                    <p className="text-sm text-zinc-200">{s}</p>
                    <button onClick={(e) => { e.stopPropagation(); onApply(f.blockId, f, s); }} className="mt-1.5 flex items-center gap-1 text-xs text-amber-300 hover:text-amber-200"><Check className="h-3.5 w-3.5" /> {t("ui.contentEditorPage.useThis")}</button>
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
  const t = useT();

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
        <div className="text-xs uppercase tracking-widest text-zinc-500 mb-1">{t("ui.contentEditorPage.saveFocused")}</div>
        <div className="flex gap-2">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={t("ui.contentEditorPage.snippetPlaceholder")}
            className="flex-1 rounded-md border border-zinc-700 bg-zinc-950 px-2 py-1.5 text-sm text-zinc-200 placeholder:text-zinc-600 outline-hidden focus:border-amber-400"
          />
          <button
            onClick={save}
            disabled={busy || !name.trim() || !currentText.trim()}
            className="rounded-md bg-amber-400 px-3 py-1.5 text-sm font-medium text-zinc-950 hover:bg-amber-300 disabled:opacity-40 transition-colors"
          >
            {busy ? "…" : t("ui.contentEditorPage.save")}
          </button>
        </div>
        <p className="mt-1 text-[11px] text-zinc-500 line-clamp-2">
          {currentText.trim()
            ? t("ui.contentEditorPage.savesPreview", { text: `${currentText.trim().slice(0, 80)}${currentText.trim().length > 80 ? "…" : ""}` })
            : t("ui.contentEditorPage.clickBlockFirst")}
        </p>
      </div>

      <div>
        <div className="text-xs uppercase tracking-widest text-zinc-500 mb-2">{t("ui.contentEditorPage.library")}</div>
        {snippets.length === 0 ? (
          <p className="text-xs text-zinc-500">
            {t("ui.contentEditorPage.noSnippets")}
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
                    title={s.favorite ? t("ui.contentEditorPage.unfavorite") : t("ui.contentEditorPage.favoriteTitle")}
                    className={s.favorite ? "text-amber-400" : "text-zinc-600 hover:text-amber-400"}
                  >
                    <Star className={`h-3.5 w-3.5 ${s.favorite ? "fill-current" : ""}`} />
                  </button>
                  <button
                    onClick={async () => setSnippets(await toggleDynamic(s, !dyn))}
                    title={dyn ? t("ui.contentEditorPage.dynamicSnippetTitle") : t("ui.contentEditorPage.makeDynamicSnippetTitle")}
                    className={`flex-none ${dyn ? "text-violet-400" : "text-zinc-600 hover:text-violet-400"}`}
                  >
                    <Wand2 className="h-3.5 w-3.5" />
                  </button>
                  <span className="flex-1 min-w-0 truncate text-sm text-zinc-200">{s.name}</span>
                  <button onClick={() => onInsert(s)} className="text-xs text-amber-300 hover:text-amber-200" title={dyn ? t("ui.contentEditorPage.addAsDynamic") : t("ui.contentEditorPage.addAsBlock")}>
                    {t("ui.contentEditorPage.insert")}
                  </button>
                  <button onClick={async () => setSnippets(await removeSnippet(s.id))} className="text-zinc-500 hover:text-rose-400" title={t("ui.contentEditorPage.deleteSnippet")}>
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
  const t = useT();

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
        <label className="mb-1.5 block font-mono text-[11px] uppercase tracking-widest text-zinc-500">{t("ui.contentEditorPage.voiceProfile")}</label>
        <textarea value={voice} onChange={(e) => setVoice(e.target.value)} rows={5} disabled={!loaded}
          className="w-full resize-none rounded-md border border-zinc-700 bg-zinc-900 p-2 text-sm text-zinc-200 outline-hidden focus:border-amber-400 disabled:opacity-50"
          placeholder={t("ui.contentEditorPage.voicePlaceholder")} />
        <p className="mt-1.5 text-xs text-zinc-500">{t("ui.contentEditorPage.voiceHelp")}</p>
      </div>
      <div>
        <label className="mb-2 block font-mono text-[11px] uppercase tracking-widest text-zinc-500">{t("ui.contentEditorPage.bannedConstructions")}</label>
        <div className="flex flex-wrap gap-2">
          {bans.map((b, i) => (
            editing === i ? (
              <span key={i} className="flex items-center gap-1 rounded-full border border-amber-400 bg-zinc-900 pl-2.5 pr-1 py-0.5">
                <input autoFocus value={draft} onChange={(e) => setDraft(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") commitEdit(); if (e.key === "Escape") { setEditing(null); setDraft(""); } }}
                  className="w-32 bg-transparent text-xs text-zinc-100 outline-hidden" />
                <button onClick={commitEdit} title={t("ui.contentEditorPage.saveChip")} className="rounded-full p-0.5 text-amber-300 hover:text-amber-200">
                  <Check className="h-3 w-3" />
                </button>
              </span>
            ) : (
              <span key={i}
                className={`flex items-center gap-1 rounded-full border pl-2.5 pr-1 py-1 text-xs transition-colors ${b.on ? "border-amber-400 bg-amber-400 text-zinc-950" : "border-zinc-700 text-zinc-500 line-through"}`}>
                <button onClick={() => toggle(i)} title={t("ui.contentEditorPage.toggleConstraint")} className="max-w-48 truncate">{b.text}</button>
                <button onClick={() => startEdit(i)} title={t("ui.contentEditorPage.edit")} className={`rounded-full p-0.5 ${b.on ? "hover:bg-amber-500/40" : "hover:bg-zinc-700"}`}>
                  <Pencil className="h-2.5 w-2.5" />
                </button>
                <button onClick={() => remove(i)} title={t("ui.contentEditorPage.remove")} className={`rounded-full p-0.5 ${b.on ? "hover:bg-amber-500/40" : "hover:bg-zinc-700"}`}>
                  <Minus className="h-2.5 w-2.5" />
                </button>
              </span>
            )
          ))}
        </div>
        <div className="mt-2 flex items-center gap-1.5">
          <input value={adding} onChange={(e) => setAdding(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") addBan(); }}
            placeholder={t("ui.contentEditorPage.addBanPlaceholder")}
            className="flex-1 rounded-md border border-zinc-700 bg-zinc-900 px-2 py-1 text-xs text-zinc-200 outline-hidden focus:border-amber-400" />
          <button onClick={addBan} disabled={!adding.trim()} title={t("ui.contentEditorPage.add")}
            className="flex items-center gap-1 rounded-md border border-zinc-700 px-2 py-1 text-xs text-zinc-300 hover:border-amber-400 hover:text-amber-300 disabled:opacity-40">
            <Plus className="h-3 w-3" /> {t("ui.contentEditorPage.add")}
          </button>
        </div>
        <p className="mt-2 text-xs text-zinc-500">{t("ui.contentEditorPage.bansHelp")}</p>
      </div>
      <div className="flex items-center gap-3 border-t border-zinc-800 pt-3">
        <button onClick={onSave} disabled={!loaded || saving || !dirty}
          className="flex items-center gap-1.5 rounded-md bg-amber-400 px-3 py-1.5 text-sm font-medium text-zinc-950 hover:bg-amber-300 disabled:cursor-not-allowed disabled:opacity-40">
          {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />}
          {saving ? t("ui.contentEditorPage.saving") : t("ui.contentEditorPage.saveVoice")}
        </button>
        {error
          ? <span className="text-xs text-red-400">{error}</span>
          : saved && !dirty
            ? <span className="flex items-center gap-1 text-xs text-emerald-400"><Check className="h-3.5 w-3.5" /> {t("ui.contentEditorPage.savedBadge")}</span>
            : dirty
              ? <span className="text-xs text-zinc-500">{t("ui.contentEditorPage.unsavedChanges")}</span>
              : null}
      </div>
    </div>
  );
}

// ── schedule tab ────────────────────────────────────────────────────────────
function ScheduleTab({
  publishAt, setPublishAt, freq, setFreq, interval, setInterval, ceaseAt, setCeaseAt,
  timeZone,
  onDiscard, isNew,
}: {
  publishAt: string; setPublishAt: (v: string) => void;
  freq: Freq; setFreq: (v: Freq) => void;
  interval: number; setInterval: (v: number) => void;
  ceaseAt: string; setCeaseAt: (v: string) => void;
  timeZone: string;
  onDiscard: () => void; isNew: boolean;
}) {
  const t = useT();
  const field = "w-full rounded-md border border-zinc-700 bg-zinc-900 p-2 text-sm text-zinc-200 outline-hidden focus:border-amber-400";
  return (
    <div className="space-y-5">
      <div>
        <label className="mb-1.5 flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-widest text-zinc-500"><Calendar className="h-3.5 w-3.5" /> {t("ui.contentEditorPage.publishAt")}</label>
        <input type="datetime-local" value={publishAt} onChange={(e) => setPublishAt(e.target.value)} className={field} />
        <p className="mt-1.5 text-xs text-zinc-500">
          <Tx
            ns={WORDS}
            k="ui.contentEditorPage.scheduleHelp"
            components={{
              zone: <span className="text-zinc-300">{timeZone}</span>,
              ready: <span className="text-amber-400" />,
              postNow: <span className="text-amber-400" />,
            }}
          />
        </p>
      </div>
      <div>
        <label className="mb-1.5 flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-widest text-zinc-500"><Repeat className="h-3.5 w-3.5" /> {t("ui.contentEditorPage.republish")}</label>
        <div className="flex gap-2">
          <select value={freq} onChange={(e) => setFreq(e.target.value as Freq)} className={field}>
            <option value="none">{t("ui.contentEditorPage.freqNone")}</option>
            <option value="daily">{t("ui.contentEditorPage.freqDaily")}</option>
            <option value="weekdays">{t("ui.contentEditorPage.freqWeekdays")}</option>
            <option value="weekly">{t("ui.contentEditorPage.freqWeekly")}</option>
            <option value="monthly">{t("ui.contentEditorPage.freqMonthly")}</option>
          </select>
          {freq !== "none" && (
            <div className="flex flex-none items-center gap-1.5">
              <span className="text-xs text-zinc-500">{t("ui.contentEditorPage.every")}</span>
              <input type="number" min={1} value={interval} onChange={(e) => setInterval(Math.max(1, Number(e.target.value) || 1))}
                className="w-14 rounded-md border border-zinc-700 bg-zinc-900 p-2 text-center text-sm text-zinc-200 outline-hidden focus:border-amber-400" />
            </div>
          )}
        </div>
      </div>
      <div>
        <label className="mb-1.5 flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-widest text-zinc-500"><Octagon className="h-3.5 w-3.5" /> {t("ui.contentEditorPage.cease")}</label>
        <input type="datetime-local" value={ceaseAt} onChange={(e) => setCeaseAt(e.target.value)} disabled={freq === "none"} className={`${field} disabled:opacity-40`} />
      </div>

      <CalendarPreview publishAt={publishAt} freq={freq} interval={interval} ceaseAt={ceaseAt} />

      <button onClick={onDiscard} className="w-full text-center text-xs text-zinc-600 hover:text-rose-400 transition-colors">
        {isNew ? t("ui.contentEditorPage.discardDraft") : t("ui.contentEditorPage.archivePost")}
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

// Parse a datetime-local wall string's calendar day without browser-zone bias.
// The value is already in the patron zone; only Y-M-D matter for the month grid.
function wallYmd(value: string): { y: number; m: number; d: number } | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(value.trim());
  if (!m) return null;
  return { y: Number(m[1]), m: Number(m[2]) - 1, d: Number(m[3]) };
}

// A compact month calendar that marks a scheduled post's start, its recurrence
// occurrences, and the cease date — replaces the raw intent-JSON dump.
// Day stepping uses Date only as a civil calendar helper (local construction of
// Y/M/D), never as a UTC conversion of the scheduled instant.
function CalendarPreview({ publishAt, freq, interval, ceaseAt }: {
  publishAt: string; freq: Freq; interval: number; ceaseAt: string;
}) {
  const t = useT();
  const locale = useLanguageLocale();
  const startYmd = publishAt ? wallYmd(publishAt) : null;
  const valid = !!startYmd;
  const ceaseYmd = ceaseAt ? wallYmd(ceaseAt) : null;
  const ceaseValid = !!ceaseYmd;
  const start = valid
    ? new Date(startYmd!.y, startYmd!.m, startYmd!.d)
    : null;
  const cease = ceaseValid
    ? new Date(ceaseYmd!.y, ceaseYmd!.m, ceaseYmd!.d)
    : null;

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
    return <p className="text-xs text-zinc-500">{t("ui.contentEditorPage.setTimeToPreview")}</p>;
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
  const monthLabel = first.toLocaleString(locale, { month: "long", year: "numeric" });
  const prev = () => setView((v) => (v.m === 0 ? { y: v.y - 1, m: 11 } : { y: v.y, m: v.m - 1 }));
  const next = () => setView((v) => (v.m === 11 ? { y: v.y + 1, m: 0 } : { y: v.y, m: v.m + 1 }));

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-3">
      <div className="mb-2 flex items-center justify-between">
        <button onClick={prev} title={t("ui.contentEditorPage.prevMonth")} className="rounded-sm px-2 text-zinc-500 hover:text-amber-300">‹</button>
        <span className="font-mono text-[11px] uppercase tracking-widest text-zinc-400">{monthLabel}</span>
        <button onClick={next} title={t("ui.contentEditorPage.nextMonth")} className="rounded-sm px-2 text-zinc-500 hover:text-amber-300">›</button>
      </div>
      <div className="grid grid-cols-7 gap-0.5 text-center">
        {Array.from({ length: 7 }, (_, i) => new Date(2023, 0, 1 + i).toLocaleString(locale, { weekday: "narrow" })).map((d, i) => (
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
            <div key={i} className={`flex aspect-square items-center justify-center rounded-sm text-[11px] tabular-nums ${cls}`}>
              {day}
            </div>
          );
        })}
      </div>
      <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[10px] text-zinc-500">
        <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-xs bg-amber-400" /> {t("ui.contentEditorPage.legendStart")}</span>
        {freq !== "none" && <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-xs bg-amber-400/30" /> {t("ui.contentEditorPage.legendRepeats")}</span>}
        {ceaseKey && <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-xs ring-1 ring-rose-400" /> {t("ui.contentEditorPage.legendCease")}</span>}
      </div>
    </div>
  );
}

// toLocalInput removed — use isoToDatetimeLocalValue(iso, timeZone) (#367).
