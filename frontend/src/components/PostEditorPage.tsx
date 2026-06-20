import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Dispatch, HTMLAttributes, ReactNode, SetStateAction } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  MessageCircle, Repeat2, Heart, BarChart2, Bookmark, Share, BadgeCheck,
  Sparkles, Flag, GripVertical, Pencil, Trash2, Plus, Calendar, Repeat,
  Octagon, Copy, Check, ChevronUp, ChevronDown, Eye, EyeOff,
  Wand2, Loader2, Swords, Save, Bold, Italic, Code,
} from "lucide-react";
import { useSession } from "../App";
import Avatar from "./Avatar";
import { avatarFor } from "../lib/avatar";
import { styleText, type UnicodeStyle } from "../lib/unicodeFormat";
import { addSnippet, getSnippets, removeSnippet, type Snippet } from "../lib/snippets";
import {
  createPost, deletePost, getPost, postTweet, refinePostRegion, updatePost,
  type PostRow, type Recurrence,
} from "../lib/mcp";
import {
  charOffset, composeText, DEFAULT_BANS, DEFAULT_VOICE, overlaps, paletteOf,
  parsePostDoc, segmentize, serializeBlocks, uid,
  type Ban, type Block, type Flag as FlagT,
} from "../lib/editorDoc";

type Freq = "none" | "daily" | "weekly" | "monthly";
interface Sel { blockId: string; start: number; end: number; x: number; y: number }
interface ActiveFlag { blockId: string; flagId: string }
interface PillPos { blockId: string; flagId: string; x: number; y: number }

export default function PostEditorPage() {
  const { postId } = useParams();
  const isNew = !postId;
  const nav = useNavigate();
  const { npub } = useSession();
  const createReqId = useRef(uid());

  const [blocks, setBlocks] = useState<Block[]>([{ id: uid(), text: "", flags: [] }]);
  const [activeFlag, setActiveFlag] = useState<ActiveFlag | null>(null);
  const [preview, setPreview] = useState(false);
  const [tab, setTab] = useState<"flags" | "voice" | "schedule" | "snippets">("flags");
  const [editingBlock, setEditingBlock] = useState<string | null>(null);
  const [sel, setSel] = useState<Sel | null>(null);
  const [clearPill, setClearPill] = useState<PillPos | null>(null);
  const [hint, setHint] = useState("");

  const [voice, setVoice] = useState(() => localStorage.getItem("excalibur:voice") ?? DEFAULT_VOICE);
  const [bans, setBans] = useState<Ban[]>(() => {
    try {
      const r = localStorage.getItem("excalibur:bans");
      if (r) return JSON.parse(r) as Ban[];
    } catch { /* ignore */ }
    return DEFAULT_BANS.map((b) => ({ text: b, on: true }));
  });

  const [publishAt, setPublishAt] = useState("");
  const [freq, setFreq] = useState<Freq>("none");
  const [interval, setIntervalN] = useState(1);
  const [ceaseAt, setCeaseAt] = useState("");
  const [copied, setCopied] = useState(false);

  const [loading, setLoading] = useState(!isNew);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // ── load ────────────────────────────────────────────────────────────────
  useEffect(() => {
    if (isNew) {
      setBlocks([{ id: uid(), text: "", flags: [] }]);
      setLoading(false);
      return;
    }
    let live = true;
    setLoading(true);
    getPost(postId!)
      .then((row: PostRow) => {
        if (!live) return;
        if (row.error) { setError(row.error); setLoading(false); return; }
        setBlocks(parsePostDoc(row.doc, row.text_cache));
        if (row.publish_at) setPublishAt(toLocalInput(row.publish_at));
        const rec = row.recurrence as Recurrence | undefined;
        if (rec?.freq) { setFreq(rec.freq); setIntervalN(rec.interval || 1); }
        if (row.cease_at) setCeaseAt(toLocalInput(row.cease_at));
        setLoading(false);
      })
      .catch((e) => { if (live) { setError((e as Error).message); setLoading(false); } });
    return () => { live = false; };
  }, [postId, isNew]);

  useEffect(() => { localStorage.setItem("excalibur:voice", voice); }, [voice]);
  useEffect(() => { localStorage.setItem("excalibur:bans", JSON.stringify(bans)); }, [bans]);

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
  // selected block, else the whole composed post.
  const focusedBlockText =
    (editingBlock ? blocks.find((b) => b.id === editingBlock)?.text : undefined) ??
    (sel ? blocks.find((b) => b.id === sel.blockId)?.text : undefined) ??
    composed;
  const allFlags = useMemo(
    () => blocks.flatMap((b) => b.flags.map((f) => ({ ...f, blockId: b.id, blockText: b.text }))),
    [blocks],
  );

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
  const insertSnippet = (text: string) => {
    setBlocks((prev) => [...prev, { id: uid(), text, flags: [] }]);
    setHint("Snippet added as a block — drag it where you want.");
  };
  const deleteBlock = (blockId: string) =>
    setBlocks((prev) => (prev.length > 1 ? prev.filter((b) => b.id !== blockId) : prev));

  // ── persistence ───────────────────────────────────────────────────────────
  const intent = useMemo(() => ({
    intent: "scheduled_post",
    operator: "excalibur-mcp",
    text: composed,
    publish_at: publishAt ? new Date(publishAt).toISOString() : null,
    recurrence: freq === "none" ? null : { freq, interval: Number(interval) || 1 },
    cease_at: ceaseAt ? new Date(ceaseAt).toISOString() : null,
    voice_profile_present: voice.trim().length > 0,
    banned_constructions: bans.filter((b) => b.on).map((b) => b.text),
  }), [composed, publishAt, freq, interval, ceaseAt, voice, bans]);

  async function copyIntent() {
    try {
      await navigator.clipboard.writeText(JSON.stringify(intent, null, 2));
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch { setHint("Copy failed — select the JSON manually."); }
  }

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
        });
        if (r.error) setError(r.error);
        else if (r.post_id) nav(`/post/${r.post_id}`, { replace: true });
      } else {
        const patch: Record<string, unknown> = { doc: docPayload, status };
        if (publishIso) patch.publish_at = publishIso;
        if (recurrence) patch.recurrence = recurrence;
        if (ceaseIso) patch.cease_at = ceaseIso;
        const r = await updatePost({ postId: postId!, patch, textCache: composed, clientReqId: uid() });
        if (r.error) setError(r.error);
        else setHint(scheduled ? "Scheduled." : "Saved.");
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  async function handleDiscard() {
    if (isNew) { nav("/"); return; }
    if (!window.confirm("Archive this post?")) return;
    try { await deletePost(postId!, false); nav("/"); } catch (e) { setError((e as Error).message); }
  }

  // Post to X now (paid), then save the post as sent so it lands in the list.
  async function handlePostNow() {
    if (!composed.trim()) { setError("Write something first."); return; }
    setSaving(true);
    setError(null);
    try {
      const r = await postTweet(composed);
      if (r.error || r.success === false) {
        setError(r.message || r.error || "Couldn't post to X.");
        return;
      }
      const docPayload = serializeBlocks(blocks);
      if (isNew) {
        const c = await createPost({
          doc: docPayload, textCache: composed, status: "sent", clientReqId: createReqId.current,
        });
        if (c.post_id) { nav(`/post/${c.post_id}`, { replace: true }); return; }
        setHint("Posted to X (couldn't save a copy).");
      } else {
        await updatePost({
          postId: postId!, patch: { doc: docPayload, status: "sent" },
          textCache: composed, clientReqId: uid(),
        });
        setHint("Posted to X.");
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return <div className="min-h-screen bg-zinc-950 flex items-center justify-center text-zinc-400 text-sm">Loading…</div>;
  }

  const openFlagCount = allFlags.length;
  const handle = npub ? `@${npub.slice(4, 13)}…` : "@excalibur";

  return (
    <div className="min-h-screen w-full bg-zinc-950 text-zinc-200 flex flex-col">
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
          <button onClick={() => nav("/")} className="flex h-8 w-8 items-center justify-center rounded-md bg-amber-400 text-zinc-950" title="Back to posts">
            <Swords className="h-5 w-5" />
          </button>
          <div className="leading-tight">
            <div className="font-serif text-lg text-zinc-50">eXcalibur Editorial</div>
            <div className="font-mono text-[11px] uppercase tracking-widest text-zinc-500">draft → refine → schedule</div>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className="font-mono text-sm tabular-nums text-zinc-400">
            {charCount.toLocaleString()}<span className="ml-1 text-zinc-600">chars</span>
          </div>
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
          <button
            onClick={() => { setPreview((p) => !p); setSel(null); setClearPill(null); }}
            className="flex items-center gap-1.5 rounded-md border border-zinc-700 px-3 py-1.5 text-sm text-zinc-300 hover:border-zinc-500 hover:text-zinc-100 transition-colors"
          >
            {preview ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            {preview ? "Edit" : "Preview"}
          </button>
        </div>
      </header>

      <div className="flex flex-1 flex-col lg:flex-row">
        {/* stage */}
        <main className="relative flex flex-1 items-start justify-center overflow-y-auto px-4 py-10">
          <div className="pointer-events-none absolute inset-x-0 top-0 h-64 bg-gradient-to-b from-amber-400 to-transparent opacity-5" />
          <div className="relative w-full max-w-xl">
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
                <Avatar value={avatarFor(npub)} size={44} className="flex-none" />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1 text-[15px]">
                    <span className="font-bold text-zinc-900">eXcalibur</span>
                    <BadgeCheck className="h-4 w-4 text-amber-500" />
                    <span className="text-zinc-500">{handle} · now</span>
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

                  <div className="mt-4 flex max-w-md items-center justify-between text-zinc-500">
                    {([[MessageCircle, "24"], [Repeat2, "18"], [Heart, "212"], [BarChart2, "9.4K"]] as const).map(([Icon, n], i) => (
                      <div key={i} className="flex items-center gap-1.5 text-[13px]"><Icon className="h-[18px] w-[18px]" /> {n}</div>
                    ))}
                    <div className="flex items-center gap-3"><Bookmark className="h-[18px] w-[18px]" /><Share className="h-[18px] w-[18px]" /></div>
                  </div>
                </div>
              </div>
            </div>

            {!preview && (
              <button onClick={addBlock} className="mt-3 flex items-center gap-1.5 rounded-md border border-dashed border-zinc-700 px-3 py-1.5 text-sm text-zinc-400 hover:border-amber-400 hover:text-amber-300 transition-colors">
                <Plus className="h-4 w-4" /> Add text block
              </button>
            )}
            {hint && <div className="mt-3 font-mono text-xs text-amber-300">{hint}</div>}
            {error && <div className="mt-3 rounded-md border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-300">{error}</div>}
          </div>
        </main>

        {/* rail */}
        {!preview && (
          <aside className="w-full flex-none border-t border-zinc-800 lg:w-96 lg:border-l lg:border-t-0">
            <nav className="flex border-b border-zinc-800 font-mono text-xs uppercase tracking-widest">
              {([["flags", `Flags ${openFlagCount ? `(${openFlagCount})` : ""}`], ["voice", "Voice"], ["snippets", "Snippets"], ["schedule", "Schedule"]] as const).map(([k, label]) => (
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
              {tab === "voice" && <VoiceTab voice={voice} setVoice={setVoice} bans={bans} setBans={setBans} />}
              {tab === "snippets" && (
                <SnippetsTab
                  npub={npub}
                  currentText={focusedBlockText}
                  onInsert={insertSnippet}
                />
              )}
              {tab === "schedule" && (
                <ScheduleTab
                  publishAt={publishAt} setPublishAt={setPublishAt}
                  freq={freq} setFreq={setFreq}
                  interval={interval} setInterval={setIntervalN}
                  ceaseAt={ceaseAt} setCeaseAt={setCeaseAt}
                  intent={intent} copyIntent={copyIntent} copied={copied}
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
  block, idx, preview, editing, activeFlagId, overIndex,
  onMouseUp, onFlagClick, onEdit, onDoneEdit, onChange, onDelete, onMoveUp, onMoveDown, canDelete, dragHandlers,
}: {
  block: Block; idx: number; preview: boolean; editing: boolean; activeFlagId: string | null; overIndex: number | null;
  onMouseUp: (blockId: string, el: HTMLElement | null) => void;
  onFlagClick: (flagId: string, rect: DOMRect) => void;
  onEdit: () => void; onDoneEdit: () => void; onChange: (t: string) => void; onDelete: () => void;
  onMoveUp: () => void; onMoveDown: () => void; canDelete: boolean;
  dragHandlers: HTMLAttributes<HTMLDivElement>;
}) {
  const ref = useRef<HTMLParagraphElement>(null);
  const editRef = useRef<HTMLTextAreaElement>(null);
  const segs = useMemo(() => segmentize(block.text, block.flags), [block.text, block.flags]);

  if (preview) {
    return <p className="whitespace-pre-wrap break-words text-[15px] leading-normal text-zinc-900">{block.text}</p>;
  }
  if (editing) {
    const applyStyle = (style: UnicodeStyle) => {
      const ta = editRef.current;
      if (!ta || ta.selectionStart === ta.selectionEnd) return;
      const s = ta.selectionStart, e = ta.selectionEnd;
      onChange(block.text.slice(0, s) + styleText(block.text.slice(s, e), style) + block.text.slice(e));
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
        <div className="flex items-center gap-1 rounded-t-md bg-amber-100 px-2 py-1">
          {fmtBtn(<Bold className="h-3.5 w-3.5" />, "bold", "Bold (Unicode)")}
          {fmtBtn(<Italic className="h-3.5 w-3.5" />, "italic", "Italic (Unicode)")}
          {fmtBtn(<Code className="h-3.5 w-3.5" />, "mono", "Monospace (Unicode)")}
          <span className="ml-2 text-[10px] text-amber-700">select text, then style — X-ready Unicode</span>
        </div>
        <textarea
          ref={editRef}
          autoFocus value={block.text} onChange={(e) => onChange(e.target.value)}
          rows={Math.max(2, Math.ceil(block.text.length / 42))}
          className="w-full resize-none bg-amber-50 p-2 text-[15px] leading-normal text-zinc-900 outline-none"
        />
        <div className="flex items-center justify-between rounded-b-md bg-amber-100 px-2 py-1">
          <span className="font-mono text-[10px] text-amber-700">editing clears this block's flags</span>
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

// ── voice tab ─────────────────────────────────────────────────────────────
// ── snippets tab ────────────────────────────────────────────────────────────
function SnippetsTab({
  npub, currentText, onInsert,
}: {
  npub: string;
  currentText: string;
  onInsert: (text: string) => void;
}) {
  const [snippets, setSnippets] = useState<Snippet[]>(() => getSnippets(npub));
  const [name, setName] = useState("");

  function save() {
    const n = name.trim();
    const t = currentText.trim();
    if (!n || !t) return;
    setSnippets(addSnippet(npub, n, t));
    setName("");
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
            disabled={!name.trim() || !currentText.trim()}
            className="rounded-md bg-amber-400 px-3 py-1.5 text-sm font-medium text-zinc-950 hover:bg-amber-300 disabled:opacity-40 transition-colors"
          >
            Save
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
            {snippets.map((s) => (
              <div key={s.id} className="rounded-lg border border-zinc-800 bg-zinc-900 p-2.5">
                <div className="flex items-center gap-2">
                  <span className="flex-1 min-w-0 truncate text-sm text-zinc-200">{s.name}</span>
                  <button onClick={() => onInsert(s.text)} className="text-xs text-amber-300 hover:text-amber-200" title="Add as a block">
                    + Insert
                  </button>
                  <button onClick={() => setSnippets(removeSnippet(npub, s.id))} className="text-zinc-500 hover:text-rose-400" title="Delete snippet">
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
                <p className="mt-1 text-[11px] text-zinc-500 line-clamp-2">{s.text}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function VoiceTab({ voice, setVoice, bans, setBans }: {
  voice: string; setVoice: (v: string) => void; bans: Ban[]; setBans: Dispatch<SetStateAction<Ban[]>>;
}) {
  const toggle = (i: number) => setBans((prev) => prev.map((b, j) => (j === i ? { ...b, on: !b.on } : b)));
  return (
    <div className="space-y-5">
      <div>
        <label className="mb-1.5 block font-mono text-[11px] uppercase tracking-widest text-zinc-500">Voice profile</label>
        <textarea value={voice} onChange={(e) => setVoice(e.target.value)} rows={5}
          className="w-full resize-none rounded-md border border-zinc-700 bg-zinc-900 p-2 text-sm text-zinc-200 outline-none focus:border-amber-400"
          placeholder="Paste a few sentences in your own voice…" />
        <p className="mt-1.5 text-xs text-zinc-500">Fed to Claude on every refinement so rewrites sound like you, not like a model.</p>
      </div>
      <div>
        <label className="mb-2 block font-mono text-[11px] uppercase tracking-widest text-zinc-500">Banned constructions</label>
        <div className="flex flex-wrap gap-2">
          {bans.map((b, i) => (
            <button key={i} onClick={() => toggle(i)}
              className={`rounded-full border px-2.5 py-1 text-xs transition-colors ${b.on ? "border-amber-400 bg-amber-400 text-zinc-950" : "border-zinc-700 text-zinc-500 line-through"}`}>
              {b.text}
            </button>
          ))}
        </div>
        <p className="mt-2 text-xs text-zinc-500">Active chips are passed as hard constraints. Tap to disable any you don't mind.</p>
      </div>
    </div>
  );
}

// ── schedule tab ────────────────────────────────────────────────────────────
function ScheduleTab({
  publishAt, setPublishAt, freq, setFreq, interval, setInterval, ceaseAt, setCeaseAt,
  intent, copyIntent, copied, onSchedule, saving, onDiscard, isNew,
}: {
  publishAt: string; setPublishAt: (v: string) => void;
  freq: Freq; setFreq: (v: Freq) => void;
  interval: number; setInterval: (v: number) => void;
  ceaseAt: string; setCeaseAt: (v: string) => void;
  intent: unknown; copyIntent: () => void; copied: boolean;
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

      <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-3">
        <div className="mb-2 flex items-center justify-between">
          <span className="font-mono text-[11px] uppercase tracking-widest text-zinc-500">publish intent</span>
          <button onClick={copyIntent} className="flex items-center gap-1 text-xs text-amber-300 hover:text-amber-200">
            {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}{copied ? "Copied" : "Copy"}
          </button>
        </div>
        <pre className="overflow-x-auto whitespace-pre-wrap break-words font-mono text-[11px] leading-relaxed text-zinc-400">{JSON.stringify(intent, null, 2)}</pre>
      </div>

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

function toLocalInput(iso: string): string {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "";
  const local = new Date(d.getTime() - d.getTimezoneOffset() * 60000);
  return local.toISOString().slice(0, 16);
}
