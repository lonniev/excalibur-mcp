import { useEffect, useReducer, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import * as Y from "yjs";
import {
  createPost,
  deletePost,
  getPost,
  updatePost,
  type PostRow,
  type Recurrence,
} from "../lib/mcp";
import {
  allocColor,
  applyTextDiff,
  blockText,
  FOLD_BUDGET,
  makeBlock,
  markBg,
  parseDoc,
  swatch,
  uid,
  weightedLength,
  type BlockDesc,
  type FlagOffset,
  type FlagState,
} from "../lib/editorDoc";

const TYPO = "text-[15px] leading-7 font-sans whitespace-pre-wrap break-words";
const card = "rounded-xl border border-stone-200 dark:border-zinc-800 bg-white dark:bg-zinc-900";
const primary =
  "bg-amber-600 hover:bg-amber-500 text-white text-sm px-4 py-2 rounded-lg disabled:opacity-40 transition-colors";
const chip =
  "text-xs px-2 py-1 rounded-lg text-stone-500 dark:text-zinc-400 hover:bg-stone-100 dark:hover:bg-zinc-800 disabled:opacity-30 transition-colors";

interface Selection {
  blockIndex: number;
  start: number;
  end: number;
}
interface ResolvedFlag {
  flag: FlagState;
  blockIndex: number;
  start: number;
  end: number;
}

export default function PostEditorPage() {
  const { postId } = useParams();
  const nav = useNavigate();
  const isNew = !postId;

  const ydoc = useRef<Y.Doc | null>(null);
  const blocks = useRef<Y.Array<Y.Map<unknown>> | null>(null);
  const undo = useRef<Y.UndoManager | null>(null);
  const loaded = useRef(false);
  const autosaveTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const createReqId = useRef(uid());

  const [, bump] = useReducer((x) => x + 1, 0);
  const [flags, setFlags] = useState<FlagState[]>([]);
  const [sel, setSel] = useState<Selection | null>(null);
  const [activeBlock, setActiveBlock] = useState(0);

  const [status, setStatus] = useState<"draft" | "scheduled">("draft");
  const [publishAt, setPublishAt] = useState("");
  const [recFreq, setRecFreq] = useState<"" | "daily" | "weekly" | "monthly">("");
  const [recInterval, setRecInterval] = useState(1);
  const [ceaseAt, setCeaseAt] = useState("");

  const [loading, setLoading] = useState(!isNew);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [savedNote, setSavedNote] = useState<string | null>(null);

  // ── doc lifecycle ──────────────────────────────────────────────────────
  useEffect(() => {
    const doc = new Y.Doc();
    const arr = doc.getArray<Y.Map<unknown>>("blocks");
    ydoc.current = doc;
    blocks.current = arr;
    let cancelled = false;

    function finishInit(seedFlags: FlagState[]) {
      undo.current = new Y.UndoManager(arr, { captureTimeout: 350 });
      arr.observeDeep(() => {
        bump();
        if (!isNew && loaded.current) scheduleAutosave();
      });
      setFlags(seedFlags);
      loaded.current = true;
      setLoading(false);
      bump();
    }

    async function init() {
      if (isNew) {
        doc.transact(() => arr.push([makeBlock({ id: uid(), text: "" })]));
        finishInit([]);
        return;
      }
      try {
        const row: PostRow = await getPost(postId!);
        if (cancelled) return;
        if (row.error) {
          setError(row.error);
          setLoading(false);
          return;
        }
        const { blocks: bstr, flags: foff } = parseDoc(row.doc, row.text_cache);
        const descs: BlockDesc[] = bstr.map((t) => ({ id: uid(), text: t }));
        doc.transact(() => arr.push(descs.map(makeBlock)));
        if (row.status === "scheduled") setStatus("scheduled");
        if (row.publish_at) setPublishAt(toLocalInput(row.publish_at));
        const rec = row.recurrence as Recurrence | undefined;
        if (rec?.freq) {
          setRecFreq(rec.freq);
          setRecInterval(rec.interval || 1);
        }
        if (row.cease_at) setCeaseAt(toLocalInput(row.cease_at));
        finishInit(rebuildFlags(arr, descs, foff));
      } catch (e) {
        if (!cancelled) {
          setError((e as Error).message);
          setLoading(false);
        }
      }
    }
    void init();

    return () => {
      cancelled = true;
      if (autosaveTimer.current) clearTimeout(autosaveTimer.current);
      doc.destroy();
      loaded.current = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [postId, isNew]);

  // ── derived ────────────────────────────────────────────────────────────
  const descs = readDescs(blocks.current);
  const resolved = resolveFlags(ydoc.current, blocks.current, flags);
  const flagsByBlock = (i: number) =>
    resolved.filter((r) => r.blockIndex === i).map((r) => ({ start: r.start, end: r.end, colorIdx: r.flag.colorIdx }));
  const joined = descs.map((d) => d.text).join("\n\n");
  const weight = weightedLength(joined);
  const overFold = weight > FOLD_BUDGET;

  // ── mutations ──────────────────────────────────────────────────────────
  function setText(i: number, next: string) {
    const arr = blocks.current;
    if (!arr) return;
    applyTextDiff(blockText(arr.get(i)), next);
  }

  function addFlag() {
    const arr = blocks.current;
    if (!arr || !sel) return;
    const ytext = blockText(arr.get(sel.blockIndex));
    const startRel = Y.createRelativePositionFromTypeIndex(ytext, sel.start);
    const endRel = Y.createRelativePositionFromTypeIndex(ytext, sel.end);
    const colorIdx = allocColor(flags.map((f) => f.colorIdx));
    setFlags((prev) => [
      ...prev,
      { id: uid(), blockId: descs[sel.blockIndex]?.id ?? "", startRel, endRel, colorIdx, note: "" },
    ]);
    setSel(null);
    if (!isNew) scheduleAutosave();
  }

  function removeFlag(id: string) {
    setFlags((prev) => prev.filter((f) => f.id !== id));
    if (!isNew) scheduleAutosave();
  }

  function setFlagNote(id: string, note: string) {
    setFlags((prev) => prev.map((f) => (f.id === id ? { ...f, note } : f)));
    if (!isNew) scheduleAutosave();
  }

  function addBlock() {
    const arr = blocks.current;
    const doc = ydoc.current;
    if (!arr || !doc) return;
    const at = Math.min(activeBlock + 1, arr.length);
    doc.transact(() => arr.insert(at, [makeBlock({ id: uid(), text: "" })]));
    setActiveBlock(at);
  }

  function deleteBlock(i: number) {
    const arr = blocks.current;
    const doc = ydoc.current;
    if (!arr || !doc || arr.length <= 1) return;
    doc.transact(() => arr.delete(i, 1));
    // prune flags whose anchor was in the removed block
    setFlags((prev) => prev.filter((f) => resolveOne(doc, arr, f) !== null));
    if (!isNew) scheduleAutosave();
  }

  function moveBlock(from: number, to: number) {
    const arr = blocks.current;
    const doc = ydoc.current;
    if (!arr || !doc || to < 0 || to >= arr.length) return;
    const cur = readDescs(arr);
    const offsets = serializeFlags(doc, arr, flags);
    const order = [...cur];
    const [m] = order.splice(from, 1);
    order.splice(to, 0, m);
    const idToNew = new Map(order.map((d, i) => [d.id, i]));
    const remapped = offsets
      .map((o) => {
        const newIdx = idToNew.get(cur[o.blockIndex]?.id ?? "");
        return newIdx == null ? null : { ...o, blockIndex: newIdx };
      })
      .filter((o): o is FlagOffset => o !== null);
    doc.transact(() => {
      arr.delete(0, arr.length);
      arr.push(order.map((d) => makeBlock(d)));
    });
    setFlags(rebuildFlags(arr, order, remapped));
    setActiveBlock(to);
    if (!isNew) scheduleAutosave();
  }

  // ── persistence ────────────────────────────────────────────────────────
  function scheduleAutosave() {
    if (autosaveTimer.current) clearTimeout(autosaveTimer.current);
    autosaveTimer.current = setTimeout(() => void save(true), 5000);
  }

  async function save(silent = false) {
    const arr = blocks.current;
    const doc = ydoc.current;
    if (!arr || !doc) return;
    const cur = readDescs(arr);
    const blocksStr = cur.map((d) => d.text);
    if (!blocksStr.join("").trim()) {
      if (!silent) setError("Write something first.");
      return;
    }
    if (status === "scheduled" && !publishAt) {
      if (!silent) setError("Pick a publish time for a scheduled post.");
      return;
    }
    if (!silent) setSaving(true);
    setError(null);
    const docPayload = { blocks: blocksStr, flags: serializeFlags(doc, arr, flags) };
    const textCache = blocksStr.join("\n\n");
    const publishIso =
      status === "scheduled" && publishAt ? new Date(publishAt).toISOString() : undefined;
    const recurrence: Recurrence | undefined =
      status === "scheduled" && recFreq ? { freq: recFreq, interval: Math.max(1, recInterval) } : undefined;
    const ceaseIso = ceaseAt ? new Date(ceaseAt).toISOString() : undefined;

    try {
      if (isNew) {
        const r = await createPost({
          doc: docPayload,
          textCache,
          status,
          publishAt: publishIso,
          recurrence,
          ceaseAt: ceaseIso,
          clientReqId: createReqId.current,
        });
        if (r.error) setError(r.error);
        else if (r.post_id) nav(`/post/${r.post_id}`, { replace: true });
      } else {
        const patch: Record<string, unknown> = { doc: docPayload, status };
        if (publishIso) patch.publish_at = publishIso;
        if (recurrence) patch.recurrence = recurrence;
        if (ceaseIso) patch.cease_at = ceaseIso;
        const r = await updatePost({ postId: postId!, patch, textCache, clientReqId: uid() });
        if (r.error) setError(r.error);
        else setSavedNote(silent ? "Autosaved" : "Saved");
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      if (!silent) setSaving(false);
      if (savedNote) window.setTimeout(() => setSavedNote(null), 2000);
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
    <div className="max-w-5xl mx-auto px-4 py-6">
      <div className="flex items-center gap-2 mb-4">
        <h1 className="text-lg font-semibold">{isNew ? "Compose" : "Edit post"}</h1>
        <div className="ml-auto flex items-center gap-1.5">
          <button onClick={() => undo.current?.undo()} className={chip} title="Undo">↶ Undo</button>
          <button onClick={() => undo.current?.redo()} className={chip} title="Redo">↷ Redo</button>
          <button onClick={() => nav("/")} className={chip}>← Posts</button>
        </div>
      </div>

      <div className="grid md:grid-cols-[1fr_280px] gap-5">
        {/* Editor column */}
        <div className="space-y-3">
          {descs.map((d, i) => (
            <div key={d.id} className="group">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-xs text-stone-400 dark:text-zinc-600">block {i + 1}</span>
                <div className="ml-auto flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
                  <button onClick={() => moveBlock(i, i - 1)} disabled={i === 0} className={chip} title="Move up">↑</button>
                  <button onClick={() => moveBlock(i, i + 1)} disabled={i === descs.length - 1} className={chip} title="Move down">↓</button>
                  <button onClick={() => deleteBlock(i)} disabled={descs.length <= 1} className={chip} title="Delete block">✕</button>
                </div>
              </div>
              <BlockView
                text={d.text}
                flags={flagsByBlock(i)}
                onChange={(next) => setText(i, next)}
                onSelect={(range) => setSel(range ? { blockIndex: i, ...range } : null)}
                onFocus={() => setActiveBlock(i)}
              />
            </div>
          ))}

          <div className="flex items-center gap-2">
            <button onClick={addBlock} className={chip}>+ Add block</button>
            <button
              onClick={addFlag}
              disabled={!sel}
              className="text-xs px-2.5 py-1 rounded-lg bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-400 disabled:opacity-30 transition-colors"
              title="Flag the selected text for rework"
            >
              ⚑ Flag selection
            </button>
            <span className="text-xs text-stone-400 dark:text-zinc-600">
              {sel ? "selection ready — flag it" : "select text in a block to flag a region"}
            </span>
          </div>

          {/* Fold meter */}
          <div>
            <div className="flex justify-between text-xs mb-1">
              <span className="text-stone-400 dark:text-zinc-500">{descs.length} block(s)</span>
              <span className={overFold ? "text-red-500 dark:text-red-400" : "text-stone-400 dark:text-zinc-500"}>
                {weight}/{FOLD_BUDGET}{overFold ? " · past the fold" : ""}
              </span>
            </div>
            <div className="h-1 rounded-full bg-stone-100 dark:bg-zinc-800 overflow-hidden">
              <div
                className={`h-full transition-all ${overFold ? "bg-red-500" : "bg-amber-500"}`}
                style={{ width: `${Math.min(100, (weight / FOLD_BUDGET) * 100)}%` }}
              />
            </div>
          </div>
        </div>

        {/* Side rail */}
        <div className="space-y-4">
          {/* Flagged regions */}
          <div className={`${card} p-4`}>
            <div className="flex items-center mb-2">
              <span className="text-sm font-medium">Flagged regions</span>
              <span className="ml-auto text-xs text-stone-400 dark:text-zinc-500">{resolved.length}</span>
            </div>
            {resolved.length === 0 ? (
              <p className="text-xs text-stone-400 dark:text-zinc-500">
                Select text in a block and click <span className="whitespace-nowrap">⚑ Flag selection</span> to mark a region for rework.
              </p>
            ) : (
              <ul className="space-y-2.5">
                {resolved.map((r) => {
                  const excerpt = descs[r.blockIndex]?.text.slice(r.start, r.end) ?? "";
                  return (
                    <li key={r.flag.id} className="text-xs">
                      <div className="flex items-start gap-2">
                        <span className="w-3 h-3 rounded-full mt-0.5 shrink-0" style={{ backgroundColor: swatch(r.flag.colorIdx) }} />
                        <span className="flex-1 min-w-0 text-stone-600 dark:text-zinc-300 line-clamp-2">“{excerpt || "—"}”</span>
                        <button onClick={() => removeFlag(r.flag.id)} className="text-stone-400 hover:text-red-500 dark:text-zinc-500 shrink-0" title="Remove flag">✕</button>
                      </div>
                      <input
                        value={r.flag.note}
                        onChange={(e) => setFlagNote(r.flag.id, e.target.value)}
                        placeholder="how to rework this…"
                        className="mt-1.5 w-full rounded-md px-2 py-1 text-xs bg-white dark:bg-zinc-950 border border-stone-200 dark:border-zinc-800 focus:outline-none focus:border-amber-400"
                      />
                    </li>
                  );
                })}
              </ul>
            )}
            <button
              disabled
              title="Refine needs the operator's Anthropic key (delivered via Secure Courier). Coming next."
              className="mt-3 w-full text-xs py-2 rounded-lg border border-dashed border-stone-300 dark:border-zinc-700 text-stone-400 dark:text-zinc-600 cursor-not-allowed"
            >
              ✦ Refine flagged with Claude (soon)
            </button>
          </div>

          {/* Schedule */}
          <div className={`${card} p-4 space-y-3`}>
            <div className="text-sm font-medium">Schedule</div>
            <label className="block text-xs text-stone-500 dark:text-zinc-400">
              Status
              <select
                value={status}
                onChange={(e) => setStatus(e.target.value as "draft" | "scheduled")}
                className="mt-1 w-full rounded-lg px-2 py-1.5 text-sm bg-white dark:bg-zinc-950 border border-stone-300 dark:border-zinc-700"
              >
                <option value="draft">Draft</option>
                <option value="scheduled">Scheduled</option>
              </select>
            </label>
            {status === "scheduled" && (
              <>
                <label className="block text-xs text-stone-500 dark:text-zinc-400">
                  Publish at
                  <input
                    type="datetime-local"
                    value={publishAt}
                    onChange={(e) => setPublishAt(e.target.value)}
                    className="mt-1 w-full rounded-lg px-2 py-1.5 text-sm bg-white dark:bg-zinc-950 border border-stone-300 dark:border-zinc-700"
                  />
                </label>
                <label className="block text-xs text-stone-500 dark:text-zinc-400">
                  Repeat
                  <div className="mt-1 flex gap-1.5">
                    <select
                      value={recFreq}
                      onChange={(e) => setRecFreq(e.target.value as typeof recFreq)}
                      className="flex-1 rounded-lg px-2 py-1.5 text-sm bg-white dark:bg-zinc-950 border border-stone-300 dark:border-zinc-700"
                    >
                      <option value="">No repeat</option>
                      <option value="daily">Daily</option>
                      <option value="weekly">Weekly</option>
                      <option value="monthly">Monthly</option>
                    </select>
                    {recFreq && (
                      <input
                        type="number"
                        min={1}
                        value={recInterval}
                        onChange={(e) => setRecInterval(Math.max(1, Number(e.target.value) || 1))}
                        className="w-16 rounded-lg px-2 py-1.5 text-sm bg-white dark:bg-zinc-950 border border-stone-300 dark:border-zinc-700"
                        title="every N periods"
                      />
                    )}
                  </div>
                </label>
                {recFreq && (
                  <label className="block text-xs text-stone-500 dark:text-zinc-400">
                    Stop after
                    <input
                      type="datetime-local"
                      value={ceaseAt}
                      onChange={(e) => setCeaseAt(e.target.value)}
                      className="mt-1 w-full rounded-lg px-2 py-1.5 text-sm bg-white dark:bg-zinc-950 border border-stone-300 dark:border-zinc-700"
                    />
                  </label>
                )}
              </>
            )}
          </div>

          {/* Actions */}
          <div className="flex items-center gap-2">
            <button onClick={() => void save(false)} disabled={saving} className={primary}>
              {saving ? "Saving…" : isNew ? "Save" : "Save now"}
            </button>
            <button
              onClick={() => handleDelete(false)}
              className="text-sm px-3 py-2 rounded-lg text-stone-500 dark:text-zinc-400 hover:bg-stone-100 dark:hover:bg-zinc-800 transition-colors"
            >
              {isNew ? "Discard" : "Archive"}
            </button>
            {savedNote && <span className="text-xs text-green-600 dark:text-green-400">{savedNote}</span>}
          </div>
          {!isNew && (
            <button
              onClick={() => handleDelete(true)}
              className="text-xs text-stone-400 dark:text-zinc-600 hover:text-red-500 dark:hover:text-red-400 transition-colors"
            >
              Delete permanently
            </button>
          )}

          {error && (
            <div className="rounded-lg p-3 text-xs bg-red-50 border border-red-200 text-red-700 dark:bg-red-500/10 dark:border-red-500/30 dark:text-red-400">
              {error}
            </div>
          )}
          <p className="text-xs text-stone-400 dark:text-zinc-600">
            {isNew ? "Saves on demand." : "Autosaves ~5s after you stop typing."}
          </p>
        </div>
      </div>
    </div>
  );
}

// ── Block editor with highlight overlay ────────────────────────────────────

function BlockView({
  text,
  flags,
  onChange,
  onSelect,
  onFocus,
}: {
  text: string;
  flags: { start: number; end: number; colorIdx: number }[];
  onChange: (next: string) => void;
  onSelect: (range: { start: number; end: number } | null) => void;
  onFocus: () => void;
}) {
  const ref = useRef<HTMLTextAreaElement>(null);
  function report() {
    const ta = ref.current;
    if (!ta) return;
    onSelect(ta.selectionStart < ta.selectionEnd ? { start: ta.selectionStart, end: ta.selectionEnd } : null);
  }
  const segs = buildSegments(text, flags);
  return (
    <div className="relative rounded-lg border border-stone-200 dark:border-zinc-800 bg-white dark:bg-zinc-950 focus-within:border-amber-400 dark:focus-within:border-amber-500 transition-colors">
      <div aria-hidden className={`${TYPO} px-3 py-2.5 text-stone-900 dark:text-zinc-100`} style={{ minHeight: "3.5rem" }}>
        {segs.map((s, i) =>
          s.colorIdx == null ? (
            <span key={i}>{s.text}</span>
          ) : (
            <mark key={i} style={{ backgroundColor: markBg(s.colorIdx), color: "inherit", borderRadius: 2 }}>
              {s.text}
            </mark>
          ),
        )}
        {"​"}
      </div>
      <textarea
        ref={ref}
        value={text}
        onChange={(e) => onChange(e.target.value)}
        onSelect={report}
        onKeyUp={report}
        onMouseUp={report}
        onFocus={onFocus}
        placeholder="Write…"
        spellCheck
        className={`${TYPO} absolute inset-0 w-full h-full resize-none bg-transparent text-transparent caret-stone-900 dark:caret-zinc-100 placeholder:text-stone-400 dark:placeholder:text-zinc-600 outline-none px-3 py-2.5`}
      />
    </div>
  );
}

interface Seg {
  text: string;
  colorIdx: number | null;
}
function buildSegments(text: string, flags: { start: number; end: number; colorIdx: number }[]): Seg[] {
  if (!flags.length) return [{ text, colorIdx: null }];
  const color = new Array<number | null>(text.length).fill(null);
  for (const f of flags) {
    for (let i = Math.max(0, f.start); i < Math.min(text.length, f.end); i++) color[i] = f.colorIdx;
  }
  const segs: Seg[] = [];
  let i = 0;
  while (i < text.length) {
    const c = color[i];
    let j = i + 1;
    while (j < text.length && color[j] === c) j++;
    segs.push({ text: text.slice(i, j), colorIdx: c });
    i = j;
  }
  return segs.length ? segs : [{ text, colorIdx: null }];
}

// ── helpers ────────────────────────────────────────────────────────────────

function readDescs(arr: Y.Array<Y.Map<unknown>> | null): BlockDesc[] {
  if (!arr) return [];
  const out: BlockDesc[] = [];
  for (let i = 0; i < arr.length; i++) {
    const b = arr.get(i);
    out.push({ id: b.get("id") as string, text: blockText(b).toString() });
  }
  return out;
}

function resolveOne(
  doc: Y.Doc | null,
  arr: Y.Array<Y.Map<unknown>> | null,
  flag: FlagState,
): ResolvedFlag | null {
  if (!doc || !arr) return null;
  const a = Y.createAbsolutePositionFromRelativePosition(flag.startRel, doc);
  const b = Y.createAbsolutePositionFromRelativePosition(flag.endRel, doc);
  if (!a || !b) return null;
  let blockIndex = -1;
  for (let i = 0; i < arr.length; i++) {
    if (blockText(arr.get(i)) === a.type) {
      blockIndex = i;
      break;
    }
  }
  if (blockIndex < 0) return null;
  const start = Math.min(a.index, b.index);
  const end = Math.max(a.index, b.index);
  if (end <= start) return null;
  return { flag, blockIndex, start, end };
}

function resolveFlags(
  doc: Y.Doc | null,
  arr: Y.Array<Y.Map<unknown>> | null,
  flags: FlagState[],
): ResolvedFlag[] {
  const out: ResolvedFlag[] = [];
  for (const f of flags) {
    const r = resolveOne(doc, arr, f);
    if (r) out.push(r);
  }
  return out;
}

function serializeFlags(
  doc: Y.Doc | null,
  arr: Y.Array<Y.Map<unknown>> | null,
  flags: FlagState[],
): FlagOffset[] {
  return resolveFlags(doc, arr, flags).map((r) => ({
    blockIndex: r.blockIndex,
    start: r.start,
    end: r.end,
    colorIdx: r.flag.colorIdx,
    note: r.flag.note,
  }));
}

function rebuildFlags(
  arr: Y.Array<Y.Map<unknown>>,
  descs: BlockDesc[],
  offsets: FlagOffset[],
): FlagState[] {
  const out: FlagState[] = [];
  for (const o of offsets) {
    if (o.blockIndex < 0 || o.blockIndex >= arr.length) continue;
    const ytext = blockText(arr.get(o.blockIndex));
    const len = ytext.length;
    const start = Math.min(o.start, len);
    const end = Math.min(o.end, len);
    if (end <= start) continue;
    out.push({
      id: uid(),
      blockId: descs[o.blockIndex]?.id ?? "",
      colorIdx: o.colorIdx,
      note: o.note,
      startRel: Y.createRelativePositionFromTypeIndex(ytext, start),
      endRel: Y.createRelativePositionFromTypeIndex(ytext, end),
    });
  }
  return out;
}

function toLocalInput(iso: string): string {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return "";
  const local = new Date(d.getTime() - d.getTimezoneOffset() * 60000);
  return local.toISOString().slice(0, 16);
}
