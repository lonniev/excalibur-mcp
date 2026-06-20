// Yjs document model for the editorial editor.
//
// A post is a Y.Array of blocks; each block is a Y.Map { id: string,
// text: Y.Text }. Flagged regions ("select a span for rework") anchor to
// Y.RelativePosition so they ride along as the author edits the text around
// them. Single-player for now (no provider) — Yjs gives us stable anchors +
// a free undo/redo manager, and sets up real-time later.

import * as Y from "yjs";

export interface BlockDesc {
  id: string;
  text: string;
}

// Flag persisted to the backend `doc` (plain block-index + char offsets —
// RelativePosition is session-bound, and stored blocks are plain strings with
// no ids, so we anchor by index and rebuild RelativePositions on load).
export interface FlagOffset {
  blockIndex: number;
  start: number;
  end: number;
  colorIdx: number;
  note: string;
}

// Live flag held in component state: anchors survive edits to the block.
export interface FlagState {
  id: string;
  blockId: string;
  startRel: Y.RelativePosition;
  endRel: Y.RelativePosition;
  colorIdx: number;
  note: string;
}

// Distinct highlight hues (rgb triplets) — used at low alpha for marks and
// solid for rail swatches, so they read in both light and dark themes.
export const MARK_RGB = [
  "234,179,8", // amber
  "239,68,68", // red
  "59,130,246", // blue
  "16,185,129", // emerald
  "168,85,247", // purple
  "249,115,22", // orange
  "20,184,166", // teal
  "236,72,153", // pink
];

export function markBg(idx: number): string {
  return `rgba(${MARK_RGB[idx % MARK_RGB.length]},0.32)`;
}
export function swatch(idx: number): string {
  return `rgb(${MARK_RGB[idx % MARK_RGB.length]})`;
}

/// Stable free-list: hand out the lowest colour index not currently in use so
/// removing a flag frees its colour for reuse (no drift toward high indices).
export function allocColor(used: number[]): number {
  for (let i = 0; i < 256; i++) if (!used.includes(i)) return i;
  return used.length;
}

export function uid(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) return crypto.randomUUID();
  return `id-${Date.now()}-${Math.floor(Math.random() * 1e9)}`;
}

// X-style fold weighting (editorial spec): URLs count 23, emoji 2, else 1.
const URL_RE = /https?:\/\/\S+/g;
const EMOJI_RE = /\p{Extended_Pictographic}/gu;
export const FOLD_BUDGET = 280;

export function weightedLength(text: string): number {
  const urls = text.match(URL_RE) ?? [];
  let body = text;
  for (const u of urls) body = body.replace(u, "");
  const emoji = (body.match(EMOJI_RE) ?? []).length;
  const rest = [...body.replace(EMOJI_RE, "")].length;
  return urls.length * 23 + emoji * 2 + rest;
}

/// Apply the minimal insert/delete to turn `ytext` into `next`, preserving
/// relative-position anchors outside the changed span (a wholesale
/// delete+insert would orphan every flag).
export function applyTextDiff(ytext: Y.Text, next: string): void {
  const prev = ytext.toString();
  if (prev === next) return;
  const min = Math.min(prev.length, next.length);
  let p = 0;
  while (p < min && prev[p] === next[p]) p++;
  let s = 0;
  while (s < min - p && prev[prev.length - 1 - s] === next[next.length - 1 - s]) s++;
  const delCount = prev.length - p - s;
  const insStr = next.slice(p, next.length - s);
  const doc = ytext.doc;
  const run = () => {
    if (delCount > 0) ytext.delete(p, delCount);
    if (insStr) ytext.insert(p, insStr);
  };
  doc ? doc.transact(run) : run();
}

export function blockText(block: Y.Map<unknown>): Y.Text {
  return block.get("text") as Y.Text;
}

export function makeBlock(desc: BlockDesc): Y.Map<unknown> {
  const m = new Y.Map();
  m.set("id", desc.id);
  m.set("text", new Y.Text(desc.text));
  return m;
}

export interface PostDoc {
  blocks: string[];
  flags: FlagOffset[];
}

/// Parse a stored post `doc` (or fall back to text_cache) into block strings.
export function parseDoc(doc: unknown, textCache?: string): { blocks: string[]; flags: FlagOffset[] } {
  const d = doc as Partial<PostDoc> | null | undefined;
  let blocks: string[] = [];
  if (d && Array.isArray(d.blocks)) {
    blocks = d.blocks.map((b) => (typeof b === "string" ? b : String((b as { text?: string })?.text ?? "")));
  } else if (textCache) {
    blocks = textCache.split(/\n\n+/);
  }
  blocks = blocks.length ? blocks : [""];
  const flags: FlagOffset[] = d && Array.isArray(d.flags)
    ? d.flags.filter(
        (f): f is FlagOffset =>
          !!f && typeof f.blockIndex === "number" &&
          typeof f.start === "number" && typeof f.end === "number",
      ).map((f) => ({ ...f, colorIdx: f.colorIdx ?? 0, note: f.note ?? "" }))
    : [];
  return { blocks, flags };
}
