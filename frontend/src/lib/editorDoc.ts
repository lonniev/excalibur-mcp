// Editor document model — block list with per-block flagged regions.
// Mirrors the Excalibur Editorial prototype: flags are plain {start,end}
// char offsets within a block; freeform editing a block clears its flags.

export interface Flag {
  id: string;
  start: number;
  end: number;
  note: string;
  suggestions: string[];
  loading: boolean;
  error: string;
  colorIdx: number;
}

export interface Block {
  id: string;
  text: string;
  flags: Flag[];
  // A dynamic block's `text` IS a runnable prompt: at post time (and in Preview)
  // the server runs it with Claude and weaves a fresh answer into the tweet.
  // `fallback` is posted instead if resolution fails. Static blocks omit these.
  dynamic?: boolean;
  fallback?: string;
  // Author web-access controls for the prompt's resolution. `domains` is an
  // optional allowlist for web fetch (comma/newline; blank = any URL the prompt
  // references); `maxFetches` bounds web lookups (search + fetch).
  domains?: string;
  maxFetches?: number;
}

export interface Ban {
  text: string;
  on: boolean;
}

let _id = 100;
export function uid(): string {
  return `id${_id++}`;
}

// Distinct highlight colour per flagged region. Static Tailwind classes
// (no JIT) — marks sit on the white X card, dots/chips in the dark rail.
export interface Palette {
  mark: string;
  active: string;
  dot: string;
}
export const PALETTE: Palette[] = [
  { mark: "bg-amber-200", active: "bg-amber-300", dot: "bg-amber-400" },
  { mark: "bg-sky-200", active: "bg-sky-300", dot: "bg-sky-400" },
  { mark: "bg-emerald-200", active: "bg-emerald-300", dot: "bg-emerald-400" },
  { mark: "bg-fuchsia-200", active: "bg-fuchsia-300", dot: "bg-fuchsia-400" },
  { mark: "bg-orange-200", active: "bg-orange-300", dot: "bg-orange-400" },
  { mark: "bg-violet-200", active: "bg-violet-300", dot: "bg-violet-400" },
];
export function paletteOf(i: number): Palette {
  return PALETTE[((i % PALETTE.length) + PALETTE.length) % PALETTE.length];
}

export const DEFAULT_VOICE =
  "Plain, declarative, slightly contrarian. Sound-money conviction without " +
  "sermonizing. Short sentences. No hype words. Lets the mechanism carry the pitch.";

export const DEFAULT_BANS = [
  "Happy to…",
  "It's not X, it's Y",
  "not just X, but Y",
  "em-dash overuse",
  "delve / dive in",
  "in today's landscape",
  "game-changer",
  "elevate / unlock",
  "I hope this helps",
];

export interface Segment {
  text: string;
  flag: Flag | null;
}

/// Split block text into rendered segments given its flags.
export function segmentize(text: string, flags: Flag[]): Segment[] {
  const sorted = [...flags].sort((a, b) => a.start - b.start);
  const segs: Segment[] = [];
  let cursor = 0;
  for (const f of sorted) {
    if (f.start > cursor) segs.push({ text: text.slice(cursor, f.start), flag: null });
    segs.push({ text: text.slice(f.start, f.end), flag: f });
    cursor = f.end;
  }
  if (cursor < text.length) segs.push({ text: text.slice(cursor), flag: null });
  return segs;
}

export function overlaps(a: { start: number; end: number }, b: { start: number; end: number }): boolean {
  return a.start < b.end && b.start < a.end;
}

/// Absolute character offset of (node, offset) within `root`.
export function charOffset(root: Node, node: Node, offset: number): number {
  let chars = 0;
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  let n: Node | null;
  while ((n = walker.nextNode())) {
    if (n === node) return chars + offset;
    chars += (n.textContent ?? "").length;
  }
  return chars;
}

// Placeholder a dynamic block contributes to the FE-composed text_cache (a
// list-excerpt only — the live post resolves the prompt fresh server-side).
export const DYNAMIC_PLACEHOLDER = "⟨dynamic⟩";

export function composeText(blocks: Block[]): string {
  return blocks
    .map((b) => (b.dynamic ? (b.fallback?.trim() || DYNAMIC_PLACEHOLDER) : b.text))
    .join("\n\n")
    .trim();
}

/// Does this document carry any dynamic (prompt-driven) block?
export function hasDynamic(blocks: Block[]): boolean {
  return blocks.some((b) => b.dynamic);
}

function freshFlag(start: number, end: number, colorIdx: number, note = ""): Flag {
  return { id: uid(), start, end, note, suggestions: [], loading: false, error: "", colorIdx };
}

// ── persistence ──────────────────────────────────────────────────────────
// Stored doc shape: { blocks: [{ text, flags: [{start,end,note,colorIdx}] }] }.
// Falls back to legacy string[] blocks or text_cache.

interface StoredFlag {
  start: number;
  end: number;
  note?: string;
  colorIdx?: number;
}
interface StoredBlock {
  text: string;
  flags?: StoredFlag[];
  dynamic?: boolean;
  fallback?: string;
  domains?: string;
  maxFetches?: number;
}

/// Normalize a stored `doc` that may arrive as a parsed object OR a JSON string
/// (Neon hands JSONB back either way — the backend does the same in scheduler's
/// `_as_dict`). Returns the object, or null if absent/unparseable.
export function asDoc(doc: unknown): { blocks?: unknown } | null {
  if (doc == null) return null;
  if (typeof doc === "string") {
    try {
      const parsed = JSON.parse(doc);
      return parsed && typeof parsed === "object" ? (parsed as { blocks?: unknown }) : null;
    } catch {
      return null;
    }
  }
  return typeof doc === "object" ? (doc as { blocks?: unknown }) : null;
}

export function parsePostDoc(doc: unknown, textCache?: string): Block[] {
  const d = asDoc(doc);
  let raw: StoredBlock[] = [];
  if (d && Array.isArray(d.blocks)) {
    raw = d.blocks.map((b) =>
      typeof b === "string"
        ? { text: b }
        : {
            text: String((b as StoredBlock)?.text ?? ""),
            flags: (b as StoredBlock)?.flags,
            dynamic: (b as StoredBlock)?.dynamic,
            fallback: (b as StoredBlock)?.fallback,
            domains: (b as StoredBlock)?.domains,
            maxFetches: (b as StoredBlock)?.maxFetches,
          },
    );
  } else if (textCache) {
    raw = textCache.split(/\n\n+/).map((t) => ({ text: t }));
  }
  if (!raw.length) raw = [{ text: "" }];
  return raw.map((b) => ({
    id: uid(),
    text: b.text,
    // A dynamic block's text is a prompt, not flaggable copy — drop any flags.
    flags: b.dynamic
      ? []
      : (b.flags ?? [])
          .filter((f) => typeof f.start === "number" && typeof f.end === "number" && f.end > f.start)
          .map((f) => freshFlag(f.start, f.end, f.colorIdx ?? 0, f.note ?? "")),
    ...(b.dynamic ? { dynamic: true } : {}),
    ...(b.fallback ? { fallback: b.fallback } : {}),
    ...(b.domains ? { domains: b.domains } : {}),
    ...(b.maxFetches ? { maxFetches: b.maxFetches } : {}),
  }));
}

export interface PostDocPayload {
  blocks: { text: string; flags: StoredFlag[]; dynamic?: boolean; fallback?: string; domains?: string; maxFetches?: number }[];
}

export function serializeBlocks(blocks: Block[]): PostDocPayload {
  return {
    blocks: blocks.map((b) => ({
      text: b.text,
      flags: b.dynamic
        ? []
        : b.flags.map((f) => ({ start: f.start, end: f.end, note: f.note, colorIdx: f.colorIdx })),
      ...(b.dynamic ? { dynamic: true } : {}),
      ...(b.fallback ? { fallback: b.fallback } : {}),
      ...(b.domains ? { domains: b.domains } : {}),
      ...(b.maxFetches ? { maxFetches: b.maxFetches } : {}),
    })),
  };
}
