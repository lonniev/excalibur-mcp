// Reusable post snippets (common openings / footers / CTAs) — persisted in
// Neon, npub-scoped, via the MCP's free + proof-gated snippet tools. The
// logged-in npub follows the patron across devices; the browser keeps no copy.
// Favorites surface as one-click chiclets in the editor.

import { deleteSnippet, listSnippets, saveSnippet, type SnippetRow } from "./mcp";
import { asDoc } from "./editorDoc";

export type Snippet = SnippetRow;

/// Load the logged-in npub's snippets for the editor (favorites first, full
/// rows incl. text+doc). One big page is plenty — snippet libraries are small.
/// Network errors yield an empty list so the editor still opens if the MCP is
/// warming up.
export async function loadSnippets(): Promise<Snippet[]> {
  try {
    const r = await listSnippets({ sortCol: "favorite", sortDir: "desc", pageSize: 200 });
    return r.snippets ?? [];
  } catch {
    return [];
  }
}

/// Create a snippet, then return the refreshed list. A `dynamic` snippet stores
/// a single dynamic block in its `doc` (its `text` is a runnable prompt); an
/// optional `fallback` is what posts if resolution fails. Static snippets store
/// just the text (no doc), exactly as before.
export async function addSnippet(
  name: string,
  text: string,
  opts: { dynamic?: boolean; fallback?: string; doc?: unknown } = {},
): Promise<Snippet[]> {
  // Prefer an explicit serialized doc (carries the focused block's full settings
  // — dynamic/fallback/domains/maxFetches); else synthesize one for the simple
  // {dynamic, fallback} case; else a static (no-doc) snippet.
  const doc = opts.doc
    ?? (opts.dynamic
      ? { blocks: [{ text, flags: [], dynamic: true, ...(opts.fallback ? { fallback: opts.fallback } : {}) }] }
      : undefined);
  await saveSnippet({ name: name.trim(), text, favorite: false, doc });
  return loadSnippets();
}

/// A snippet is dynamic when its stored `doc` carries a dynamic block. Reading
/// from `doc` keeps dynamic-ness in one place (no extra column) — the same flag
/// a post block carries.
export function snippetIsDynamic(s: Snippet): boolean {
  const blocks = (asDoc(s.doc) as { blocks?: { dynamic?: boolean }[] } | null)?.blocks;
  return Array.isArray(blocks) && blocks.some((b) => b?.dynamic);
}

/// The fallback text stored on a dynamic snippet's block (empty if none).
export function snippetFallback(s: Snippet): string {
  const blocks = (asDoc(s.doc) as { blocks?: { fallback?: string }[] } | null)?.blocks;
  const b = Array.isArray(blocks) ? blocks.find((x) => x?.fallback) : undefined;
  return b?.fallback ?? "";
}

/// Delete a snippet, then return the refreshed list.
export async function removeSnippet(id: string): Promise<Snippet[]> {
  await deleteSnippet(id);
  return loadSnippets();
}

/// Set a snippet's favorite flag, then return the refreshed list. Favorites
/// become one-click chiclets next to "Add text block".
export async function toggleFavorite(id: string, favorite: boolean): Promise<Snippet[]> {
  await saveSnippet({ id, favorite });
  return loadSnippets();
}

/// Toggle an existing snippet into / out of being dynamic, then return the
/// refreshed list. Dynamic-ness lives in the snippet's `doc` (a single block
/// whose text is the prompt); a dynamic snippet's existing fallback is preserved
/// when toggling on. This is a doc-only patch, so the snippet's favorite/name are
/// left untouched server-side.
export async function toggleDynamic(s: Snippet, dynamic: boolean): Promise<Snippet[]> {
  const doc = dynamic
    ? { blocks: [{ text: s.text, flags: [], dynamic: true, ...(snippetFallback(s) ? { fallback: snippetFallback(s) } : {}) }] }
    : { blocks: [{ text: s.text, flags: [] }] };
  await saveSnippet({ id: s.id, doc });
  return loadSnippets();
}
