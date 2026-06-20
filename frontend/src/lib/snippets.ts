// Reusable post snippets (common openings / footers / CTAs) — persisted in
// Neon, npub-scoped, via the MCP's free + proof-gated snippet tools. The
// logged-in npub follows the patron across devices; the browser keeps no copy.
// Favorites surface as one-click chiclets in the editor.

import { deleteSnippet, listSnippets, saveSnippet, type SnippetRow } from "./mcp";

export type Snippet = SnippetRow;

/// Load the logged-in npub's snippets (favorites first). Network errors yield
/// an empty list so the editor still opens if the MCP is warming up.
export async function loadSnippets(): Promise<Snippet[]> {
  try {
    return await listSnippets();
  } catch {
    return [];
  }
}

/// Create a snippet, then return the refreshed list.
export async function addSnippet(name: string, text: string): Promise<Snippet[]> {
  await saveSnippet({ name: name.trim(), text, favorite: false });
  return loadSnippets();
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
