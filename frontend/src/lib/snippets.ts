// Reusable post snippets (common openings / footers) saved per npub in
// localStorage — e.g. "My CTA Footer 26jun2026", "Christmas Welcome 2025".
// Click one in the editor to drop it in as a block.

export interface Snippet {
  id: string;
  name: string;
  text: string;
}

function key(npub: string): string {
  return `excalibur:snippets:${npub}`;
}

function sid(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) return crypto.randomUUID();
  return `snip-${Date.now()}-${Math.floor(Math.random() * 1e9)}`;
}

export function getSnippets(npub: string): Snippet[] {
  if (!npub) return [];
  try {
    const raw = window.localStorage.getItem(key(npub));
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed)
      ? parsed.filter(
          (s): s is Snippet =>
            !!s && typeof s.id === "string" && typeof s.name === "string" && typeof s.text === "string",
        )
      : [];
  } catch {
    return [];
  }
}

function write(npub: string, list: Snippet[]): void {
  window.localStorage.setItem(key(npub), JSON.stringify(list));
}

/// Add a snippet (newest first). Returns the updated list.
export function addSnippet(npub: string, name: string, text: string): Snippet[] {
  const list = [{ id: sid(), name: name.trim(), text }, ...getSnippets(npub)];
  write(npub, list);
  return list;
}

export function removeSnippet(npub: string, id: string): Snippet[] {
  const list = getSnippets(npub).filter((s) => s.id !== id);
  write(npub, list);
  return list;
}
