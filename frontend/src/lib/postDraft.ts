// Save safety for the post editor: (a) refuse to treat an unconfirmed tool
// response as a success, and (b) mirror the working post to device-local storage
// as the author edits. Together these guarantee a blocked/unconfirmed save — or a
// reload or crash — never silently loses their work.
//
// Motivation: create_post / update_post can return a SOFT failure
// (`{success:false, message}`) with no `.error` field. The editor previously
// checked only `.error`, so a blocked save slipped through the success branch,
// cleared the dirty baseline, and dropped the post cache — and the edit vanished.

export interface SaveResultish {
  post_id?: string;
  updated_at?: string;
  success?: boolean;
  error?: string;
  error_code?: string;
  message?: string;
}

/// Normalize any create/update tool response to a human error string, or `null`
/// on a CONFIRMED success. A confirmed success is a response carrying a real
/// `post_id` with no soft-error. Everything else — an explicit `error`, a
/// `success:false` soft failure, or a response with no `post_id` — is a failure
/// the caller must surface WITHOUT discarding the author's edits.
export function saveError(r: SaveResultish | null | undefined): string | null {
  if (!r) return "The save didn't reach the server — your edits are still here. Try again.";
  if (r.error) return r.error;
  if (r.success === false) return r.message || r.error_code || "The save was blocked — nothing was changed. Your edits are still here.";
  if (!r.post_id) return "The save didn't confirm — your edits are still here. Try again.";
  return null;
}

// ── device-local autosave ──────────────────────────────────────────────────
// One draft per post id ("new" for an unsaved compose). Stores the serialized
// blocks + schedule fields + a timestamp, so the editor can offer to restore
// work that a blocked save, reload, or crash would otherwise drop.

export interface LocalDraft {
  doc: unknown; // serializeBlocks() output
  title?: string;
  publishAt?: string; // datetime-local input value
  freq?: string;
  interval?: number;
  ceaseAt?: string;
  savedAt: number; // epoch ms
}

const KEY = (id: string) => `excalibur.postdraft.${id}`;

export function writeDraft(id: string, draft: Omit<LocalDraft, "savedAt">): void {
  try {
    localStorage.setItem(KEY(id), JSON.stringify({ ...draft, savedAt: Date.now() }));
  } catch {
    /* storage full / disabled — autosave is best-effort, never a blocker */
  }
}

export function readDraft(id: string): LocalDraft | null {
  try {
    const raw = localStorage.getItem(KEY(id));
    return raw ? (JSON.parse(raw) as LocalDraft) : null;
  } catch {
    return null;
  }
}

export function clearDraft(id: string): void {
  try {
    localStorage.removeItem(KEY(id));
  } catch {
    /* ignore */
  }
}

/// A stored draft is worth offering back only when it is NEWER than the server's
/// last-saved copy — i.e. it holds edits the server never confirmed. (We clear
/// the draft on every confirmed save, so a lingering newer draft means the last
/// edits didn't land.) For a brand-new compose there is no server row, so any
/// stored draft qualifies.
export function draftIsUnsaved(draft: LocalDraft | null, serverUpdatedAt?: string | null): boolean {
  if (!draft) return false;
  if (!serverUpdatedAt) return true;
  const server = new Date(serverUpdatedAt).getTime();
  return isNaN(server) || draft.savedAt > server;
}
