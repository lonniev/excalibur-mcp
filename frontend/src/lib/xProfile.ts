// Connected X account, cached per npub. The editor reads the cache for an
// instant @handle on open and revalidates in the background, so the tweet-card
// preview shows the author's real X identity without a blocking round-trip.

import { getXProfile, type XProfile } from "./mcp";

const KEY = (npub: string) => `excalibur:xprofile:${npub}`;

export function cachedXProfile(npub: string): XProfile | null {
  if (!npub) return null;
  try {
    const raw = localStorage.getItem(KEY(npub));
    return raw ? (JSON.parse(raw) as XProfile) : null;
  } catch {
    return null;
  }
}

/// Fetch the live profile and cache it. Returns null (and leaves any cache
/// intact) when X isn't connected or the call fails — personalization is
/// best-effort; the editor falls back to a placeholder handle.
export async function refreshXProfile(npub: string): Promise<XProfile | null> {
  if (!npub) return null;
  try {
    const p = await getXProfile();
    if (p.username) {
      localStorage.setItem(KEY(npub), JSON.stringify(p));
      return p;
    }
  } catch {
    /* best-effort */
  }
  return null;
}
