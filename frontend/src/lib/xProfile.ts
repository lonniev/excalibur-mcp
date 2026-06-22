// Connected X account, cached per npub. The editor reads the cache for an
// instant @handle on open; the network is hit at most once per TTL (a handle
// rarely changes), which keeps this personalization call from churning OAuth
// token refreshes on every page mount. Failures are inert — best-effort.

import { getXProfile, type XProfile } from "./mcp";

const KEY = (npub: string) => `excalibur:xprofile:${npub}`;
const TTL_MS = 7 * 24 * 60 * 60 * 1000; // a handle is stable; refetch weekly

interface Cached extends XProfile {
  _ts?: number;
}

export function cachedXProfile(npub: string): XProfile | null {
  if (!npub) return null;
  try {
    const raw = localStorage.getItem(KEY(npub));
    return raw ? (JSON.parse(raw) as Cached) : null;
  } catch {
    return null;
  }
}

/// Fetch the live profile and cache it (stamped). Returns null (leaving any
/// cache intact) when X isn't connected or the call fails.
export async function refreshXProfile(npub: string): Promise<XProfile | null> {
  if (!npub) return null;
  try {
    const p = await getXProfile();
    if (p.username) {
      const stamped: Cached = { ...p, _ts: Date.now() };
      localStorage.setItem(KEY(npub), JSON.stringify(stamped));
      return stamped;
    }
  } catch {
    /* best-effort */
  }
  return null;
}

/// Cache-first: return the cached profile without a network call when it's
/// still fresh; otherwise fetch once and cache. Falls back to any stale cache.
export async function ensureXProfile(npub: string): Promise<XProfile | null> {
  if (!npub) return null;
  const cached = cachedXProfile(npub) as Cached | null;
  if (cached?.username && cached._ts && Date.now() - cached._ts < TTL_MS) {
    return cached;
  }
  return (await refreshXProfile(npub)) ?? cached;
}
