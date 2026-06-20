// Avatar persistence — eXcalibur has no set_profile tool, so the chosen
// avatar lives in localStorage keyed by npub (like voice/bans). A change
// dispatches a window event so the Nav and editor update without a reload.

import { AVATAR_CHOICES } from "../components/Avatar";
import { fetchProfile } from "./nostrProfile";

export const AVATAR_EVENT = "excalibur:avatar-changed";

function key(npub: string): string {
  return `excalibur:avatar:${npub}`;
}

export function getStoredAvatar(npub: string): string | null {
  if (!npub) return null;
  try {
    return window.localStorage.getItem(key(npub));
  } catch {
    return null;
  }
}

export function setStoredAvatar(npub: string, value: string): void {
  if (!npub) return;
  window.localStorage.setItem(key(npub), value);
  window.dispatchEvent(new CustomEvent(AVATAR_EVENT, { detail: { npub, value } }));
}

/// Deterministic default glyph from the npub, so a fresh patron still has a
/// stable, distinct avatar before they pick one.
export function defaultAvatar(npub: string): string {
  let h = 0;
  for (const c of npub) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return AVATAR_CHOICES[h % AVATAR_CHOICES.length];
}

export function avatarFor(npub: string): string {
  return getStoredAvatar(npub) || defaultAvatar(npub);
}

/// Pull the npub's kind-0 `picture` from Nostr and cache it locally (so the
/// sync avatarFor / Nav / editor reflect it). kind-0 is the source of truth;
/// we only seed the cache when there's no explicit local override, so a
/// deliberate local pick isn't clobbered on every login.
export async function hydrateAvatarFromNostr(npub: string): Promise<void> {
  if (!npub || getStoredAvatar(npub)) return;
  try {
    const p = await fetchProfile(npub);
    if (p?.picture) setStoredAvatar(npub, p.picture);
  } catch {
    /* offline / no relay — keep the deterministic glyph */
  }
}
