// Nostr kind-0 profile metadata (NIP-01). The avatar + contact info for an
// npub live in a replaceable kind-0 event: JSON content with name,
// display_name, about, picture (avatar URL), banner, nip05, website, lud16
// (Lightning address). Signed by the npub's key — relays just replicate it,
// so it's self-sovereign and visible in every Nostr client.
//
// Read: fetch the latest kind-0 across our relays. Write: build a kind-0,
// sign with the in-browser session nsec (or a NIP-07 extension), publish to
// relays. picture/banner are URLs (image bytes live off-relay).

import { SimplePool, finalizeEvent, nip19, type Event as NostrEvent } from "nostr-tools";
import { getSessionNsecBytes, hasSessionNsec } from "./sessionNsec";

export const PROFILE_RELAYS = [
  "wss://relay.primal.net",
  "wss://nos.lol",
  "wss://relay.damus.io",
  "wss://relay.nostr.band",
];

export interface Kind0 {
  name?: string;
  display_name?: string;
  about?: string;
  picture?: string;
  banner?: string;
  nip05?: string;
  website?: string;
  lud16?: string;
}

interface Nip07 {
  getPublicKey(): Promise<string>;
  signEvent(event: {
    kind: number;
    created_at: number;
    tags: string[][];
    content: string;
    pubkey?: string;
  }): Promise<NostrEvent>;
}
declare global {
  interface Window {
    nostr?: Nip07;
  }
}

function npubToHex(npub: string): string {
  const d = nip19.decode(npub);
  if (d.type !== "npub" || typeof d.data !== "string") throw new Error(`Not an npub: ${npub}`);
  return d.data;
}

/// True when we can publish a kind-0 — either an in-browser session nsec or a
/// NIP-07 signer extension is available.
export function canSignProfile(): boolean {
  return hasSessionNsec() || (typeof window !== "undefined" && !!window.nostr);
}

/// Fetch the latest kind-0 metadata for an npub. Returns null on no event /
/// unreachable relays / malformed content.
export async function fetchProfile(npub: string): Promise<Kind0 | null> {
  let hex: string;
  try {
    hex = npubToHex(npub);
  } catch {
    return null;
  }
  const pool = new SimplePool();
  try {
    const events = await pool.querySync(PROFILE_RELAYS, { kinds: [0], authors: [hex] });
    if (!events.length) return null;
    events.sort((a, b) => b.created_at - a.created_at);
    try {
      return JSON.parse(events[0].content) as Kind0;
    } catch {
      return null;
    }
  } catch {
    return null;
  } finally {
    try {
      pool.close(PROFILE_RELAYS);
    } catch {
      /* noop */
    }
  }
}

export interface PublishResult {
  ok: number;
  total: number;
}

/// Sign and publish a kind-0 metadata event. Drops empty fields. Throws if no
/// signer is available.
export async function publishProfile(content: Kind0): Promise<PublishResult> {
  const clean: Kind0 = {};
  for (const [k, v] of Object.entries(content)) {
    if (typeof v === "string" && v.trim()) clean[k as keyof Kind0] = v.trim();
  }
  const template = {
    kind: 0,
    created_at: Math.floor(Date.now() / 1000),
    tags: [] as string[][],
    content: JSON.stringify(clean),
  };

  let signed: NostrEvent;
  if (hasSessionNsec()) {
    signed = finalizeEvent(template, getSessionNsecBytes());
  } else if (typeof window !== "undefined" && window.nostr) {
    const pubkey = await window.nostr.getPublicKey();
    signed = await window.nostr.signEvent({ ...template, pubkey });
  } else {
    throw new Error(
      "No signer available — sign in with a session key or a NIP-07 extension to publish your Nostr profile.",
    );
  }

  const pool = new SimplePool();
  try {
    const results = await Promise.allSettled(pool.publish(PROFILE_RELAYS, signed));
    return { ok: results.filter((r) => r.status === "fulfilled").length, total: PROFILE_RELAYS.length };
  } finally {
    try {
      pool.close(PROFILE_RELAYS);
    } catch {
      /* noop */
    }
  }
}
