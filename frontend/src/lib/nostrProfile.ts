// Nostr kind-0 profile — DRY edition. Relay I/O now lives in the wheel
// (get_nostr_profile / publish_nostr_profile); the FE only does the part that
// MUST stay client-side: SIGNING. We never hand a patron nsec to the backend —
// we sign the kind-0 here (session key or NIP-07) and pass the signed event to
// the wheel, which verifies pubkey+signature and relays it.

import { finalizeEvent, type Event as NostrEvent } from "nostr-tools";
import { getSessionNsecBytes, hasSessionNsec } from "./sessionNsec";
import {
  getNostrProfile,
  getStoredNpub,
  publishNostrProfile,
  type Kind0,
  type PublishNostrProfileResult,
} from "./mcp";

export type { Kind0 } from "./mcp";

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

/// True when we can sign a kind-0 — in-browser session nsec or a NIP-07 signer.
export function canSignProfile(): boolean {
  return hasSessionNsec() || (typeof window !== "undefined" && !!window.nostr);
}

/// Read the npub's public kind-0 via the operator MCP.
export async function fetchProfile(npub: string): Promise<Kind0 | null> {
  try {
    const r = await getNostrProfile(npub);
    return r.profile && Object.keys(r.profile).length ? r.profile : null;
  } catch {
    return null;
  }
}

/// Sign a kind-0 with the patron's key (session nsec or NIP-07) and hand the
/// signed event to the wheel to relay. Throws if no signer is available.
export async function publishProfile(content: Kind0): Promise<PublishNostrProfileResult> {
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

  return publishNostrProfile(getStoredNpub(), JSON.stringify(signed));
}
