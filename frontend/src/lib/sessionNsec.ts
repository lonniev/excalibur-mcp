// Session nsec — a freshly-generated (or pasted) key kept in-browser to
// sign kind-27235 identity proofs per paid tool call (Tactic 2 in the
// wheel's identity_proof). Modeled on optionality-mcp's sessionNsec.ts.
//
// Threat model (named explicitly at the gate when the user picks this path):
//   - Stored unencrypted in localStorage under a fixed key. XSS on this
//     origin can exfiltrate it. Accepted for single-click sign-in; users
//     wanting stronger isolation can use a NIP-07 extension instead.
//   - Persisted only so a reload survives. Cleared on sign-out.

import { getPublicKey, nip19 } from "nostr-tools";

const STORAGE_KEY = "excalibur:session_nsec:v1";

export function getSessionNsec(): string | null {
  try {
    return window.localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

export function setSessionNsec(nsecBech32: string): void {
  if (!nsecBech32 || !nsecBech32.startsWith("nsec1")) {
    throw new Error("Expected a bech32 nsec1… string");
  }
  try {
    nip19.decode(nsecBech32);
  } catch (e) {
    throw new Error(`Invalid nsec: ${(e as Error).message}`);
  }
  window.localStorage.setItem(STORAGE_KEY, nsecBech32);
}

export function clearSessionNsec(): void {
  window.localStorage.removeItem(STORAGE_KEY);
}

/// Decode the cached nsec to its 32-byte secp256k1 scalar (the form
/// nostr-tools' finalizeEvent wants). Throws if absent or malformed.
export function getSessionNsecBytes(): Uint8Array {
  const nsec = getSessionNsec();
  if (!nsec) throw new Error("No session nsec set");
  const decoded = nip19.decode(nsec);
  if (decoded.type !== "nsec" || !(decoded.data instanceof Uint8Array)) {
    throw new Error("Stored value is not a valid nsec");
  }
  return decoded.data;
}

export function hasSessionNsec(): boolean {
  return !!getSessionNsec();
}

/// Bech32 npub for the stored session nsec, or null if absent/malformed.
/// Used to verify the cached nsec belongs to the signed-in patron before
/// signing an inline proof with it.
export function sessionNsecNpub(): string | null {
  try {
    const pk = getPublicKey(getSessionNsecBytes());
    return nip19.npubEncode(pk);
  } catch {
    return null;
  }
}
