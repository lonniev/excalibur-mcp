// Nostr profile panel presentation — pure helpers for the Profile UX contract
// (#378): single-avatar chrome, collapsible fields, and a non-disabled
// "How to set…" control in read-only mode.
//
// Kept free of React so the acceptance rules can be unit-tested under node:test.
// Truncation mirrors Avatar.shortNpub (first 8 + last 4) so this module stays
// importable from node:test without pulling the React Avatar component.

export type PublishControlMode = "publish" | "how-to-set";

/** Read-only (no session key / NIP-07) → explain; otherwise publish. */
export function publishControlMode(canSign: boolean): PublishControlMode {
  return canSign ? "publish" : "how-to-set";
}

/** Label for the primary action under the profile fields. */
export function publishControlLabel(
  mode: PublishControlMode,
  publishing: boolean,
): string {
  if (mode === "how-to-set") return "How to set…";
  return publishing ? "Publishing…" : "Publish to Nostr";
}

/**
 * Whether the primary action is disabled.
 * "How to set…" must NEVER be disabled — disabled elements do not fire
 * pointer events, so a handler on one never runs (and hover is unavailable
 * on iPad). Only the real publish path disables while in-flight.
 */
export function publishControlDisabled(
  mode: PublishControlMode,
  publishing: boolean,
): boolean {
  if (mode === "how-to-set") return false;
  return publishing;
}

/** Collapsed-header identity line: display name or a fallback title. */
export function collapsedDisplayName(displayName: string): string {
  const t = displayName.trim();
  return t || "Nostr profile";
}

/** Truncated npub for the collapsed header (copy-on-click target). */
export function collapsedNpubLabel(npub: string): string {
  if (!npub) return "";
  return npub.length <= 16 ? npub : `${npub.slice(0, 8)}…${npub.slice(-4)}`;
}

/** Copy shown when the read-only "How to set…" explainer opens. */
export const HOW_TO_SET_EXPLAINER = {
  title: "How to set your Nostr profile",
  paragraphs: [
    "Nostr identity is a secure keypair. Your profile is owned by the key, not by eXcalibur.",
    "To change it, use your preferred Nostr client — the one that already holds your key.",
    "eXcalibur could accept your nsec directly, but deliberately does not ask for it. Handing a private key to a web frontend is the thing the keypair model exists to avoid.",
  ],
} as const;
