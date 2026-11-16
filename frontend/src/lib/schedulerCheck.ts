// What the scheduler's last look for the operator's reply found, in words.
//
// The Worker used to discard this: every failed check read "Awaiting operator
// reply", so a reply that could NEVER be matched looked exactly like one not yet
// sent, and the operator was left approving DMs into a request that was already
// dead. The codes are the SDK's (`tollbooth.constants.ErrorCode`); the Worker
// keeps the last one it got.

import type { SchedulerLastCheck } from "./mcp";
import { shortNpub } from "@tollbooth-dpyc/web";
import { tr } from "../i18n/index.ts";
import type { MessageKey } from "../i18n/en.ts";

/// An npub as a person reads it: the name its profile publishes, else the
/// shortened npub. Never the empty string for a real npub.
export function whoIs(npub: string, name?: string | null): string {
  const t = (name ?? "").trim();
  return t || shortNpub(npub);
}

/// For a viewer who is not the operator: whose approval the scheduler waits on,
/// and who they are signed in as. The operator-only controls are hidden from
/// them, and the commonest reason for that is being signed in as a different
/// npub than the operator's — which this makes visible at a glance.
export function waitingOnLine(
  operator: { npub: string; name?: string | null },
  viewer: { npub: string; name?: string | null } | null,
): string {
  const op = whoIs(operator.npub, operator.name);
  if (!viewer?.npub) return tr("lib.schedulerCheck.waitingOn", { op });
  return tr("lib.schedulerCheck.waitingOnSignedIn", { op, viewer: whoIs(viewer.npub, viewer.name) });
}

/// Codes meaning THIS request can never complete. Mirrors the Worker's
/// `DEAD_CHALLENGE` — on any of these it sends a fresh request by itself on its
/// next check, so the card can say so rather than ask the operator to wait.
export const DEAD_CHALLENGE: ReadonlySet<string> = new Set([
  "courier_no_pending_record",
  "courier_nonce_mismatch",
  "courier_token_expired",
  "courier_no_pinned_relay",
]);

// What each code means, as a catalog key; the words are read when shown.
const CODE_WORDS: Record<string, MessageKey> = {
  no_reply: "lib.schedulerCheck.code.no_reply",
  courier_not_found: "lib.schedulerCheck.code.courier_not_found",
  courier_relay_unreachable: "lib.schedulerCheck.code.courier_relay_unreachable",
  courier_nonce_mismatch: "lib.schedulerCheck.code.courier_nonce_mismatch",
  courier_no_pending_record: "lib.schedulerCheck.code.courier_no_pending_record",
  courier_token_expired: "lib.schedulerCheck.code.courier_token_expired",
  courier_no_pinned_relay: "lib.schedulerCheck.code.courier_no_pinned_relay",
  secure_courier_unavailable: "lib.schedulerCheck.code.secure_courier_unavailable",
};

export function isDead(check: SchedulerLastCheck | null | undefined): boolean {
  return !!check && DEAD_CHALLENGE.has(check.code);
}

function ago(ms: number, now: number): string {
  const mins = Math.max(0, Math.round((now - ms) / 60_000));
  if (mins < 1) return tr("lib.schedulerCheck.ago.justNow");
  if (mins < 90) return tr("lib.schedulerCheck.ago.minutes", { n: mins });
  return tr("lib.schedulerCheck.ago.hours", { n: Math.round(mins / 60) });
}

/// "Last check 12 min ago: no matching reply on the relay yet." — or null when
/// the Worker has not looked yet.
export function lastCheckLine(
  check: SchedulerLastCheck | null | undefined, now: number = Date.now(),
): string | null {
  if (!check) return null;
  const key = CODE_WORDS[check.code];
  const words = key ? tr(key) : check.code;
  return tr("lib.schedulerCheck.lastCheck", { ago: ago(check.at, now), words });
}
