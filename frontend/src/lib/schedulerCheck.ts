// What the scheduler's last look for the operator's reply found, in words.
//
// The Worker used to discard this: every failed check read "Awaiting operator
// reply", so a reply that could NEVER be matched looked exactly like one not yet
// sent, and the operator was left approving DMs into a request that was already
// dead. The codes are the SDK's (`tollbooth.constants.ErrorCode`); the Worker
// keeps the last one it got.

import type { SchedulerLastCheck } from "./mcp";
import { shortNpub } from "@tollbooth-dpyc/web";

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
  if (!viewer?.npub) return `Waiting on the operator, ${op}.`;
  return `Waiting on the operator, ${op} — you're signed in as ${whoIs(viewer.npub, viewer.name)}.`;
}

/// Codes meaning THIS request can never complete. Mirrors the Worker's
/// `DEAD_CHALLENGE` — on any of these it sends a fresh request by itself on its
/// next check, so the card can say so rather than ask the operator to wait.
export const DEAD_CHALLENGE: ReadonlySet<string> = new Set([
  "courier_no_pending_record",
  "courier_dpop_token_mismatch",
  "courier_token_expired",
  "courier_no_pinned_relay",
]);

const WORDS: Record<string, string> = {
  no_reply: "no reply yet",
  courier_not_found: "no matching reply on the relay yet",
  courier_relay_unreachable: "the relay the request went to did not answer",
  courier_dpop_token_mismatch: "this request was replaced by a newer one, so it can't complete",
  courier_no_pending_record: "the service has lost this request, so it can't complete",
  courier_token_expired: "this request expired, so it can't complete",
  courier_no_pinned_relay: "this request has no relay to read the reply from, so it can't complete",
  secure_courier_unavailable: "the service's courier was not ready",
};

export function isDead(check: SchedulerLastCheck | null | undefined): boolean {
  return !!check && DEAD_CHALLENGE.has(check.code);
}

function ago(ms: number, now: number): string {
  const mins = Math.max(0, Math.round((now - ms) / 60_000));
  if (mins < 1) return "just now";
  if (mins < 90) return `${mins} min ago`;
  return `${Math.round(mins / 60)} h ago`;
}

/// "Last check 12 min ago: no matching reply on the relay yet." — or null when
/// the Worker has not looked yet.
export function lastCheckLine(
  check: SchedulerLastCheck | null | undefined, now: number = Date.now(),
): string | null {
  if (!check) return null;
  const words = WORDS[check.code] ?? check.code;
  return `Last check ${ago(check.at, now)}: ${words}.`;
}
