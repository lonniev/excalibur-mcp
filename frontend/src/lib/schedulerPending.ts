// Owner-private read of what the scheduled-post cron Worker is waiting on.
//
// The Worker (scheduler-worker) can't post on the operator's behalf without a
// fresh npub proof; at ~monthly renewal it DMs the operator a challenge phrase
// and parks in a "pending" state. That phrase is the Device-Grant code: the
// operator approves only if the phrase in the DM matches the one shown here.
//
// This surface is fed from the Worker's own KV — a store an impostor can't
// write — so the code shown here is the LEGIT scheduler's, never an attacker's.
// It's gated: we sign a kind-27235 event with the in-browser session key and
// the Worker returns the phrase only when the signer is the operator npub.
// A non-operator (or an npub-challenge login with no in-browser key) sees
// nothing — the card simply stays hidden.

import { signInlineProof } from "./inlineProof";
import { getSessionNsec } from "./sessionNsec";

// The Worker's public URL (e.g. https://excalibur-scheduler.<acct>.workers.dev).
// Unset in dev / when the FE isn't paired with a Worker → the card stays hidden.
const SCHEDULER_URL = (import.meta.env.VITE_SCHEDULER_URL as string | undefined) ?? "";

// Must match PENDING_U_TAG in scheduler-worker/src/index.ts.
const PENDING_U_TAG = "excalibur_scheduler_pending";

export type SchedulerPending =
  | { phase: "pending"; code: string; reason: string; requestedAt: number }
  | { phase: "active"; expiresAt: number }
  | { phase: "idle" };

/// Fetch the scheduler's pending-authorization state, owner-private. Returns
/// null when there's nothing to show or nothing we can prove: no Worker URL, no
/// in-browser signing key, or the Worker declined (not the operator). Never
/// throws — a quiet null keeps the UI calm, like SchedulerHealth's "unknown".
export async function fetchSchedulerPending(): Promise<SchedulerPending | null> {
  if (!SCHEDULER_URL || !getSessionNsec()) return null;
  try {
    const proof = signInlineProof(PENDING_U_TAG);
    const url = `${SCHEDULER_URL.replace(/\/$/, "")}/pending?proof=${encodeURIComponent(proof)}`;
    const res = await fetch(url, { method: "GET" });
    if (!res.ok) return null; // 401/403 → not the operator, or proof lapsed
    return (await res.json()) as SchedulerPending;
  } catch {
    return null;
  }
}
