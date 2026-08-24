// Pure-logic tests for the scheduler health derivation.
// Run with: node --experimental-strip-types --test frontend/src/lib/schedulerState.test.ts
//
// The case that motivated these: a Worker whose authorization has lapsed ticks
// on schedule but writes NO run rows (only `process_scheduled_posts` opens one,
// and it never gets that far). Age-based health therefore reported the one
// situation with a known cause and a human waiting on it — "approve me" — as
// the situation with neither: a red "Scheduler stalled".

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { deriveSchedulerState, FRESH_MS, STALE_MS, type AuthPhase } from "./schedulerState.ts";
import type { SchedulerRun } from "./mcp.ts";

const tick = (agoMs: number, extra: Record<string, unknown> = {}): SchedulerRun => ({
  run_at: new Date(Date.now() - agoMs).toISOString(),
  summary: { kind: "tick", processed: 0, ...extra },
});

const health = (runs: SchedulerRun[], phase?: AuthPhase) =>
  deriveSchedulerState(runs, undefined, phase).health;

describe("age-based health, unchanged when the Worker is authorized", () => {
  it("is healthy inside the fresh window", () => {
    assert.equal(health([tick(60_000)], "active"), "healthy");
  });

  it("is quiet once a tick is overdue", () => {
    assert.equal(health([tick(FRESH_MS + 60_000)], "active"), "quiet");
  });

  it("is stalled after three missed ticks", () => {
    assert.equal(health([tick(STALE_MS + 60_000)], "active"), "stalled");
  });

  it("is cutoff when a run opened and never closed", () => {
    assert.equal(health([tick(10 * 60_000, { status: "started" })], "active"), "cutoff");
  });

  it("keeps every verdict when no phase is supplied at all", () => {
    assert.equal(health([tick(STALE_MS + 60_000)]), "stalled");
    assert.equal(health([tick(60_000)]), "healthy");
    assert.equal(health([]), "quiet");
  });
});

describe("a pending authorization explains the silence, so it outranks age", () => {
  it("reports awaiting-approval instead of stalled", () => {
    assert.equal(health([tick(STALE_MS + 60_000)], "pending"), "unauthorized");
  });

  it("reports awaiting-approval instead of quiet", () => {
    assert.equal(health([tick(FRESH_MS + 60_000)], "pending"), "unauthorized");
  });

  it("reports awaiting-approval instead of cutoff", () => {
    assert.equal(health([tick(10 * 60_000, { status: "started" })], "pending"), "unauthorized");
  });

  // The common case: authorization lapsed long enough ago that the ring holds no
  // tick at all. Without the phase this is indistinguishable from a brand-new
  // deployment that has simply never run.
  it("reports awaiting-approval when there are no rows whatsoever", () => {
    assert.equal(health([], "pending"), "unauthorized");
  });

  it("does not fire for an idle Worker holding no request", () => {
    assert.equal(health([tick(STALE_MS + 60_000)], "idle"), "stalled");
  });
});

describe("what the rows still carry while parked", () => {
  // The health verdict changes; the post-level facts must not. A patron parked
  // behind an approval still needs to see which of their posts is stuck.
  it("keeps stuck posts visible", () => {
    const runs: SchedulerRun[] = [
      tick(STALE_MS + 60_000),
      {
        run_at: new Date(Date.now() - (STALE_MS + 30_000)).toISOString(),
        summary: {
          kind: "publication",
          post_id: "abcdef1234",
          outcome: "held",
          reason: "insufficient_balance",
          detail: "Top up to resume.",
        },
      },
    ];
    const state = deriveSchedulerState(runs, undefined, "pending");
    assert.equal(state.health, "unauthorized");
    assert.equal(state.stuck.length, 1);
    assert.equal(state.stuck[0].reason, "insufficient_balance");
  });
});
