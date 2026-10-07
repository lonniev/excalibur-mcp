// Run with: node --test frontend/src/lib/readiness.test.ts

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { BADGE_LABEL, flipOf, nextSweepSlot } from "./readiness.ts";

describe("a person flips Draft ↔ Ready; the machine's states are read-only", () => {
  it("draft and scheduled flip into each other", () => {
    assert.equal(flipOf("draft"), "scheduled");
    assert.equal(flipOf("scheduled"), "draft");
  });

  it("paused answers Ready (go again); sending rescues to Draft", () => {
    assert.equal(flipOf("paused"), "scheduled");
    assert.equal(flipOf("sending"), "draft");
  });

  it("resolving, resolved, sent and archived cannot be flipped", () => {
    for (const s of ["resolving", "resolved", "sent", "archived", "nonsense"]) {
      assert.equal(flipOf(s), null, s);
    }
  });

  it("every status the list filters on has a badge label", () => {
    for (const s of ["draft", "scheduled", "resolving", "resolved", "sending", "paused", "sent", "archived"]) {
      assert.ok(BADGE_LABEL[s], s);
    }
    assert.equal(BADGE_LABEL.scheduled, "Ready");
  });
});

describe("a post made Ready without a time gets the next sweep", () => {
  it("rounds up to :30 before the half hour", () => {
    const at = nextSweepSlot(new Date("2026-10-07T14:07:41.000Z"));
    assert.equal(at.toISOString(), "2026-10-07T14:30:00.000Z");
  });

  it("rounds up to the next hour after the half hour", () => {
    const at = nextSweepSlot(new Date("2026-10-07T14:30:00.001Z"));
    assert.equal(at.toISOString(), "2026-10-07T15:00:00.000Z");
  });

  it("an exact slot still moves forward — the sweep for this minute may already have run", () => {
    const at = nextSweepSlot(new Date("2026-10-07T23:30:00.000Z"));
    assert.equal(at.toISOString(), "2026-10-08T00:00:00.000Z");
  });
});
