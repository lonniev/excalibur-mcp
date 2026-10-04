// Pure-logic tests for the Leads page presentation.
// Run with: node --experimental-strip-types --test frontend/src/lib/conversationsPresentation.test.ts

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  compactCount, runSummary, scoreTone, statusCounts, STATUSES,
} from "./conversationsPresentation.ts";

describe("scoreTone", () => {
  it("bands at 60 and 30", () => {
    assert.equal(scoreTone(100), "hot");
    assert.equal(scoreTone(60), "hot");
    assert.equal(scoreTone(59), "warm");
    assert.equal(scoreTone(30), "warm");
    assert.equal(scoreTone(29), "cool");
    assert.equal(scoreTone(0), "cool");
  });
});

describe("statusCounts", () => {
  it("tallies every status and keeps zeros", () => {
    const counts = statusCounts([
      { status: "new" }, { status: "new" }, { status: "engaged" },
    ]);
    assert.deepEqual(counts, { new: 2, seen: 0, engaged: 1, dismissed: 0 });
    assert.deepEqual(Object.keys(counts), [...STATUSES]);
  });
});

describe("compactCount", () => {
  it("shortens thousands and millions, keeps small numbers, dashes null", () => {
    assert.equal(compactCount(980), "980");
    assert.equal(compactCount(1000), "1k");
    assert.equal(compactCount(12345), "12.3k");
    assert.equal(compactCount(2_000_000), "2M");
    assert.equal(compactCount(null), "—");
  });
});

describe("runSummary", () => {
  it("reads counts and names the truncation", () => {
    assert.equal(runSummary({ posts_read: 120, new: 7, refreshed: 3 }), "120 read · 7 new · 3 refreshed");
    assert.match(runSummary({ posts_read: 1, truncated_reason: "rate_limited" }), /X paused us/);
    assert.match(runSummary({ posts_read: 300, truncated_reason: "max_posts" }), /more available/);
    assert.equal(runSummary({}), "0 read · 0 new · 0 refreshed");
  });
});
