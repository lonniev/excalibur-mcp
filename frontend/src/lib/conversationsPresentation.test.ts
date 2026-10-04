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

import {
  DEFAULT_WEIGHTS, lastRunLabel, mergedWeights, weightOverrides, weightsProblem, WEIGHT_FIELDS,
} from "./conversationsPresentation.ts";

describe("weights", () => {
  it("every editor field has a default and vice versa", () => {
    assert.deepEqual(WEIGHT_FIELDS.map((f) => f.key).sort(), Object.keys(DEFAULT_WEIGHTS).sort());
  });
  it("merges overrides over defaults and sends back only the diff", () => {
    const shown = mergedWeights({ need: 10 });
    assert.equal(shown.need, 10);
    assert.equal(shown.band, 15);
    assert.deepEqual(weightOverrides(shown), { need: 10 });
    assert.deepEqual(weightOverrides(mergedWeights(null)), {});
  });
  it("refuses out-of-bounds, non-integers and an inverted band", () => {
    assert.equal(weightsProblem(mergedWeights(null)), null);
    assert.match(weightsProblem(mergedWeights({ need: 101 })) ?? "", /between/);
    assert.match(weightsProblem({ ...mergedWeights(null), need: 1.5 }) ?? "", /whole number/);
    assert.match(weightsProblem(mergedWeights({ followers_min: 30000 })) ?? "", /Band from/);
  });
});

describe("lastRunLabel", () => {
  it("names never, relative time, and posts read", () => {
    const now = Date.parse("2026-10-04T12:00:00Z");
    assert.equal(lastRunLabel(null, null, now), "never");
    assert.equal(lastRunLabel("2026-10-04T11:58:30Z", 54, now), "2 min ago · 54 read");
    assert.equal(lastRunLabel("2026-10-04 09:00:00+00", null, now), "3 h ago");
    assert.equal(lastRunLabel("2026-10-01T12:00:00Z", 0, now), "3 d ago · 0 read");
  });
});

import { normalizePgTimestamp } from "./conversationsPresentation.ts";

describe("normalizePgTimestamp", () => {
  it("turns Neon's Postgres text into something Date.parse accepts", () => {
    assert.equal(normalizePgTimestamp("2026-10-04 19:21:02.344888+00"), "2026-10-04T19:21:02.344888+00:00");
    assert.equal(normalizePgTimestamp("2026-10-04T19:21:02Z"), "2026-10-04T19:21:02Z");
    assert.equal(normalizePgTimestamp("2026-10-04T19:21:02+05:30"), "2026-10-04T19:21:02+05:30");
    assert.ok(!Number.isNaN(Date.parse(normalizePgTimestamp("2026-10-04 19:21:02.344888+00"))));
  });
});
