// Run with: node --test frontend/src/lib/occurrences.test.ts
// The cases mirror publisher._advance / upcoming_slot, which the scheduler runs.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { advance, countsOf, occurrencesIn, slotsIn } from "./occurrences.ts";
import type { PostSummary } from "./mcp.ts";

const iso = (ms: number) => new Date(ms).toISOString();
const utc = (y: number, m: number, d: number, h = 0, min = 0) => Date.UTC(y, m - 1, d, h, min);
const post = (over: Partial<PostSummary>): PostSummary => ({
  post_id: "p", status: "scheduled", excerpt: "", publish_at: null, updated_at: null, ...over,
});

describe("advance", () => {
  it("steps daily, weekly and by interval", () => {
    assert.equal(advance(utc(2026, 11, 22, 12), { freq: "daily", interval: 1 }), utc(2026, 11, 23, 12));
    assert.equal(advance(utc(2026, 11, 22, 12), { freq: "daily", interval: 13 }), utc(2026, 12, 5, 12));
    assert.equal(advance(utc(2026, 11, 22, 12), { freq: "weekly" }), utc(2026, 11, 29, 12));
  });

  it("a weekday cadence steps from Friday to Monday, counting days in UTC", () => {
    assert.equal(advance(utc(2026, 11, 20, 9), { freq: "weekdays", interval: 1 }), utc(2026, 11, 23, 9));
    // Friday 20:30 in New York is already Saturday 01:30 UTC: the publisher sees Saturday.
    assert.equal(advance(utc(2026, 11, 21, 1, 30), { freq: "weekdays", interval: 1 }), utc(2026, 11, 23, 1, 30));
  });

  it("a monthly post on the 31st lands on the last day of a shorter month", () => {
    assert.equal(advance(utc(2027, 1, 31, 10), { freq: "monthly", interval: 1 }), utc(2027, 2, 28, 10));
  });

  it("a bad interval counts as one, and an unknown pattern stops", () => {
    assert.equal(advance(utc(2026, 11, 22), { freq: "daily", interval: 0 }), utc(2026, 11, 23));
    assert.equal(advance(utc(2026, 11, 22), { freq: "hourly" }), null);
  });
});

describe("slotsIn", () => {
  const now = utc(2026, 11, 22, 11);
  const from = utc(2026, 11, 1), to = utc(2026, 12, 1);

  it("walks a recurring post from its next slot to the end of the range", () => {
    const p = post({ publish_at: "2026-11-22 12:45:00+00", recurrence: { freq: "weekly", interval: 1 } });
    assert.deepEqual(slotsIn(p, from, to, now).map(iso), ["2026-11-22T12:45:00.000Z", "2026-11-29T12:45:00.000Z"]);
  });

  it("stops at cease_at", () => {
    const p = post({ publish_at: iso(utc(2026, 11, 22, 9)), recurrence: { freq: "daily" }, cease_at: iso(utc(2026, 11, 24, 0)) });
    assert.equal(slotsIn(p, from, to, now).length, 2);
  });

  it("a paused post would rejoin at its first slot after now, not in a burst", () => {
    const p = post({ status: "paused", publish_at: "2026-11-15 15:00:00+00", recurrence: { freq: "weekly" } });
    assert.deepEqual(slotsIn(p, from, to, now).map(iso), ["2026-11-22T15:00:00.000Z", "2026-11-29T15:00:00.000Z"]);
  });

  it("a scheduled slot already past is due now, then the rhythm carries on after now", () => {
    const p = post({ publish_at: "2026-11-15 15:00:00+00", recurrence: { freq: "weekly" } });
    assert.deepEqual(slotsIn(p, from, to, now).map(iso), [iso(now), "2026-11-22T15:00:00.000Z", "2026-11-29T15:00:00.000Z"]);
    const once = post({ publish_at: "2026-11-15 15:00:00+00" });
    assert.deepEqual(slotsIn(once, from, to, now).map(iso), [iso(now)]);
  });

  it("a one-off has just its own slot", () => {
    const p = post({ publish_at: iso(utc(2026, 11, 28, 17)) });
    assert.deepEqual(slotsIn(p, from, to, now).map(iso), ["2026-11-28T17:00:00.000Z"]);
  });
});

describe("occurrencesIn", () => {
  it("puts sent posts where they went out and upcoming ones on their slots, in time order", () => {
    const now = utc(2026, 11, 22, 11);
    const sent = [post({ post_id: "s", status: "sent", last_sent_at: "2026-11-20 14:01:10+00" })];
    const up = [
      post({ post_id: "c", publish_at: "2026-11-22 12:45:00+00", recurrence: { freq: "weekly" } }),
      post({ post_id: "z", status: "paused", publish_at: "2026-11-15 15:00:00+00", recurrence: { freq: "weekly" } }),
    ];
    const occ = occurrencesIn(sent, up, utc(2026, 11, 16), utc(2026, 11, 23), now);
    assert.deepEqual(occ.map((o) => [o.post.post_id, o.kind]), [["s", "sent"], ["c", "coming"], ["z", "paused"]]);
    assert.deepEqual(countsOf(occ), [["sent", 1], ["coming", 1], ["paused", 1]]);
  });
});
