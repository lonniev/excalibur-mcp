// Pure-logic tests for display-timezone preference + conversions.
// Run with: node --experimental-strip-types --test frontend/src/lib/timezone.test.ts
//
// #367 — all patron-facing times render/parse in an IANA zone (default Auto).

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import {
  datetimeLocalValueToIso,
  formatPostedShort,
  getZonedParts,
  hourInZone,
  isoToDatetimeLocalValue,
  localDateFilterBounds,
  resolveTimeZone,
  startOfLocalDayIso,
  startOfNextLocalDayIso,
  timeOfDayCohortInZone,
  zonedWallTimeToUtcMs,
} from "./timezone.ts";

// Minimal localStorage so read/write helpers don't throw under node:test.
const store = new Map<string, string>();
before(() => {
  // @ts-expect-error test shim
  globalThis.window = {
    localStorage: {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => {
        store.set(k, v);
      },
      removeItem: (k: string) => {
        store.delete(k);
      },
    },
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => true,
  };
  // @ts-expect-error test shim
  globalThis.localStorage = globalThis.window.localStorage;
});
after(() => {
  store.clear();
});

describe("resolveTimeZone", () => {
  it("passes through an explicit IANA zone", () => {
    assert.equal(resolveTimeZone("America/New_York"), "America/New_York");
    assert.equal(resolveTimeZone("UTC"), "UTC");
  });
});

describe("zoned wall time ↔ UTC (DST-aware)", () => {
  it("maps America/New_York winter wall time to the correct UTC instant", () => {
    // 2026-01-15 12:00 EST = UTC-5 → 17:00Z
    const ms = zonedWallTimeToUtcMs(2026, 1, 15, 12, 0, 0, "America/New_York");
    assert.equal(new Date(ms).toISOString(), "2026-01-15T17:00:00.000Z");
  });

  it("maps America/New_York summer wall time to the correct UTC instant", () => {
    // 2026-07-15 12:00 EDT = UTC-4 → 16:00Z
    const ms = zonedWallTimeToUtcMs(2026, 7, 15, 12, 0, 0, "America/New_York");
    assert.equal(new Date(ms).toISOString(), "2026-07-15T16:00:00.000Z");
  });

  it("round-trips ISO through datetime-local in a non-UTC zone", () => {
    const iso = "2026-01-15T17:00:00.000Z";
    const local = isoToDatetimeLocalValue(iso, "America/New_York");
    assert.equal(local, "2026-01-15T12:00");
    const back = datetimeLocalValueToIso(local, "America/New_York");
    assert.equal(back, iso);
  });

  it("renders a winter send in the offset that applied at send time (not 'now')", () => {
    // Viewed any time of year, a January send in NY is EST (UTC-5).
    const parts = getZonedParts(new Date("2026-01-15T17:00:00.000Z"), "America/New_York");
    assert.equal(parts.hour, 12);
    assert.equal(parts.month, 1);
  });
});

describe("local day filter bounds", () => {
  it("converts a New York calendar day into UTC instants spanning that local day", () => {
    // 2026-08-01 in America/New_York (EDT, UTC-4):
    //   start 00:00 EDT = 04:00Z
    //   next  00:00 EDT = 04:00Z next day
    const start = startOfLocalDayIso("2026-08-01", "America/New_York");
    const next = startOfNextLocalDayIso("2026-08-01", "America/New_York");
    assert.equal(start, "2026-08-01T04:00:00.000Z");
    assert.equal(next, "2026-08-02T04:00:00.000Z");

    const bounds = localDateFilterBounds("2026-08-01", "2026-08-01", "America/New_York");
    assert.equal(bounds.dateFrom, start);
    assert.equal(bounds.dateTo, next);
  });

  it("uses UTC midnight when the zone is UTC", () => {
    assert.equal(startOfLocalDayIso("2026-08-01", "UTC"), "2026-08-01T00:00:00.000Z");
    assert.equal(startOfNextLocalDayIso("2026-08-01", "UTC"), "2026-08-02T00:00:00.000Z");
  });
});

describe("time-of-day cohort computed in the patron zone (not UTC-relabeled)", () => {
  it("buckets by local hour so a UTC-14 send near a TZ edge lands on the local hour", () => {
    // 14:30 UTC on 2026-08-01 = 10:30 America/New_York (EDT).
    // Relabeling the UTC key "14" by a fixed offset is the bug #367 forbids;
    // computing from the instant puts it in local hour 10.
    const posts = [
      { last_sent_at: "2026-08-01T14:30:00.000Z", latest_impressions: 200 },
      { last_sent_at: "2026-08-01T14:10:00.000Z", latest_impressions: 100 },
      { last_sent_at: "2026-08-01T05:00:00.000Z", latest_impressions: 40 }, // 01:00 EDT
    ];
    const cohort = timeOfDayCohortInZone(posts, "America/New_York");
    assert.equal(cohort["10"]?.n, 2);
    assert.equal(cohort["10"]?.median, 150);
    assert.equal(cohort["01"]?.n, 1);
    assert.equal(cohort["01"]?.median, 40);
    // Must NOT appear under the UTC hour key.
    assert.equal(cohort["14"], undefined);
  });

  it("keeps January and July sends in their own DST offsets when bucketed", () => {
    // Both are 17:00Z; NY hour is 12 in January (EST) and 13 in July (EDT).
    assert.equal(hourInZone("2026-01-15T17:00:00.000Z", "America/New_York"), 12);
    assert.equal(hourInZone("2026-07-15T17:00:00.000Z", "America/New_York"), 13);
    const cohort = timeOfDayCohortInZone(
      [
        { last_sent_at: "2026-01-15T17:00:00.000Z", latest_impressions: 10 },
        { last_sent_at: "2026-07-15T17:00:00.000Z", latest_impressions: 20 },
      ],
      "America/New_York",
    );
    assert.equal(cohort["12"]?.n, 1);
    assert.equal(cohort["13"]?.n, 1);
  });
});

describe("formatPostedShort", () => {
  it("includes the zone's wall clock, not a bare UTC dump", () => {
    const s = formatPostedShort("2026-01-15T17:00:00.000Z", "America/New_York");
    // en-US short: "Jan 15, 12:00 PM" (exact locale punctuation may vary slightly)
    assert.match(s, /Jan/);
    assert.match(s, /15/);
    assert.match(s, /12:00/);
  });
});
