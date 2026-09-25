// Tests for eXcalibur's own clock helpers; the generic zone conversions are
// @tollbooth-dpyc/web's and tested there.
// Run with: node --test frontend/src/lib/timezone.test.ts
//
// #367 — all patron-facing times render/parse in an IANA zone (default Auto).

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { hourInZone } from "@tollbooth-dpyc/web";
import {
  formatPostedShort,
  parseLocalHourParam,
  postsHrefForLocalHour,
  timeOfDayCohortInZone,
} from "./timezone.ts";

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

describe("time-of-day deep-link (Performance → Posts) #506", () => {
  it("parses zero-padded and bare hour query values into 0–23", () => {
    assert.equal(parseLocalHourParam("09"), 9);
    assert.equal(parseLocalHourParam("9"), 9);
    assert.equal(parseLocalHourParam("00"), 0);
    assert.equal(parseLocalHourParam("23"), 23);
  });

  it("rejects missing and out-of-range hour params", () => {
    assert.equal(parseLocalHourParam(null), null);
    assert.equal(parseLocalHourParam(""), null);
    assert.equal(parseLocalHourParam("24"), null);
    assert.equal(parseLocalHourParam("-1"), null);
    assert.equal(parseLocalHourParam("9am"), null);
    assert.equal(parseLocalHourParam("abc"), null);
  });

  it("builds a Posts href that pre-sets the hour filter for a chart bar click", () => {
    // Chart bars deep-link here so Posts can filter last_sent_at by local hour.
    assert.equal(postsHrefForLocalHour(9), "/?hour=09");
    assert.equal(postsHrefForLocalHour(0), "/?hour=00");
    assert.equal(postsHrefForLocalHour(23), "/?hour=23");
    // Invalid hours must not invent a filter.
    assert.equal(postsHrefForLocalHour(24), "/");
    assert.equal(postsHrefForLocalHour(-3), "/");
  });
});
