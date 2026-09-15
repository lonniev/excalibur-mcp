// The scheduler's last check, in words — and the Worker agreeing on which ones
// are dead.
// Run with: node --experimental-strip-types --test frontend/src/lib/schedulerCheck.test.ts

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DEAD_CHALLENGE, isDead, lastCheckLine } from "./schedulerCheck.ts";

const NOW = Date.UTC(2026, 8, 15, 12, 0, 0);
const check = (code: string, minsAgo = 12) => ({ at: NOW - minsAgo * 60_000, code });

describe("the last check, as the operator reads it", () => {
  it("says nothing before the Worker has looked", () => {
    assert.equal(lastCheckLine(null, NOW), null);
  });

  it("tells waiting apart from a request that can never complete", () => {
    assert.equal(lastCheckLine(check("courier_not_found"), NOW),
      "Last check 12 min ago: no matching reply on the relay yet.");
    assert.equal(lastCheckLine(check("courier_dpop_token_mismatch", 0), NOW),
      "Last check just now: this request was replaced by a newer one, so it can't complete.");
    assert.equal(isDead(check("courier_not_found")), false);
    assert.equal(isDead(check("courier_token_expired")), true);
  });

  it("shows a code it has no words for as the code, never nothing", () => {
    assert.equal(lastCheckLine(check("something_new", 120), NOW), "Last check 2 h ago: something_new.");
  });
});

describe("the Worker and the page agree on what is dead", () => {
  it("has the same DEAD_CHALLENGE set as scheduler-worker/src/index.ts", () => {
    const src = readFileSync(new URL("../../../scheduler-worker/src/index.ts", import.meta.url), "utf8");
    const block = src.match(/const DEAD_CHALLENGE = new Set\(\[([\s\S]*?)\]\)/)?.[1] ?? "";
    const worker = [...block.matchAll(/"([a-z_]+)"/g)].map((m) => m[1]).sort();
    assert.ok(worker.length > 0, "found the Worker's set");
    assert.deepEqual(worker, [...DEAD_CHALLENGE].sort());
  });
});
