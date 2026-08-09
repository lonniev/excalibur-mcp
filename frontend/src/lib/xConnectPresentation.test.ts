// Pure-logic tests for the X account card presentation.
// Run with: node --experimental-strip-types --test frontend/src/lib/xConnectPresentation.test.ts
//
// Confirms the field-report defect (#369): a stored linkage with an expired
// access token must NOT render as green "Connected".

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { presentXConnectedCard } from "./xConnectPresentation.ts";
import { composeOauthRow } from "./fundingStatus.ts";

const opts = { checkedAt: "2026-08-09T14:55:34.000Z" };

describe("presentXConnectedCard", () => {
  it("does not say Connected when the access token is expired (issue #369)", () => {
    // Reproduce the scout report: linkage @lonniev exists, token expired.
    const card = presentXConnectedCard(0, "@lonniev");
    const health = composeOauthRow({ kind: "connected", expiresInSec: 0 }, opts);

    // Account health already reports blocked — the X card must agree.
    assert.equal(health.state, "blocked");
    assert.equal(card.level, "blocked");
    assert.equal(card.level, health.state);

    // Must not use the healthy "Connected" language.
    assert.doesNotMatch(card.badge, /^Connected\b/i);
    assert.match(card.badge, /token expired/i);
    assert.match(card.badge, /@lonniev/);
    assert.match(card.badge, /Linked/i);
    assert.match(card.body, /expired/i);
    assert.match(card.body, /reconnect/i);
  });

  it("shows Connected in ok state when the token is healthy", () => {
    const card = presentXConnectedCard(7200, "lonniev");
    const health = composeOauthRow({ kind: "connected", expiresInSec: 7200 }, opts);
    assert.equal(health.state, "ok");
    assert.equal(card.level, "ok");
    assert.match(card.badge, /^Connected · @lonniev$/);
    assert.match(card.body, /as @lonniev/);
    assert.match(card.body, /2h/);
  });

  it("warns (not blocked) when the token renews within an hour", () => {
    const card = presentXConnectedCard(30 * 60, "@lonniev");
    const health = composeOauthRow({ kind: "connected", expiresInSec: 30 * 60 }, opts);
    assert.equal(health.state, "warning");
    assert.equal(card.level, "warning");
    assert.match(card.badge, /^Connected/);
  });

  it("treats negative expiry as expired (clock skew / already past)", () => {
    const card = presentXConnectedCard(-120, "@lonniev");
    assert.equal(card.level, "blocked");
    assert.match(card.badge, /token expired/i);
  });
});
