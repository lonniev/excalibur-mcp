// eXcalibur's own funding rows (X account, model router). The package's rows
// (proof, credits, credentials, Authority, Neon, jobs) are tested there.
// Run with: node --test frontend/src/lib/fundingStatus.test.ts

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { composeModelRouterRow, composeOauthRow } from "./fundingStatus.ts";

const CHECKED = "2026-08-05T12:00:00.000Z";

describe("composeOauthRow", () => {
  it("is ok when connected with time left, and stamps checked_at", () => {
    const row = composeOauthRow({ kind: "connected", expiresInSec: 7200 }, CHECKED);
    assert.equal(row.state, "ok");
    assert.equal(row.checked_at, CHECKED);
    assert.match(row.detail, /2h/);
  });

  it("warns when access renews inside the hour", () => {
    assert.equal(composeOauthRow({ kind: "connected", expiresInSec: 600 }, CHECKED).state, "warning");
  });

  it("blocks disconnected X and warns on indeterminate", () => {
    assert.equal(composeOauthRow({ kind: "disconnected" }, CHECKED).state, "blocked");
    assert.equal(composeOauthRow({ kind: "indeterminate", reason: "warming_up" }, CHECKED).state, "warning");
  });

  it("blocks a linked X account when the access token is expired (issue #369)", () => {
    // The field-report case: linkage exists (kind connected) but token is dead.
    const row = composeOauthRow({ kind: "connected", expiresInSec: 0 }, CHECKED);
    assert.equal(row.state, "blocked");
    assert.match(row.detail, /expired/i);
    assert.match(row.detail, /reconnect/i);
  });
});

describe("composeModelRouterRow", () => {
  it("acknowledges key presence without inventing a credit balance", () => {
    const row = composeModelRouterRow({ configured: [{ field: "llm_api_key" }] }, CHECKED);
    assert.equal(row.state, "ok");
    assert.match(row.detail, /llm_api_key is configured/i);
    assert.match(row.detail, /provider dashboard/i);
    assert.doesNotMatch(row.detail, /\b(price|prices|cost|rate|rates)\b/i);
  });

  it("warns when llm_api_key is only optional_missing", () => {
    const row = composeModelRouterRow({ configured: [], optional_missing: [{ field: "llm_api_key" }] }, CHECKED);
    assert.equal(row.state, "warning");
    assert.match(row.detail, /llm_api_key not delivered/i);
  });

  it("warns when onboarding says nothing about the key", () => {
    assert.equal(composeModelRouterRow({}, CHECKED).state, "warning");
  });
});
