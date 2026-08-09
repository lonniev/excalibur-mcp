// Pure-logic tests for the funding/credential status composer.
// Run with: node --experimental-strip-types --test frontend/src/lib/fundingStatus.test.ts
// (no vitest/jest in this package — Node's built-in test runner is enough).

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  composePatronRows,
  composeOperatorRows,
  composeCreditsRow,
  composeOauthRow,
  composeProofRow,
  composeModelRouterRow,
  composeAuthorityRow,
  composeNeonRow,
  composeDurableJobsRow,
  composeBtcpayRow,
  worstState,
  type StatusRow,
} from "./fundingStatus.ts";

const CHECKED = "2026-08-05T12:00:00.000Z";
const NOW = Date.parse(CHECKED);
const opts = { checkedAt: CHECKED, nowMs: NOW };

function byId(rows: StatusRow[], id: string): StatusRow {
  const r = rows.find((x) => x.id === id);
  assert.ok(r, `missing row ${id}`);
  return r!;
}

describe("composePatronRows", () => {
  it("marks zero balance blocked and surfaces checked_at on every row", () => {
    const rows = composePatronRows(
      {
        oauth: { kind: "connected", expiresInSec: 7200 },
        proof: { kind: "session_nsec" },
        balance: { balance_api_sats: 0, active_tranches: 0 },
      },
      opts,
    );
    assert.equal(rows.length, 3);
    for (const r of rows) assert.equal(r.checked_at, CHECKED);
    assert.equal(byId(rows, "api-sats").state, "blocked");
    assert.match(byId(rows, "api-sats").detail, /zero/i);
    assert.equal(byId(rows, "x-oauth").state, "ok");
    assert.equal(byId(rows, "npub-proof").state, "ok");
    assert.equal(worstState(rows), "blocked");
  });

  it("warns when a tranche expires inside the warning window", () => {
    const soon = new Date(NOW + 6 * 60 * 60 * 1000).toISOString(); // 6h
    const row = composeCreditsRow(
      {
        balance_api_sats: 8807,
        next_expiration_iso: soon,
        expiring_within_24h_sats: 6547,
        active_tranches: 2,
      },
      opts,
    );
    assert.equal(row.state, "warning");
    assert.match(row.detail, /6,?547/);
    assert.match(row.detail, /evaporate/i);
    // Never a price (word-boundary so "evaporate"/"sats" don't false-positive).
    assert.doesNotMatch(row.detail, /\b(price|prices|cost|rate|rates)\b/i);
  });

  it("is ok when balance is healthy and expiry is far out", () => {
    const later = new Date(NOW + 10 * 24 * 60 * 60 * 1000).toISOString();
    const row = composeCreditsRow(
      { balance_api_sats: 5000, next_expiration_iso: later, active_tranches: 1 },
      opts,
    );
    assert.equal(row.state, "ok");
  });

  it("blocks disconnected X and warns on indeterminate", () => {
    assert.equal(composeOauthRow({ kind: "disconnected" }, opts).state, "blocked");
    assert.equal(
      composeOauthRow({ kind: "indeterminate", reason: "warming_up" }, opts).state,
      "warning",
    );
  });

  it("blocks a linked X account when the access token is expired (issue #369)", () => {
    // The field-report case: linkage exists (kind connected) but token is dead.
    const row = composeOauthRow({ kind: "connected", expiresInSec: 0 }, opts);
    assert.equal(row.state, "blocked");
    assert.match(row.detail, /expired/i);
    assert.match(row.detail, /reconnect/i);
  });

  it("blocks an expired dm proof and keeps session_nsec ok", () => {
    assert.equal(
      composeProofRow({ kind: "dm_proof", status: "expired", expiresInSec: 0 }, opts).state,
      "blocked",
    );
    assert.equal(composeProofRow({ kind: "session_nsec" }, opts).state, "ok");
    assert.equal(composeProofRow({ kind: "none" }, opts).state, "blocked");
  });

  it("warns on vault_unavailable without sticky state (fresh compose only)", () => {
    const bad = composeCreditsRow(
      { balance_api_sats: 100, vault_unavailable: true, warning: "Vault is not yet available" },
      opts,
    );
    assert.equal(bad.state, "warning");
    // A later successful read produces ok — no residual warning.
    const good = composeCreditsRow({ balance_api_sats: 100, active_tranches: 1 }, opts);
    assert.equal(good.state, "ok");
  });
});

describe("composeOperatorRows", () => {
  it("composes five operator dependencies from existing signals", () => {
    const rows = composeOperatorRows(
      {
        onboarding: {
          ready: true,
          vault_ok: true,
          configured: [
            { field: "btcpay_host" },
            { field: "btcpay_api_key" },
            { field: "btcpay_store_id" },
            { field: "llm_api_key" },
          ],
          missing: [],
        },
        authority: { success: true, balance_api_sats: 12000 },
        lifecycle: { lifecycle: "ready" },
        service: {
          vault_configured: true,
          durable_jobs: {
            detached_executor_active: true,
            detached_executor_resolved: true,
            key_id: "abc",
          },
          async_jobs: { durable_across_recycles: true, backend: "redis" },
        },
      },
      opts,
    );
    assert.equal(rows.length, 5);
    assert.deepEqual(
      rows.map((r) => r.id),
      ["model-router", "authority-balance", "neon-quota", "durable-jobs", "btcpay"],
    );
    assert.equal(worstState(rows), "ok");
    // Model router acknowledges key presence without inventing a credit balance.
    assert.match(byId(rows, "model-router").detail, /llm_api_key is configured/i);
    assert.match(byId(rows, "model-router").detail, /provider dashboard/i);
  });

  it("blocks zero Authority balance and missing BTCPay", () => {
    assert.equal(
      composeAuthorityRow({ success: true, balance_api_sats: 0 }, opts).state,
      "blocked",
    );
    assert.equal(
      composeBtcpayRow(
        {
          configured: [{ field: "btcpay_host" }],
          missing: [{ field: "btcpay_api_key" }, { field: "btcpay_store_id" }],
        },
        opts,
      ).state,
      "blocked",
    );
  });

  it("blocks Neon on quota_exceeded and misconfigured lifecycles", () => {
    assert.equal(
      composeNeonRow(
        { lifecycle: "quota_exceeded", message: "Neon 402" },
        { vault_configured: true },
        { vault_ok: true },
        opts,
      ).state,
      "blocked",
    );
    assert.equal(
      composeNeonRow(
        { lifecycle: "misconfigured" },
        { vault_configured: true },
        { vault_ok: true },
        opts,
      ).state,
      "blocked",
    );
  });

  it("does not treat detached_active alone as healthy", () => {
    // The field report: detached_active proves the object exists, not that
    // dispatch works. Pair with non-durable docket → warning.
    const row = composeDurableJobsRow(
      {
        durable_jobs: {
          detached_executor_active: true,
          detached_executor_resolved: true,
        },
        async_jobs: { durable_across_recycles: false, backend: "memory (default)" },
      },
      opts,
    );
    assert.equal(row.state, "warning");
    assert.match(row.detail, /not durable/i);
  });

  it("warns when llm_api_key is only optional_missing", () => {
    const row = composeModelRouterRow(
      {
        configured: [],
        optional_missing: [{ field: "llm_api_key" }],
      },
      opts,
    );
    assert.equal(row.state, "warning");
    assert.match(row.detail, /llm_api_key not delivered/i);
  });
});
