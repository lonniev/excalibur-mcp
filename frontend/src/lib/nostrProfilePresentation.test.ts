// Pure-logic tests for Nostr profile panel presentation (#378).
// Run with: node --experimental-strip-types --test frontend/src/lib/nostrProfilePresentation.test.ts
//
// Confirms the three Profile UX acceptance rules:
// 1. Read-only mode uses an enabled "How to set…" control (never disabled).
// 2. Collapsed header surfaces display name + truncated npub + read-only cue.
// 3. Explainer copy states the security posture plainly.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  HOW_TO_SET_EXPLAINER,
  collapsedDisplayName,
  collapsedNpubLabel,
  publishControlDisabled,
  publishControlLabel,
  publishControlMode,
} from "./nostrProfilePresentation.ts";

describe("publishControlMode / label / disabled (#378)", () => {
  it("uses How to set… when the profile is read-only, and never disables it", () => {
    const mode = publishControlMode(false);
    assert.equal(mode, "how-to-set");
    assert.equal(publishControlLabel(mode, false), "How to set…");
    assert.equal(publishControlLabel(mode, true), "How to set…");
    // Critical: must fire on tap/click — disabled elements drop pointer events.
    assert.equal(publishControlDisabled(mode, false), false);
    assert.equal(publishControlDisabled(mode, true), false);
  });

  it("uses Publish to Nostr when a signer is available, disabled only while publishing", () => {
    const mode = publishControlMode(true);
    assert.equal(mode, "publish");
    assert.equal(publishControlLabel(mode, false), "Publish to Nostr");
    assert.equal(publishControlLabel(mode, true), "Publishing…");
    assert.equal(publishControlDisabled(mode, false), false);
    assert.equal(publishControlDisabled(mode, true), true);
  });
});

describe("collapsed header (#378)", () => {
  it("shows the display name, or a fallback when empty", () => {
    assert.equal(collapsedDisplayName("Satoshi"), "Satoshi");
    assert.equal(collapsedDisplayName("  "), "Nostr profile");
    assert.equal(collapsedDisplayName(""), "Nostr profile");
  });

  it("truncates the npub for the collapsed header (copy-on-click target)", () => {
    const npub =
      "npub16qarmz80zwag03nhvgz67903glq9qams632834zy4h3ha3klfycqyn35wf";
    const label = collapsedNpubLabel(npub);
    assert.notEqual(label, npub);
    assert.match(label, /^npub16/);
    assert.match(label, /…/);
    assert.ok(label.length < npub.length);
  });
});

describe("How to set explainer copy (#378)", () => {
  it("states key ownership, client-side edit, and why nsec is not collected", () => {
    const body = HOW_TO_SET_EXPLAINER.paragraphs.join(" ");
    assert.match(HOW_TO_SET_EXPLAINER.title, /How to set/i);
    assert.match(body, /keypair/i);
    assert.match(body, /not by eXcalibur/i);
    assert.match(body, /Nostr client/i);
    assert.match(body, /nsec/i);
    assert.match(body, /deliberately does not/i);
  });
});

describe("NostrProfilePanel source contract (#378)", () => {
  // Structural acceptance — the panel is React and has no component harness
  // here, so we assert the wire-up the pure helpers require.
  it("mounts one Avatar, a focusable Change-avatar badge, collapse, and How to set", async () => {
    const { readFileSync } = await import("node:fs");
    const { fileURLToPath } = await import("node:url");
    const { dirname, join } = await import("node:path");
    const here = dirname(fileURLToPath(import.meta.url));
    const src = readFileSync(join(here, "../components/NostrProfilePanel.tsx"), "utf8");

    const avatarMounts = src.match(/<Avatar\b/g) ?? [];
    assert.equal(avatarMounts.length, 1, "exactly one Avatar on the page");

    assert.match(src, /aria-label=\{showPicker \? "Done changing avatar" : "Change avatar"\}/);
    assert.match(src, /<Camera\b/);
    assert.doesNotMatch(src, />\s*Change avatar\s*</);

    assert.match(src, /aria-expanded=\{expanded\}/);
    assert.match(src, /aria-controls=\{fieldsId\}/);
    assert.match(src, /hidden=\{!expanded\}/);
    assert.match(src, /Read-only/);

    assert.match(src, /publishControlMode/);
    assert.match(src, /publishControlDisabled/);
    assert.match(src, /publishControlLabel/);
    assert.match(src, /HOW_TO_SET_EXPLAINER/);
    // Must not hard-disable publish on !signer — that killed the explainer path.
    assert.doesNotMatch(src, /disabled=\{publishing \|\| !signer\}/);
    assert.match(src, /role="dialog"/);
  });
});
