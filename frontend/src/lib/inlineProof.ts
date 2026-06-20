// Inline kind-27235 identity proof — Tactic 2 in the wheel's
// identity_proof.verify_proof. A fresh signed event per paid tool call,
// scoped to the runtime tool name via the ``u`` tag. The wheel verifies
// the Schnorr signature inline — no relay round-trip, no cached poison.
//
// Bound to: the sender pubkey (must match the claimed npub), the ``u`` tag
// (must match the MCP-namespaced tool, e.g. "excalibur_create_post"), and
// created_at (within ~60s of server time).

import { finalizeEvent } from "nostr-tools";
import { getSessionNsecBytes } from "./sessionNsec";

const PROOF_KIND = 27235;

/// Sign a kind-27235 proof event for ``mcpToolName`` (the slug-prefixed
/// name like ``excalibur_create_post``) using the in-browser session nsec.
/// Returns the JSON-stringified signed event — exactly what verify_proof
/// expects.
export function signInlineProof(mcpToolName: string): string {
  const signed = finalizeEvent(
    {
      kind: PROOF_KIND,
      created_at: Math.floor(Date.now() / 1000),
      tags: [["u", mcpToolName]],
      content: "",
    },
    getSessionNsecBytes(),
  );
  return JSON.stringify(signed);
}
