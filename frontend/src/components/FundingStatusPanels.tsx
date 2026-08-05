// Patron + operator funding/credential status panels.
//
// Composes existing MCP signals into the uniform StatusSurface rows:
//   Patron  — X OAuth, npub-proof expiry, api_sats tranche expiry
//   Operator — model router key, Authority balance, Neon lifecycle,
//              durable-job dispatch, BTCPay credentials
// Operator panel is gated like SchedulerPendingCard: only renders when the
// signed-in npub equals scheduler_status.operator_npub. Every refresh re-reads
// the tools so a warning cannot outlive its cause.

import { useCallback, useEffect, useState } from "react";
import {
  checkAuthorityBalance,
  checkBalance,
  checkProofStatus,
  getOperatorOnboardingStatus,
  getSchedulerStatus,
  getSessionLifecycle,
  getStoredNpub,
  getStoredProof,
  getXConnection,
  serviceStatus,
  type CheckBalanceResult,
} from "../lib/mcp";
import { hasSessionNsec, sessionNsecNpub } from "../lib/sessionNsec";
import {
  composeOperatorRows,
  composePatronRows,
  type OauthInput,
  type ProofKind,
  type StatusRow,
} from "../lib/fundingStatus";
import StatusSurface from "./StatusSurface";

function isSessionKeyLogin(npub: string): boolean {
  try {
    return hasSessionNsec() && sessionNsecNpub() === npub;
  } catch {
    return false;
  }
}

function readProofKind(
  proofStatus: { status?: string; expires_in_seconds?: number | null } | null,
): ProofKind {
  const npub = getStoredNpub();
  if (isSessionKeyLogin(npub)) return { kind: "session_nsec" };
  if (!getStoredProof()) return { kind: "none" };
  if (!proofStatus) return { kind: "dm_proof", status: "unknown" };
  const s = (proofStatus.status ?? "unknown").toLowerCase();
  const status = s === "valid" || s === "expired" ? s : "unknown";
  return {
    kind: "dm_proof",
    status,
    expiresInSec: proofStatus.expires_in_seconds ?? null,
  };
}

export function PatronFundingStatus() {
  const [rows, setRows] = useState<StatusRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    const checkedAt = new Date().toISOString();
    try {
      const npub = getStoredNpub();
      const sessionKey = isSessionKeyLogin(npub);

      const [bal, xconn, proof] = await Promise.all([
        checkBalance().catch((e: Error) => ({ error: e.message }) as CheckBalanceResult),
        getXConnection(),
        sessionKey || !getStoredProof()
          ? Promise.resolve(null)
          : checkProofStatus(npub, getStoredProof()).catch(() => null),
      ]);

      const oauth: OauthInput =
        xconn.kind === "connected"
          ? {
              kind: "connected",
              expiresInSec: xconn.oauth.access_token_expires_in_seconds ?? null,
            }
          : xconn.kind === "disconnected"
            ? { kind: "disconnected" }
            : { kind: "indeterminate", reason: xconn.reason };

      setRows(
        composePatronRows(
          {
            oauth,
            proof: readProofKind(proof),
            balance: bal,
          },
          { checkedAt },
        ),
      );
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return (
    <StatusSurface
      title="Account health"
      subtitle="Connection, sign-in proof, and credit expiry — checked live, never sticky."
      rows={rows}
      loading={loading}
      error={error}
      onRefresh={() => void refresh()}
    />
  );
}

export function OperatorFundingStatus() {
  const [rows, setRows] = useState<StatusRow[]>([]);
  const [visible, setVisible] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    const checkedAt = new Date().toISOString();
    try {
      // Gate first — same discipline as SchedulerPendingCard. A patron must not
      // even fire the operator-only probes (and must not see the panel).
      const sched = await getSchedulerStatus();
      const operator = sched?.operator_npub;
      if (!operator || getStoredNpub() !== operator) {
        setVisible(false);
        setRows([]);
        return;
      }
      setVisible(true);

      const [svc, onb, auth, life] = await Promise.all([
        serviceStatus().catch(() => ({})),
        getOperatorOnboardingStatus().catch(() => ({})),
        checkAuthorityBalance().catch((e: Error) => ({
          success: false as const,
          error: e.message,
        })),
        getSessionLifecycle().catch(() => ({})),
      ]);

      setRows(
        composeOperatorRows(
          {
            onboarding: onb ?? {},
            authority: auth,
            lifecycle: life ?? {},
            service: svc ?? {},
          },
          { checkedAt },
        ),
      );
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Hidden unless the viewer is the operator (no flash for patrons).
  if (!visible) return null;

  return (
    <StatusSurface
      title="Operator dependencies"
      subtitle="Upstream things only you can fix — model router, Authority tax balance, Neon, durable jobs, BTCPay. No prices."
      rows={rows}
      loading={loading}
      error={error}
      onRefresh={() => void refresh()}
    />
  );
}
