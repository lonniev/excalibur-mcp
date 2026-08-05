// Funding & credential status — pure composition over existing MCP signals.
//
// The 2026-08-05 outage showed that eXcalibur depends on several things that can
// run dry (api_sats tranches, X OAuth, npub proof, model-router credit, Authority
// balance, Neon, durable jobs, BTCPay) and none of them had a place to be seen
// before a post silently stopped. This module turns the already-available tool
// responses into a uniform list the FE can render on Profile (identity) and
// Wallet (funding), with an operator-only set gated like scheduler_pending.
//
// Constraints (from the field report):
//   1. No prices — balances and expiries only.
//   2. No warning that outlives its cause — every row is derived fresh from the
//      latest tool read; nothing is cached as a sticky badge.
//   3. Compose, don't invent — every input is a field some existing tool already
//      returns (check_balance, session_status/upstream_oauth, check_proof_status,
//      service_status, get_operator_onboarding_status, check_authority_balance).

export type StatusLevel = "ok" | "warning" | "blocked";

export interface StatusRow {
  /** Stable key for React lists + tests. */
  id: string;
  /** Human label shown in the row. */
  dependency: string;
  state: StatusLevel;
  /** One-line explanation; never a price. */
  detail: string;
  /** ISO timestamp of the read that produced this row. */
  checked_at: string;
}

export interface ComposeOpts {
  /** ISO timestamp applied to every row in this composition pass. */
  checkedAt: string;
  /** Wall-clock ms used for "expires within N" math (injectable for tests). */
  nowMs?: number;
}

// A tranche (or proof) expiring within this window is a warning, not ok.
export const WARNING_WITHIN_MS = 48 * 60 * 60 * 1000;
// Access-token renew window — under an hour means reconnect soon.
export const OAUTH_WARNING_WITHIN_SEC = 60 * 60;

// ─── inputs (mirror the MCP shapes we actually read) ─────────────────────────

export interface BalanceInput {
  balance_api_sats?: number;
  next_expiration_iso?: string;
  expiring_within_24h_sats?: number;
  active_tranches?: number;
  vault_unavailable?: boolean;
  warning?: string;
  error?: string;
}

export interface OauthInput {
  kind: "connected" | "disconnected" | "indeterminate";
  expiresInSec?: number | null;
  reason?: string;
}

export type ProofKind =
  | { kind: "session_nsec" }
  | { kind: "dm_proof"; status: "valid" | "expired" | "unknown"; expiresInSec?: number | null }
  | { kind: "none" };

export interface ServiceStatusInput {
  vault_configured?: boolean;
  durable_jobs?: {
    detached_executor_active?: boolean;
    detached_executor_resolved?: boolean;
    detached_executor_error?: string | null;
    key_id?: string;
  };
  async_jobs?: {
    durable_across_recycles?: boolean;
    backend?: string;
    docket_url_set?: boolean;
  };
}

export interface LifecycleInput {
  lifecycle?: string;
  message?: string;
}

export interface OnboardingField {
  field: string;
  status?: string;
  category?: string;
}

export interface OnboardingInput {
  ready?: boolean;
  configured?: OnboardingField[];
  missing?: OnboardingField[];
  optional_missing?: OnboardingField[];
  summary?: string;
  vault_ok?: boolean;
}

export interface AuthorityBalanceInput {
  success?: boolean;
  balance_api_sats?: number;
  balance_sats?: number;
  error?: string;
}

// ─── helpers ─────────────────────────────────────────────────────────────────

function levelRank(s: StatusLevel): number {
  return s === "blocked" ? 2 : s === "warning" ? 1 : 0;
}

/** Worst state across a set of rows — useful for a section header chip. */
export function worstState(rows: StatusRow[]): StatusLevel {
  let worst: StatusLevel = "ok";
  for (const r of rows) {
    if (levelRank(r.state) > levelRank(worst)) worst = r.state;
  }
  return worst;
}

function fmtDurationSec(sec: number): string {
  if (sec <= 0) return "now";
  const h = Math.floor(sec / 3600);
  if (h >= 48) return `${Math.floor(h / 24)}d`;
  if (h >= 1) return `${h}h`;
  const m = Math.max(1, Math.floor(sec / 60));
  return `${m}m`;
}

function fieldSet(fields: OnboardingField[] | undefined): Set<string> {
  return new Set((fields ?? []).map((f) => f.field));
}

function hasAll(fields: Set<string>, names: string[]): boolean {
  return names.every((n) => fields.has(n));
}

function anyOf(fields: Set<string>, names: string[]): boolean {
  return names.some((n) => fields.has(n));
}

// ─── patron rows ─────────────────────────────────────────────────────────────

/** X / OAuth2 connection — connected, expiring, needs reconnect. */
export function composeOauthRow(oauth: OauthInput, opts: ComposeOpts): StatusRow {
  const checked_at = opts.checkedAt;
  if (oauth.kind === "connected") {
    const sec = oauth.expiresInSec;
    if (sec != null && sec <= 0) {
      return {
        id: "x-oauth",
        dependency: "X account",
        state: "blocked",
        detail: "Access token expired — reconnect to keep posting.",
        checked_at,
      };
    }
    if (sec != null && sec < OAUTH_WARNING_WITHIN_SEC) {
      return {
        id: "x-oauth",
        dependency: "X account",
        state: "warning",
        detail: `Connected — access renews in about ${fmtDurationSec(sec)}.`,
        checked_at,
      };
    }
    return {
      id: "x-oauth",
      dependency: "X account",
      state: "ok",
      detail:
        sec != null && sec > 0
          ? `Connected — access renews in about ${fmtDurationSec(sec)}.`
          : "Connected.",
      checked_at,
    };
  }
  if (oauth.kind === "indeterminate") {
    return {
      id: "x-oauth",
      dependency: "X account",
      state: "warning",
      detail: oauth.reason
        ? `Couldn't verify connection (${oauth.reason}).`
        : "Couldn't verify connection — service may be waking up.",
      checked_at,
    };
  }
  return {
    id: "x-oauth",
    dependency: "X account",
    state: "blocked",
    detail: "Not connected — authorize X before posting.",
    checked_at,
  };
}

/** npub-proof / session identity — lapsed proof drops the patron mid-session. */
export function composeProofRow(proof: ProofKind, opts: ComposeOpts): StatusRow {
  const checked_at = opts.checkedAt;
  if (proof.kind === "session_nsec") {
    return {
      id: "npub-proof",
      dependency: "Sign-in proof",
      state: "ok",
      detail: "Session key signs a fresh proof on every call — no expiry.",
      checked_at,
    };
  }
  if (proof.kind === "none") {
    return {
      id: "npub-proof",
      dependency: "Sign-in proof",
      state: "blocked",
      detail: "No proof on hand — sign in again.",
      checked_at,
    };
  }
  // dm_proof
  if (proof.status === "expired") {
    return {
      id: "npub-proof",
      dependency: "Sign-in proof",
      state: "blocked",
      detail: "Proof has expired — sign in again to resume paid calls.",
      checked_at,
    };
  }
  if (proof.status === "unknown") {
    return {
      id: "npub-proof",
      dependency: "Sign-in proof",
      state: "warning",
      detail: "No server-side proof record — the next paid call may ask you to re-sign.",
      checked_at,
    };
  }
  const sec = proof.expiresInSec;
  if (sec != null && sec * 1000 < WARNING_WITHIN_MS) {
    return {
      id: "npub-proof",
      dependency: "Sign-in proof",
      state: "warning",
      detail: `Proof valid — expires in about ${fmtDurationSec(sec)}.`,
      checked_at,
    };
  }
  return {
    id: "npub-proof",
    dependency: "Sign-in proof",
    state: "ok",
    detail:
      sec != null && sec > 0
        ? `Proof valid — expires in about ${fmtDurationSec(sec)}.`
        : "Proof valid.",
    checked_at,
  };
}

/** api_sats balance + tranche expiry — the damage today is silent evaporation. */
export function composeCreditsRow(bal: BalanceInput, opts: ComposeOpts): StatusRow {
  const checked_at = opts.checkedAt;
  const now = opts.nowMs ?? Date.now();

  if (bal.vault_unavailable) {
    // Live signal only — when the vault answers again this row flips off.
    return {
      id: "api-sats",
      dependency: "api_sats balance",
      state: "warning",
      detail: bal.warning || "Vault unavailable — balance may be stale. Retry shortly.",
      checked_at,
    };
  }
  if (bal.error) {
    return {
      id: "api-sats",
      dependency: "api_sats balance",
      state: "warning",
      detail: bal.error,
      checked_at,
    };
  }

  const balance = bal.balance_api_sats ?? 0;
  if (balance <= 0) {
    return {
      id: "api-sats",
      dependency: "api_sats balance",
      state: "blocked",
      detail: "Balance is zero — top up before paid calls will succeed.",
      checked_at,
    };
  }

  let expiresInMs: number | null = null;
  if (bal.next_expiration_iso) {
    const t = Date.parse(bal.next_expiration_iso);
    if (!Number.isNaN(t)) expiresInMs = t - now;
  }

  if (expiresInMs != null && expiresInMs <= 0) {
    return {
      id: "api-sats",
      dependency: "api_sats balance",
      state: "warning",
      detail: `${balance.toLocaleString()} sats on hand — a tranche is at or past expiry.`,
      checked_at,
    };
  }

  if (
    (expiresInMs != null && expiresInMs < WARNING_WITHIN_MS) ||
    (bal.expiring_within_24h_sats != null && bal.expiring_within_24h_sats > 0)
  ) {
    const expiring = bal.expiring_within_24h_sats;
    const when =
      expiresInMs != null && expiresInMs > 0
        ? `next expiry in about ${fmtDurationSec(Math.floor(expiresInMs / 1000))}`
        : "tranche(s) expire within 24h";
    const howMuch =
      expiring != null && expiring > 0 ? `${expiring.toLocaleString()} sats expiring; ` : "";
    return {
      id: "api-sats",
      dependency: "api_sats balance",
      state: "warning",
      detail: `${balance.toLocaleString()} sats on hand — ${howMuch}${when}. Unused credits evaporate.`,
      checked_at,
    };
  }

  const tranches = bal.active_tranches ?? 0;
  return {
    id: "api-sats",
    dependency: "api_sats balance",
    state: "ok",
    detail: `${balance.toLocaleString()} sats · ${tranches} active tranche${tranches === 1 ? "" : "s"}.`,
    checked_at,
  };
}

export function composePatronRows(
  input: { oauth: OauthInput; proof: ProofKind; balance: BalanceInput },
  opts: ComposeOpts,
): StatusRow[] {
  return [
    composeOauthRow(input.oauth, opts),
    composeProofRow(input.proof, opts),
    composeCreditsRow(input.balance, opts),
  ];
}

// ─── operator rows ───────────────────────────────────────────────────────────

const BTCPAY_FIELDS = ["btcpay_host", "btcpay_api_key", "btcpay_store_id"];
const LLM_FIELD = "llm_api_key";

export function composeModelRouterRow(onb: OnboardingInput, opts: ComposeOpts): StatusRow {
  const checked_at = opts.checkedAt;
  const configured = fieldSet(onb.configured);
  const missing = fieldSet(onb.missing);
  const optionalMissing = fieldSet(onb.optional_missing);

  if (configured.has(LLM_FIELD)) {
    // Presence only — the provider's own credit balance is not exposed by any
    // operator tool today. Saying "ok, key present" without pretending we know
    // the balance is the honest compose of what exists.
    return {
      id: "model-router",
      dependency: "Model router",
      state: "ok",
      detail:
        "llm_api_key is configured. Credit balance lives on the provider dashboard — nothing here can read it yet.",
      checked_at,
    };
  }
  if (missing.has(LLM_FIELD) || optionalMissing.has(LLM_FIELD)) {
    return {
      id: "model-router",
      dependency: "Model router",
      state: "warning",
      detail:
        "llm_api_key not delivered — refine and dynamic blocks will fail until the key is couriered (posting still works).",
      checked_at,
    };
  }
  return {
    id: "model-router",
    dependency: "Model router",
    state: "warning",
    detail: "Couldn't determine llm_api_key state from onboarding.",
    checked_at,
  };
}

export function composeAuthorityRow(bal: AuthorityBalanceInput, opts: ComposeOpts): StatusRow {
  const checked_at = opts.checkedAt;
  if (bal.success === false || bal.error) {
    return {
      id: "authority-balance",
      dependency: "Authority balance",
      state: "warning",
      detail: bal.error || "Authority balance check failed.",
      checked_at,
    };
  }
  const sats = bal.balance_api_sats ?? bal.balance_sats;
  if (sats == null) {
    return {
      id: "authority-balance",
      dependency: "Authority balance",
      state: "warning",
      detail: "Authority did not return a balance figure.",
      checked_at,
    };
  }
  if (sats <= 0) {
    return {
      id: "authority-balance",
      dependency: "Authority balance",
      state: "blocked",
      detail: "Tax balance is zero — patron top-ups cannot be certified until you fund the Authority.",
      checked_at,
    };
  }
  return {
    id: "authority-balance",
    dependency: "Authority balance",
    state: "ok",
    detail: `${sats.toLocaleString()} sats available to certify patron purchases.`,
    checked_at,
  };
}

export function composeNeonRow(
  life: LifecycleInput,
  svc: ServiceStatusInput,
  onb: OnboardingInput,
  opts: ComposeOpts,
): StatusRow {
  const checked_at = opts.checkedAt;
  const lc = (life.lifecycle ?? "").toLowerCase();

  if (lc === "quota_exceeded" || lc === "persistence_quota_exceeded") {
    return {
      id: "neon-quota",
      dependency: "Neon persistence",
      state: "blocked",
      detail: life.message || "Database quota exceeded — paid tools are locked until capacity is restored.",
      checked_at,
    };
  }
  if (lc === "misconfigured" || lc === "persistence_misconfigured") {
    return {
      id: "neon-quota",
      dependency: "Neon persistence",
      state: "blocked",
      detail: life.message || "Persistence misconfigured — repair the database before paid tools will work.",
      checked_at,
    };
  }
  if (lc === "warming_up" || lc === "not_registered" || lc === "no_identity") {
    return {
      id: "neon-quota",
      dependency: "Neon persistence",
      state: "warning",
      detail: life.message || `Operator lifecycle: ${lc}.`,
      checked_at,
    };
  }
  if (svc.vault_configured === false || onb.vault_ok === false) {
    return {
      id: "neon-quota",
      dependency: "Neon persistence",
      state: "blocked",
      detail: "Vault is not configured — operator cannot serve paid calls.",
      checked_at,
    };
  }
  return {
    id: "neon-quota",
    dependency: "Neon persistence",
    state: "ok",
    detail: lc ? `Lifecycle ${lc} — vault reachable.` : "Vault reachable.",
    checked_at,
  };
}

export function composeDurableJobsRow(svc: ServiceStatusInput, opts: ComposeOpts): StatusRow {
  const checked_at = opts.checkedAt;
  const dj = svc.durable_jobs;
  const aj = svc.async_jobs;

  if (!dj && !aj) {
    return {
      id: "durable-jobs",
      dependency: "Durable job dispatch",
      state: "warning",
      detail: "No durable-job diagnostics in service_status.",
      checked_at,
    };
  }

  if (dj?.detached_executor_error) {
    return {
      id: "durable-jobs",
      dependency: "Durable job dispatch",
      state: "blocked",
      detail: `Detached executor error: ${dj.detached_executor_error}`,
      checked_at,
    };
  }

  // detached_active alone is misleading — pair it with resolved + docket durability.
  const active = !!dj?.detached_executor_active;
  const resolved = dj?.detached_executor_resolved !== false;
  const durable = aj?.durable_across_recycles;

  if (active && resolved && durable !== false) {
    return {
      id: "durable-jobs",
      dependency: "Durable job dispatch",
      state: "ok",
      detail: `Detached executor active${dj?.key_id ? ` (key ${dj.key_id})` : ""}${
        aj?.backend ? ` · docket ${aj.backend}` : ""
      }.`,
      checked_at,
    };
  }

  if (active && durable === false) {
    return {
      id: "durable-jobs",
      dependency: "Durable job dispatch",
      state: "warning",
      detail:
        "Executor object exists, but the docket backend is not durable across recycles — long resolves may be lost.",
      checked_at,
    };
  }

  if (!active) {
    return {
      id: "durable-jobs",
      dependency: "Durable job dispatch",
      state: "warning",
      detail:
        "In-process executor only — long dynamic-block resolves run on the front and may be cut off by recycle.",
      checked_at,
    };
  }

  return {
    id: "durable-jobs",
    dependency: "Durable job dispatch",
    state: "warning",
    detail: "Detached executor present but not fully resolved.",
    checked_at,
  };
}

export function composeBtcpayRow(onb: OnboardingInput, opts: ComposeOpts): StatusRow {
  const checked_at = opts.checkedAt;
  const configured = fieldSet(onb.configured);
  const missing = fieldSet(onb.missing);

  if (hasAll(configured, BTCPAY_FIELDS)) {
    return {
      id: "btcpay",
      dependency: "BTCPay",
      state: "ok",
      detail: "Host, store, and API key are configured.",
      checked_at,
    };
  }
  if (anyOf(missing, BTCPAY_FIELDS) || !hasAll(configured, BTCPAY_FIELDS)) {
    const absent = BTCPAY_FIELDS.filter((f) => !configured.has(f));
    return {
      id: "btcpay",
      dependency: "BTCPay",
      state: "blocked",
      detail:
        absent.length > 0
          ? `Missing via Secure Courier: ${absent.join(", ")}.`
          : "BTCPay credentials incomplete.",
      checked_at,
    };
  }
  return {
    id: "btcpay",
    dependency: "BTCPay",
    state: "warning",
    detail: "Couldn't determine BTCPay credential state.",
    checked_at,
  };
}

export function composeOperatorRows(
  input: {
    onboarding: OnboardingInput;
    authority: AuthorityBalanceInput;
    lifecycle: LifecycleInput;
    service: ServiceStatusInput;
  },
  opts: ComposeOpts,
): StatusRow[] {
  return [
    composeModelRouterRow(input.onboarding, opts),
    composeAuthorityRow(input.authority, opts),
    composeNeonRow(input.lifecycle, input.service, input.onboarding, opts),
    composeDurableJobsRow(input.service, opts),
    composeBtcpayRow(input.onboarding, opts),
  ];
}
