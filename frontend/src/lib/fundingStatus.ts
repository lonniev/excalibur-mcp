// eXcalibur's own rows on the package's funding panels (`siteRows`): the X
// account a patron posts through, and — for the operator — the model router
// that refine and dynamic blocks need. The sign-in proof, credit balance,
// credentials, Authority balance, Neon and job rows are @tollbooth-dpyc/web's.
// Same rules: no prices, every row derived fresh and stamped when it was read.

import { durationText, type OperatorOnboardingStatus, type StatusLevel, type StatusRow } from "@tollbooth-dpyc/web";

// Access-token renew window — under an hour means reconnect soon.
export const OAUTH_WARNING_WITHIN_SEC = 60 * 60;

export interface OauthInput {
  kind: "connected" | "disconnected" | "indeterminate";
  expiresInSec?: number | null;
  reason?: string;
}

/** X / OAuth2 connection — connected, expiring, needs reconnect. */
export function composeOauthRow(oauth: OauthInput, checkedAt: string): StatusRow {
  const r = (state: StatusLevel, detail: string): StatusRow => ({
    id: "x-oauth",
    dependency: "X account",
    state,
    detail,
    checked_at: checkedAt,
  });
  if (oauth.kind === "indeterminate") {
    return r(
      "warning",
      oauth.reason
        ? `Couldn't verify connection (${oauth.reason}).`
        : "Couldn't verify connection — service may be waking up.",
    );
  }
  if (oauth.kind === "disconnected") return r("blocked", "Not connected — authorize X before posting.");
  const sec = oauth.expiresInSec;
  if (sec != null && sec <= 0) return r("blocked", "Access token expired — reconnect to keep posting.");
  if (sec != null && sec < OAUTH_WARNING_WITHIN_SEC) return r("warning", `Connected — access renews in about ${durationText(sec)}.`);
  return r("ok", sec != null && sec > 0 ? `Connected — access renews in about ${durationText(sec)}.` : "Connected.");
}

const LLM_FIELD = "llm_api_key";

/** The operator's model-router key — presence only; its credit lives with the provider. */
export function composeModelRouterRow(onb: OperatorOnboardingStatus, checkedAt: string): StatusRow {
  const r = (state: StatusLevel, detail: string): StatusRow => ({
    id: "model-router",
    dependency: "Model router",
    state,
    detail,
    checked_at: checkedAt,
  });
  const has = (list: { field: string }[] | undefined) => (list ?? []).some((f) => f.field === LLM_FIELD);
  if (has(onb.configured)) {
    return r(
      "ok",
      "llm_api_key is configured. Credit balance lives on the provider dashboard — nothing here can read it yet.",
    );
  }
  if (has(onb.missing) || has(onb.optional_missing)) {
    return r(
      "warning",
      "llm_api_key not delivered — refine and dynamic blocks will fail until the key is couriered (posting still works).",
    );
  }
  return r("warning", "Couldn't determine llm_api_key state from onboarding.");
}
