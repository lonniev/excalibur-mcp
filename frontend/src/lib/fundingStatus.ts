// eXcalibur's own rows on the package's funding panels (`siteRows`): the X
// account a patron posts through, and — for the operator — the model router
// that refine and dynamic blocks need. The sign-in proof, credit balance,
// credentials, Authority balance, Neon and job rows are @tollbooth-dpyc/web's.
// Same rules: no prices, every row derived fresh and stamped when it was read.

import { durationText, type OperatorOnboardingStatus, type StatusLevel, type StatusRow } from "@tollbooth-dpyc/web";
import { tr } from "../i18n/index.ts";

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
    dependency: tr("lib.fundingStatus.xAccount"),
    state,
    detail,
    checked_at: checkedAt,
  });
  if (oauth.kind === "indeterminate") {
    return r(
      "warning",
      oauth.reason
        ? tr("lib.fundingStatus.unverifiedReason", { reason: oauth.reason })
        : tr("lib.fundingStatus.unverified"),
    );
  }
  if (oauth.kind === "disconnected") return r("blocked", tr("lib.fundingStatus.notConnected"));
  const sec = oauth.expiresInSec;
  if (sec != null && sec <= 0) return r("blocked", tr("lib.fundingStatus.expired"));
  if (sec != null && sec < OAUTH_WARNING_WITHIN_SEC) return r("warning", tr("lib.fundingStatus.renewsIn", { duration: durationText(sec) }));
  return r(
    "ok",
    sec != null && sec > 0
      ? tr("lib.fundingStatus.renewsIn", { duration: durationText(sec) })
      : tr("lib.fundingStatus.connected"),
  );
}

const LLM_FIELD = "llm_api_key";

/** The operator's model-router key — presence only; its credit lives with the provider. */
export function composeModelRouterRow(onb: OperatorOnboardingStatus, checkedAt: string): StatusRow {
  const r = (state: StatusLevel, detail: string): StatusRow => ({
    id: "model-router",
    dependency: tr("lib.fundingStatus.modelRouter"),
    state,
    detail,
    checked_at: checkedAt,
  });
  const has = (list: { field: string }[] | undefined) => (list ?? []).some((f) => f.field === LLM_FIELD);
  if (has(onb.configured)) {
    return r("ok", tr("lib.fundingStatus.llmConfigured"));
  }
  if (has(onb.missing) || has(onb.optional_missing)) {
    return r("warning", tr("lib.fundingStatus.llmMissing"));
  }
  return r("warning", tr("lib.fundingStatus.llmUnknown"));
}
