// Patron + operator funding/credential status: the package's panels (proof,
// credits; credentials, Authority balance, Neon, durable jobs — the operator
// panel shows only to the operator npub) plus eXcalibur's own rows — the X
// account on the patron's, the model router on the operator's — in
// eXcalibur's look. Every refresh re-reads the tools, so a warning cannot
// outlive its cause.

import type { StatusLevel, StatusRow } from "@tollbooth-dpyc/web";
import {
  OperatorFundingStatus as SharedOperatorFundingStatus,
  PatronFundingStatus as SharedPatronFundingStatus,
} from "@tollbooth-dpyc/web/react";
import { getOperatorOnboardingStatus } from "@tollbooth-dpyc/web";
import { getXConnection } from "../lib/mcp";
import { composeModelRouterRow, composeOauthRow, type OauthInput } from "../lib/fundingStatus";
import { fundingStyles } from "../lib/packageStyles";
import { tr, useT } from "../i18n";
import type { MessageKey } from "../i18n/en";

const STATE_STYLES: Record<StatusLevel, { chip: string; dot: string }> = {
  ok: { chip: "bg-green-50 text-green-700 dark:bg-green-500/10 dark:text-green-400", dot: "bg-green-500" },
  warning: { chip: "bg-amber-50 text-amber-800 dark:bg-amber-500/10 dark:text-amber-400", dot: "bg-amber-500" },
  blocked: { chip: "bg-red-50 text-red-700 dark:bg-red-500/10 dark:text-red-400", dot: "bg-red-500" },
};

/** The word shown for each state; the state itself stays the wire value. */
const STATE_WORD: Record<StatusLevel, MessageKey> = {
  ok: "ui.fundingStatusPanels.stateOk",
  warning: "ui.fundingStatusPanels.stateWarning",
  blocked: "ui.fundingStatusPanels.stateBlocked",
};

/** A row as eXcalibur always drew it: a state dot, the dependency and its word, detail, stamp. */
function fundingRow(r: StatusRow, checked: string) {
  const s = STATE_STYLES[r.state];
  // Called by the package while it renders, so the words are read now.
  const word = tr(STATE_WORD[r.state]);
  return (
    <>
      <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${s.dot}`} title={word} aria-label={word} />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
          <span className="text-sm font-medium text-stone-800 dark:text-zinc-100">{r.dependency}</span>
          <span className={`text-[11px] font-medium uppercase tracking-wide ${s.chip} rounded px-1.5 py-0.5`}>{word}</span>
        </div>
        <p className="mt-0.5 text-xs leading-relaxed text-stone-500 dark:text-zinc-400">{r.detail}</p>
        <p className="mt-0.5 text-[10px] tabular-nums text-stone-400 dark:text-zinc-600">{tr("ui.fundingStatusPanels.checked", { checked })}</p>
      </div>
    </>
  );
}

function StateChip({ state }: { state: StatusLevel }) {
  const t = useT();
  const s = STATE_STYLES[state];
  return (
    <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium ${s.chip}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
      {t(STATE_WORD[state])}
    </span>
  );
}

const stateLabels = {
  ok: <StateChip state="ok" />,
  warning: <StateChip state="warning" />,
  blocked: <StateChip state="blocked" />,
};

async function xAccountRow(checkedAt: string) {
  const x = await getXConnection();
  const oauth: OauthInput =
    x.kind === "connected"
      ? { kind: "connected", expiresInSec: x.oauth.access_token_expires_in_seconds ?? null }
      : x.kind === "disconnected"
        ? { kind: "disconnected" }
        : { kind: "indeterminate", reason: x.reason };
  return [composeOauthRow(oauth, checkedAt)];
}

async function modelRouterRow(checkedAt: string) {
  const onb = await getOperatorOnboardingStatus().catch((e: Error) => ({ error: e.message }));
  return [composeModelRouterRow(onb, checkedAt)];
}

export function PatronFundingStatus() {
  const t = useT();
  return (
    <SharedPatronFundingStatus
      intro={t("ui.fundingStatusPanels.patronIntro")}
      siteRows={xAccountRow}
      stateLabels={stateLabels}
      renderRow={fundingRow}
      classNames={fundingStyles}
    />
  );
}

export function OperatorFundingStatus() {
  const t = useT();
  return (
    <SharedOperatorFundingStatus
      intro={t("ui.fundingStatusPanels.operatorIntro")}
      siteRows={modelRouterRow}
      stateLabels={stateLabels}
      renderRow={fundingRow}
      classNames={fundingStyles}
    />
  );
}
