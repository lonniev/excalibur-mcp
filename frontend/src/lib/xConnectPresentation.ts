// X account card presentation — must agree with Account health's composeOauthRow.
//
// The Profile screen used to show a sticky green "Connected" whenever a token
// record existed, while Account health (composeOauthRow) reported BLOCKED when
// the access token was expired. This module is the single source for the X
// account card's badge/body so the two surfaces cannot disagree.

import type { StatusLevel } from "@tollbooth-dpyc/web";
import { composeOauthRow, type OauthInput } from "./fundingStatus.ts";
import { tr } from "../i18n/index.ts";

export interface XConnectedPresentation {
  level: StatusLevel;
  /** Short status chip text (e.g. "Connected · @handle"). */
  badge: string;
  /** Body copy under the title. */
  body: string;
}

/**
 * Present a linked X account for the Profile X-account card.
 * `handle` is optional display handle, with or without a leading `@`.
 */
export function presentXConnectedCard(
  expiresInSec: number | null | undefined,
  handle = "",
): XConnectedPresentation {
  const oauth: OauthInput = {
    kind: "connected",
    expiresInSec: expiresInSec ?? null,
  };
  const row = composeOauthRow(oauth, "");
  const h = normalizeHandle(handle);

  if (row.state === "blocked") {
    // Linked account exists, but the live token is unusable — never say "Connected".
    return {
      level: "blocked",
      badge: h ? tr("lib.xConnectPresentation.linkedExpiredAs", { handle: h }) : tr("lib.xConnectPresentation.linkedExpired"),
      body: tr("lib.fundingStatus.expired"),
    };
  }

  if (row.state === "warning") {
    return {
      level: "warning",
      badge: h ? tr("lib.xConnectPresentation.connectedAs", { handle: h }) : tr("lib.xConnectPresentation.connected"),
      body: h
        ? `${tr("lib.xConnectPresentation.canPostAs", { handle: h })} ${row.detail}`
        : `${tr("lib.xConnectPresentation.canPost")} ${row.detail}`,
    };
  }

  // ok — healthy live token (or unknown expiry; treat as connected without a false renew line)
  const renew =
    expiresInSec != null && expiresInSec > 0
      ? ` ${tr("lib.xConnectPresentation.renews", { duration: fmtDuration(expiresInSec) })}`
      : "";
  return {
    level: "ok",
    badge: h ? tr("lib.xConnectPresentation.connectedAs", { handle: h }) : tr("lib.xConnectPresentation.connected"),
    body: h
      ? `${tr("lib.xConnectPresentation.canPostAs", { handle: h })}${renew}`
      : `${tr("lib.xConnectPresentation.canPost")}${renew}`,
  };
}

function normalizeHandle(handle: string): string {
  const t = handle.trim();
  if (!t) return "";
  return t.startsWith("@") ? t : `@${t}`;
}

function fmtDuration(sec: number): string {
  const h = Math.floor(sec / 3600);
  if (h >= 24) return tr("lib.xConnectPresentation.days", { n: Math.floor(h / 24) });
  if (h >= 1) return tr("lib.xConnectPresentation.hours", { n: h });
  return tr("lib.xConnectPresentation.minutes", { n: Math.max(1, Math.floor(sec / 60)) });
}
