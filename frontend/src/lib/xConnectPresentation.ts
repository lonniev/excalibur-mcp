// X account card presentation — must agree with Account health's composeOauthRow.
//
// The Profile screen used to show a sticky green "Connected" whenever a token
// record existed, while Account health (composeOauthRow) reported BLOCKED when
// the access token was expired. This module is the single source for the X
// account card's badge/body so the two surfaces cannot disagree.

import {
  composeOauthRow,
  type OauthInput,
  type StatusLevel,
} from "./fundingStatus.ts";

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
  const row = composeOauthRow(oauth, { checkedAt: "" });
  const h = normalizeHandle(handle);

  if (row.state === "blocked") {
    // Linked account exists, but the live token is unusable — never say "Connected".
    return {
      level: "blocked",
      badge: h ? `Linked · ${h} — token expired` : "Linked — token expired",
      body: "Access token expired — reconnect to keep posting.",
    };
  }

  if (row.state === "warning") {
    return {
      level: "warning",
      badge: h ? `Connected · ${h}` : "Connected",
      body: h
        ? `eXcalibur can post to your X account as ${h}. ${row.detail}`
        : `eXcalibur can post to your X account. ${row.detail}`,
    };
  }

  // ok — healthy live token (or unknown expiry; treat as connected without a false renew line)
  const renew =
    expiresInSec != null && expiresInSec > 0
      ? ` Access renews in about ${fmtDuration(expiresInSec)}.`
      : "";
  return {
    level: "ok",
    badge: h ? `Connected · ${h}` : "Connected",
    body: h
      ? `eXcalibur can post to your X account as ${h}.${renew}`
      : `eXcalibur can post to your X account.${renew}`,
  };
}

function normalizeHandle(handle: string): string {
  const t = handle.trim();
  if (!t) return "";
  return t.startsWith("@") ? t : `@${t}`;
}

function fmtDuration(sec: number): string {
  const h = Math.floor(sec / 3600);
  if (h >= 24) return `${Math.floor(h / 24)}d`;
  if (h >= 1) return `${h}h`;
  return `${Math.max(1, Math.floor(sec / 60))}m`;
}
