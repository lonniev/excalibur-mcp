// Profile: the package's AccountPage in eXcalibur's look, with the panels only
// eXcalibur has — the X connection and the account / operator health — right
// after the session key.

import type { ReactNode } from "react";
import type { Theme } from "@tollbooth-dpyc/web";
import { AccountPage, useAppShell } from "@tollbooth-dpyc/web/react";
import {
  accountStyles,
  buildInfoStyles,
  couponStyles,
  themeToggleStyles,
  timezonePickerStyles,
  usageStyles,
} from "../lib/packageStyles";
import XConnectPanel from "./XConnectPanel";
import { PatronFundingStatus, OperatorFundingStatus } from "./FundingStatusPanels";

const THEME_HINTS: Record<Theme, string> = { dark: "Default", light: "", system: "Match OS" };
const THEME_LABELS: Record<Theme, ReactNode> = {
  dark: <ThemeChoice theme="dark" label="Dark" />,
  light: <ThemeChoice theme="light" label="Light" />,
  system: <ThemeChoice theme="system" label="System" />,
};

export default function ProfilePage() {
  const { session, status } = useAppShell();
  return (
    <AccountPage
      npub={session.npub}
      onSignOut={session.signOut}
      classNames={accountStyles}
      between={{
        sessionKey: (
          <>
            <XConnectPanel />
            <PatronFundingStatus />
            <OperatorFundingStatus />
          </>
        ),
      }}
      usage={{ classNames: usageStyles }}
      timezone={{
        heading: "Display timezone",
        intro:
          "All times on Posts, Performance, Scheduler, and Wallet use this zone. Storage stays UTC; only display and filter edges convert. Saved on this device.",
        label: "Zone",
        id: "tz-select",
        autoLabel: (zone) => `Auto (browser) — ${zone}`,
        optionLabel: (o) => `${o.label} — ${o.value}`,
        classNames: timezonePickerStyles,
        note: (pref, zone) =>
          pref === "auto"
            ? `Currently resolving to ${zone}.`
            : `Using ${zone}. Historical posts keep the offset that applied when they were sent.`,
      }}
      theme={{
        intro: "eXcalibur defaults to dark. Your choice is saved on this device.",
        fallback: "dark",
        labels: THEME_LABELS,
        classNames: themeToggleStyles,
      }}
      coupons={{
        classNames: couponStyles,
        intro:
          "Redeem an operator code once. The discount applies automatically on subsequent paid calls until the per-patron cap or the window expires.",
        empty:
          "No coupons redeemed yet. Operators distribute codes via X, email, the welcome page, or DM — paste a code above to claim its discount.",
        placeholder: "FRESHMAN, EARLYBIRD…",
        redeemLabel: "🎟 Redeem",
        forgetLabel: "🗑",
      }}
      build={{
        status,
        frontend: {
          version: __APP_VERSION__,
          commit: __BUILD_COMMIT__,
          builtAt: __BUILD_TIME__,
          source: "https://github.com/lonniev/excalibur-mcp",
        },
        intro: (
          <>
            eXcalibur and Tollbooth-DPYC<sup>™</sup> ship as open source under the Apache License 2.0 —
            anyone can read the code, fork it, run their own operator. The <i>services</i> on top are
            private commerce: each operator sets their own tolls; patrons pre-fund a Lightning balance
            and pay per call. The protocol is shared; the businesses on it are not.
          </>
        ),
        classNames: buildInfoStyles,
      }}
    />
  );
}

function ThemeChoice({ theme, label }: { theme: Theme; label: string }) {
  return (
    <>
      <span className="flex items-center gap-2">
        <ThemeSwatch theme={theme} />
        <span className="text-sm font-medium">{label}</span>
      </span>
      {THEME_HINTS[theme] && (
        <span className="block text-xs text-stone-400 dark:text-zinc-500 mt-1">{THEME_HINTS[theme]}</span>
      )}
    </>
  );
}

function ThemeSwatch({ theme }: { theme: Theme }) {
  const base = "w-5 h-5 rounded-full border border-stone-300 dark:border-zinc-600";
  if (theme === "dark") return <span className={`${base} bg-zinc-900`} />;
  if (theme === "light") return <span className={`${base} bg-stone-100`} />;
  return <span className={`${base} bg-linear-to-r from-stone-100 to-zinc-900`} />;
}
