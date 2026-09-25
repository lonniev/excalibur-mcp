import { useState, type ReactNode } from "react";
import { useSession } from "../App";
import type { Theme } from "@tollbooth-dpyc/web";
import {
  BuildInfoPanel,
  CouponsPanel,
  NostrProfilePanel,
  SessionKeyClaim,
  ThemeToggle,
  TimezonePicker,
  UsageSummary,
  useTimezone,
} from "@tollbooth-dpyc/web/react";
import {
  buildInfoStyles,
  card,
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
  const { npub, status, logOut } = useSession();
  const [tzPref, tzResolved] = useTimezone();
  const [copied, setCopied] = useState(false);

  function copyNpub() {
    navigator.clipboard?.writeText(npub).then(
      () => {
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1500);
      },
      () => {},
    );
  }

  return (
    <div className="max-w-3xl mx-auto px-4 py-6 space-y-5">
      <h1 className="text-lg font-semibold">Profile</h1>

      {/* Nostr profile (kind-0) — avatar + contact, self-sovereign */}
      <NostrProfilePanel npub={npub} />
      {/* Browser-held session nsec only — silent for NIP-07 / DM sign-ins.
          Keyed by npub so a revealed key never carries across a sign-in. */}
      <SessionKeyClaim key={npub} npub={npub} />

      {/* X account — per-patron OAuth2 connection (required to post) */}
      <XConnectPanel />

      {/* Identity & credential health — OAuth, proof expiry, credits.
          Composed from existing tools; checked_at on every row. */}
      <PatronFundingStatus />

      {/* Operator-only upstream dependencies (gated like scheduler_pending). */}
      <OperatorFundingStatus />

      {/* Theme selection */}
      <div className={`${card} p-5`}>
        <div className="text-sm font-medium mb-1">Appearance</div>
        <p className="text-xs text-stone-500 dark:text-zinc-400 mb-3">
          eXcalibur defaults to dark. Your choice is saved on this device.
        </p>
        <ThemeToggle fallback="dark" labels={THEME_LABELS} classNames={themeToggleStyles} />
      </div>

      {/* Display timezone — IANA zone for every clock on Posts/Performance/Scheduler/Wallet. */}
      <div className={`${card} p-5`}>
        <div className="text-sm font-medium mb-1">Display timezone</div>
        <p className="text-xs text-stone-500 dark:text-zinc-400 mb-3">
          All times on Posts, Performance, Scheduler, and Wallet use this zone. Storage stays UTC;
          only display and filter edges convert. Saved on this device.
        </p>
        <TimezonePicker
          label="Zone"
          id="tz-select"
          autoLabel={(zone) => `Auto (browser) — ${zone}`}
          optionLabel={(o) => `${o.label} — ${o.value}`}
          classNames={timezonePickerStyles}
        />
        <p className="mt-2 text-[11px] text-stone-400 dark:text-zinc-500">
          {tzPref === "auto"
            ? `Currently resolving to ${tzResolved}.`
            : `Using ${tzResolved}. Historical posts keep the offset that applied when they were sent.`}
        </p>
      </div>

      {/* Identity */}
      <div className={`${card} p-5`}>
        <div className="text-sm font-medium mb-2">Nostr identity</div>
        <div className="flex items-center gap-2">
          <code className="flex-1 min-w-0 truncate text-xs font-mono text-stone-600 dark:text-zinc-300 bg-stone-50 dark:bg-zinc-950 rounded-sm px-2 py-1.5">
            {npub}
          </code>
          <button
            onClick={copyNpub}
            className="text-xs px-2.5 py-1.5 rounded-lg border border-stone-300 dark:border-zinc-700 text-stone-500 dark:text-zinc-400 hover:bg-stone-100 dark:hover:bg-zinc-800 transition-colors"
          >
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
      </div>

      {/* Usage */}
      <UsageSummary classNames={usageStyles} />

      {/* Coupons */}
      <CouponsPanel
        classNames={couponStyles}
        intro="Redeem an operator code once. The discount applies automatically on subsequent paid calls until the per-patron cap or the window expires."
        empty="No coupons redeemed yet. Operators distribute codes via X, email, the welcome page, or DM — paste a code above to claim its discount."
        placeholder="FRESHMAN, EARLYBIRD…"
        redeemLabel="🎟 Redeem"
        forgetLabel="🗑"
      />

      {/* Build & license */}
      <BuildInfoPanel
        status={status}
        frontend={{
          version: __APP_VERSION__,
          commit: __BUILD_COMMIT__,
          builtAt: __BUILD_TIME__,
          source: "https://github.com/lonniev/excalibur-mcp",
        }}
        intro={
          <>
            eXcalibur and Tollbooth-DPYC<sup>™</sup> ship as open source under the Apache License 2.0 —
            anyone can read the code, fork it, run their own operator. The <i>services</i> on top are
            private commerce: each operator sets their own tolls; patrons pre-fund a Lightning balance
            and pay per call. The protocol is shared; the businesses on it are not.
          </>
        }
        classNames={buildInfoStyles}
      />

      <div className="flex justify-end">
        <button
          onClick={logOut}
          className="text-sm px-4 py-2 rounded-lg text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-500/10 transition-colors"
        >
          Log out
        </button>
      </div>
    </div>
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
