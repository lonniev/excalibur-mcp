import { useEffect, useState } from "react";
import { useSession } from "../App";
import { useTheme, type Theme } from "../lib/theme";
import { getAccountStatement, type AccountStatementResult } from "../lib/mcp";
import NostrProfilePanel from "./NostrProfilePanel";
import XConnectPanel from "./XConnectPanel";
import CouponsPanel from "./CouponsPanel";
import BuildLicensePanel from "./BuildLicensePanel";

const card = "rounded-xl border border-stone-200 dark:border-zinc-800 bg-white dark:bg-zinc-900";

const THEMES: { value: Theme; label: string; hint: string }[] = [
  { value: "dark", label: "Dark", hint: "Default" },
  { value: "light", label: "Light", hint: "" },
  { value: "system", label: "System", hint: "Match OS" },
];

export default function ProfilePage() {
  const { npub, status, logOut } = useSession();
  const [theme, setTheme] = useTheme();
  const [stmt, setStmt] = useState<AccountStatementResult | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    getAccountStatement(30).then(setStmt).catch(() => setStmt(null));
  }, []);

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

      {/* X account — per-patron OAuth2 connection (required to post) */}
      <XConnectPanel />

      {/* Theme selection */}
      <div className={`${card} p-5`}>
        <div className="text-sm font-medium mb-1">Appearance</div>
        <p className="text-xs text-stone-500 dark:text-zinc-400 mb-3">
          eXcalibur defaults to dark. Your choice is saved on this device.
        </p>
        <div className="grid grid-cols-3 gap-2">
          {THEMES.map((t) => (
            <button
              key={t.value}
              onClick={() => setTheme(t.value)}
              className={`rounded-lg border px-3 py-3 text-left transition-colors ${
                theme === t.value
                  ? "border-amber-400 bg-amber-50 dark:border-amber-500/50 dark:bg-amber-500/10"
                  : "border-stone-200 dark:border-zinc-800 hover:bg-stone-50 dark:hover:bg-zinc-800"
              }`}
            >
              <div className="flex items-center gap-2">
                <ThemeSwatch theme={t.value} />
                <span className="text-sm font-medium">{t.label}</span>
              </div>
              {t.hint && (
                <span className="block text-xs text-stone-400 dark:text-zinc-500 mt-1">{t.hint}</span>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* Identity */}
      <div className={`${card} p-5`}>
        <div className="text-sm font-medium mb-2">Nostr identity</div>
        <div className="flex items-center gap-2">
          <code className="flex-1 min-w-0 truncate text-xs font-mono text-stone-600 dark:text-zinc-300 bg-stone-50 dark:bg-zinc-950 rounded px-2 py-1.5">
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
      <div className={`${card} p-5`}>
        <div className="text-sm font-medium mb-3">Last 30 days</div>
        {stmt ? (
          <div className="grid grid-cols-3 gap-3 text-center">
            <Stat label="Balance" value={stmt.balance_api_sats} />
            <Stat label="Deposited" value={stmt.total_deposited_api_sats} />
            <Stat label="Consumed" value={stmt.total_consumed_api_sats} />
          </div>
        ) : (
          <p className="text-xs text-stone-400 dark:text-zinc-500">No statement available.</p>
        )}
      </div>

      {/* Coupons */}
      <CouponsPanel />

      {/* Build & license */}
      <BuildLicensePanel status={status} />

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

function Stat({ label, value }: { label: string; value?: number }) {
  return (
    <div>
      <div className="text-lg font-semibold tabular-nums">{value?.toLocaleString() ?? "—"}</div>
      <div className="text-xs text-stone-400 dark:text-zinc-500">{label}</div>
    </div>
  );
}

function ThemeSwatch({ theme }: { theme: Theme }) {
  const base = "w-5 h-5 rounded-full border border-stone-300 dark:border-zinc-600";
  if (theme === "dark") return <span className={`${base} bg-zinc-900`} />;
  if (theme === "light") return <span className={`${base} bg-stone-100`} />;
  return <span className={`${base} bg-gradient-to-r from-stone-100 to-zinc-900`} />;
}
