import { useCallback, useEffect, useState } from "react";
import {
  checkBalance,
  checkPayment,
  purchaseCredits,
  type CheckBalanceResult,
  type PurchaseCreditsResult,
} from "../lib/mcp";

const card = "rounded-xl border border-stone-200 dark:border-zinc-800 bg-white dark:bg-zinc-900";
const primary =
  "bg-amber-600 hover:bg-amber-500 text-white text-sm px-4 py-2 rounded-lg disabled:opacity-40 transition-colors";
const PRESETS = [1000, 5000, 25000];

export default function WalletPage() {
  const [bal, setBal] = useState<CheckBalanceResult | null>(null);
  const [amount, setAmount] = useState(1000);
  const [invoice, setInvoice] = useState<PurchaseCreditsResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [payStatus, setPayStatus] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setBal(await checkBalance());
    } catch (e) {
      setError((e as Error).message);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function buy() {
    setBusy(true);
    setError(null);
    setPayStatus(null);
    try {
      const r = await purchaseCredits(amount);
      if (r.error) setError(r.error);
      else setInvoice(r);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function verifyPayment() {
    if (!invoice?.invoice_id) return;
    setBusy(true);
    setError(null);
    try {
      const r = await checkPayment(invoice.invoice_id);
      setPayStatus(r.message || r.status || "checked");
      if (r.status === "Settled") {
        setInvoice(null);
        await refresh();
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const bolt = invoice?.lightning_invoice || invoice?.payment_request;

  return (
    <div className="max-w-3xl mx-auto px-4 py-6 space-y-5">
      <h1 className="text-lg font-semibold">Wallet</h1>

      <div className={`${card} p-5`}>
        <div className="text-xs text-stone-400 dark:text-zinc-500">Balance</div>
        <div className="text-3xl font-semibold tabular-nums mt-1">
          {bal?.balance_api_sats?.toLocaleString() ?? "—"}
          <span className="text-base font-normal text-stone-400 dark:text-zinc-500"> sats</span>
        </div>
        <div className="flex gap-4 mt-3 text-xs text-stone-500 dark:text-zinc-400">
          <span>deposited {bal?.total_deposited_api_sats?.toLocaleString() ?? "—"}</span>
          <span>consumed {bal?.total_consumed_api_sats?.toLocaleString() ?? "—"}</span>
          <span>{bal?.active_tranches ?? 0} active tranche(s)</span>
        </div>
        {bal?.next_expiration_iso && (
          <div className="mt-1 text-xs text-amber-600 dark:text-amber-400">
            next expiry {new Date(bal.next_expiration_iso).toLocaleString()}
          </div>
        )}
      </div>

      <div className={`${card} p-5`}>
        <div className="text-sm font-medium mb-3">Top up with Lightning</div>
        <div className="flex flex-wrap items-center gap-2 mb-3">
          {PRESETS.map((p) => (
            <button
              key={p}
              onClick={() => setAmount(p)}
              className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
                amount === p
                  ? "bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-400"
                  : "text-stone-500 hover:bg-stone-100 dark:text-zinc-400 dark:hover:bg-zinc-800"
              }`}
            >
              {p.toLocaleString()}
            </button>
          ))}
          <input
            type="number"
            min={1}
            value={amount}
            onChange={(e) => setAmount(Math.max(1, Number(e.target.value) || 0))}
            className="w-28 rounded-lg px-3 py-1.5 text-sm bg-white dark:bg-zinc-950 border border-stone-300 dark:border-zinc-700"
          />
          <span className="text-sm text-stone-400 dark:text-zinc-500">sats</span>
          <button onClick={buy} disabled={busy} className={`${primary} ml-auto`}>
            {busy ? "…" : "Create invoice"}
          </button>
        </div>

        {invoice && (
          <div className="rounded-lg border border-stone-200 dark:border-zinc-800 p-3 space-y-2">
            {bolt && (
              <div className="font-mono text-xs break-all bg-stone-50 dark:bg-zinc-950 rounded p-2">
                {bolt}
              </div>
            )}
            <div className="flex flex-wrap items-center gap-3 text-sm">
              {invoice.checkout_link && (
                <a
                  href={invoice.checkout_link}
                  target="_blank"
                  rel="noreferrer"
                  className="text-amber-600 dark:text-amber-400 hover:underline"
                >
                  Open checkout ↗
                </a>
              )}
              <button onClick={verifyPayment} disabled={busy} className={primary}>
                {busy ? "Checking…" : "I've paid — check"}
              </button>
            </div>
            {payStatus && (
              <div className="text-xs text-stone-500 dark:text-zinc-400">{payStatus}</div>
            )}
          </div>
        )}
      </div>

      {error && (
        <div className="rounded-lg p-3 text-xs bg-red-50 border border-red-200 text-red-700 dark:bg-red-500/10 dark:border-red-500/30 dark:text-red-400">
          {error}
        </div>
      )}

      {bal?.tranches && bal.tranches.length > 0 && (
        <div className={`${card} p-5`}>
          <div className="text-sm font-medium mb-3">Credit tranches</div>
          <ul className="space-y-1.5 text-xs">
            {bal.tranches.map((t) => (
              <li key={t.id} className="flex justify-between text-stone-500 dark:text-zinc-400">
                <span className="tabular-nums">
                  {t.remaining_sats.toLocaleString()} / {t.amount_sats.toLocaleString()} sats
                </span>
                <span>{t.expires_at ? `expires ${new Date(t.expires_at).toLocaleDateString()}` : "no expiry"}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
