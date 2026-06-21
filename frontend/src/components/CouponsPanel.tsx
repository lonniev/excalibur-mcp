// My Coupons — patron-side redemption surface, folded in from optionality.
// Operators distribute discount codes off-network; redeem once here and the
// wheel auto-applies the discount on subsequent paid tool calls.

import { useEffect, useState } from "react";
import { Loader2 } from "lucide-react";
import { forgetCoupon, listMyCoupons, redeemCoupon, type PatronCoupon } from "../lib/mcp";

const card = "rounded-xl border border-stone-200 dark:border-zinc-800 bg-white dark:bg-zinc-900";

export default function CouponsPanel() {
  const [coupons, setCoupons] = useState<PatronCoupon[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [redeeming, setRedeeming] = useState(false);
  const [msg, setMsg] = useState<{ tone: "ok" | "err"; text: string } | null>(null);

  async function refresh() {
    setLoading(true);
    setLoadError(null);
    try {
      const r = await listMyCoupons();
      setCoupons(r.coupons ?? []);
    } catch (e) {
      setLoadError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void refresh(); }, []);

  async function onRedeem() {
    const trimmed = code.trim();
    if (!trimmed) return;
    setRedeeming(true);
    setMsg(null);
    try {
      const r = await redeemCoupon(trimmed);
      if (r.success) {
        setMsg({
          tone: "ok",
          text: `${r.name}: ${r.discount_percent}% off${
            r.uses_remaining != null ? ` — ${r.uses_remaining} use${r.uses_remaining === 1 ? "" : "s"} left` : ""
          }.`,
        });
        setCode("");
        void refresh();
      } else {
        setMsg({ tone: "err", text: r.error ?? "Couldn't redeem that code." });
      }
    } catch (e) {
      setMsg({ tone: "err", text: (e as Error).message });
    } finally {
      setRedeeming(false);
    }
  }

  async function onForget(couponId: string) {
    if (!window.confirm("Remove this coupon from your list? You can re-redeem the code later while the window allows.")) return;
    try {
      await forgetCoupon(couponId);
      setCoupons((cs) => cs.filter((c) => c.coupon_id !== couponId));
    } catch (e) {
      setMsg({ tone: "err", text: (e as Error).message });
    }
  }

  return (
    <div className={`${card} p-5`}>
      <div className="text-sm font-medium mb-1">My coupons</div>
      <p className="text-xs text-stone-500 dark:text-zinc-400 mb-4">
        Redeem an operator code once. The discount applies automatically on subsequent paid
        calls until the per-patron cap or the window expires.
      </p>

      <div className="flex gap-2 mb-3">
        <input
          type="text"
          value={code}
          onChange={(e) => setCode(e.target.value.toUpperCase())}
          onKeyDown={(e) => { if (e.key === "Enter") void onRedeem(); }}
          placeholder="FRESHMAN, EARLYBIRD…"
          autoCapitalize="characters"
          autoCorrect="off"
          spellCheck={false}
          disabled={redeeming}
          className="flex-1 rounded-lg px-3 py-2 text-sm uppercase bg-white dark:bg-zinc-950 border border-stone-300 dark:border-zinc-700 focus:outline-none focus:border-amber-400"
        />
        <button
          onClick={() => void onRedeem()}
          disabled={redeeming || !code.trim()}
          className="bg-amber-600 hover:bg-amber-500 text-white text-sm px-4 py-2 rounded-lg disabled:opacity-40 transition-colors whitespace-nowrap"
        >
          {redeeming ? "Redeeming…" : "🎟 Redeem"}
        </button>
      </div>

      {msg && (
        <div className={`rounded-lg p-2.5 mb-3 text-xs ${
          msg.tone === "ok"
            ? "bg-green-50 border border-green-200 text-green-700 dark:bg-green-500/10 dark:border-green-500/30 dark:text-green-400"
            : "bg-red-50 border border-red-200 text-red-700 dark:bg-red-500/10 dark:border-red-500/30 dark:text-red-400"
        }`}>
          {msg.text}
        </div>
      )}

      {loading ? (
        <div className="flex items-center gap-1.5 text-xs text-stone-400 dark:text-zinc-500 py-2"><Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading…</div>
      ) : loadError ? (
        <div className="rounded-lg p-2.5 text-xs bg-red-50 border border-red-200 text-red-700 dark:bg-red-500/10 dark:border-red-500/30 dark:text-red-400">{loadError}</div>
      ) : coupons.length === 0 ? (
        <p className="text-xs text-stone-400 dark:text-zinc-500 leading-relaxed">
          No coupons redeemed yet. Operators distribute codes via X, email, the welcome page, or DM —
          paste a code above to claim its discount.
        </p>
      ) : (
        <ul className="divide-y divide-stone-100 dark:divide-zinc-800">
          {coupons.map((c) => <CouponRow key={c.coupon_id} coupon={c} onForget={() => void onForget(c.coupon_id)} />)}
        </ul>
      )}
    </div>
  );
}

function CouponRow({ coupon, onForget }: { coupon: PatronCoupon; onForget: () => void }) {
  const isActive = coupon.status === "active";
  const statusLabel = (() => {
    switch (coupon.status) {
      case "active": return "Active";
      case "window_closed": return "Expired";
      case "window_not_started": return "Not yet active";
      case "patron_limit": return "All uses claimed";
      case "total_limit": return "Fully claimed";
      default: return coupon.status;
    }
  })();
  const usesText = coupon.uses_per_patron == null
    ? "∞ uses"
    : `${coupon.uses_remaining ?? 0} of ${coupon.uses_per_patron} use${coupon.uses_per_patron === 1 ? "" : "s"} left`;
  const days = Math.max(0, Math.ceil((new Date(coupon.valid_until).getTime() - Date.now()) / 86_400_000));

  return (
    <li className="flex items-center gap-3 py-2.5">
      <div className="flex-1 min-w-0">
        <div className="flex items-baseline gap-2">
          <span className="font-mono text-sm">{coupon.name}</span>
          <span className="text-sm font-semibold text-amber-600 dark:text-amber-400">{coupon.discount_percent}% off</span>
        </div>
        <div className="text-xs text-stone-400 dark:text-zinc-500 mt-0.5">
          <span className={isActive ? "text-green-600 dark:text-green-400" : ""}>{statusLabel}</span>
          {" · "}{usesText}
          {isActive && <>{" · "}{days === 0 ? "expires today" : `expires in ${days} day${days === 1 ? "" : "s"}`}</>}
        </div>
      </div>
      <button
        onClick={onForget}
        title="Remove from your list (re-redeemable later while the window allows)"
        className="text-stone-400 hover:text-red-500 dark:text-zinc-500 dark:hover:text-red-400 text-sm px-2 py-1 transition-colors"
      >
        🗑
      </button>
    </li>
  );
}
