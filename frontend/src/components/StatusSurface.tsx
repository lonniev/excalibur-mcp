// Uniform status surface — one component, two audiences.
//
// Renders `{dependency, state, detail, checked_at}` rows produced by
// `lib/fundingStatus`. Profile and Wallet both mount this with different
// row sets so "how do I check X" is learned once. Three states only:
//   ok      — working now
//   warning — will stop on a known date / incomplete but not fatal
//   blocked — stopping work now
//
// Every row carries its own checked_at so a stale reading cannot masquerade
// as a live one (the 2026-08-05 misdiagnosis was a badge with no timestamp).

import type { StatusLevel, StatusRow } from "../lib/fundingStatus";
import { worstState } from "../lib/fundingStatus";

const card = "rounded-xl border border-stone-200 dark:border-zinc-800 bg-white dark:bg-zinc-900";

const STATE_STYLES: Record<
  StatusLevel,
  { chip: string; dot: string; label: string }
> = {
  ok: {
    chip: "bg-green-50 text-green-700 dark:bg-green-500/10 dark:text-green-400",
    dot: "bg-green-500",
    label: "ok",
  },
  warning: {
    chip: "bg-amber-50 text-amber-800 dark:bg-amber-500/10 dark:text-amber-400",
    dot: "bg-amber-500",
    label: "warning",
  },
  blocked: {
    chip: "bg-red-50 text-red-700 dark:bg-red-500/10 dark:text-red-400",
    dot: "bg-red-500",
    label: "blocked",
  },
};

function fmtChecked(iso: string): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  return new Date(t).toLocaleString();
}

export default function StatusSurface({
  title,
  subtitle,
  rows,
  loading,
  error,
  emptyHint,
  onRefresh,
}: {
  title: string;
  subtitle?: string;
  rows: StatusRow[];
  loading?: boolean;
  error?: string | null;
  emptyHint?: string;
  onRefresh?: () => void;
}) {
  const overall = rows.length ? worstState(rows) : "ok";
  const overallStyle = STATE_STYLES[overall];

  return (
    <div className={`${card} p-5`}>
      <div className="mb-1 flex flex-wrap items-center gap-2">
        <span className="text-sm font-medium">{title}</span>
        {rows.length > 0 && !loading && (
          <span
            className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium ${overallStyle.chip}`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${overallStyle.dot}`} />
            {overallStyle.label}
          </span>
        )}
        {onRefresh && (
          <button
            type="button"
            onClick={onRefresh}
            disabled={loading}
            className="ml-auto text-xs text-stone-500 hover:text-amber-600 dark:text-zinc-400 dark:hover:text-amber-400 disabled:opacity-40 transition-colors"
          >
            {loading ? "Checking…" : "Refresh"}
          </button>
        )}
      </div>
      {subtitle && (
        <p className="mb-3 text-xs leading-relaxed text-stone-500 dark:text-zinc-400">{subtitle}</p>
      )}

      {loading && rows.length === 0 && (
        <p className="text-xs text-stone-400 dark:text-zinc-500">Checking status…</p>
      )}

      {error && (
        <div className="mb-3 rounded-lg border border-red-200 bg-red-50 p-2.5 text-xs text-red-700 dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-400">
          {error}
        </div>
      )}

      {!loading && !error && rows.length === 0 && (
        <p className="text-xs text-stone-400 dark:text-zinc-500">
          {emptyHint ?? "No status rows."}
        </p>
      )}

      {rows.length > 0 && (
        <ul className="divide-y divide-stone-100 dark:divide-zinc-800">
          {rows.map((r) => {
            const s = STATE_STYLES[r.state];
            return (
              <li key={r.id} className="flex items-start gap-3 py-2.5 first:pt-0 last:pb-0">
                <span
                  className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${s.dot}`}
                  title={s.label}
                  aria-label={s.label}
                />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
                    <span className="text-sm font-medium text-stone-800 dark:text-zinc-100">
                      {r.dependency}
                    </span>
                    <span className={`text-[11px] font-medium uppercase tracking-wide ${s.chip} rounded px-1.5 py-0.5`}>
                      {s.label}
                    </span>
                  </div>
                  <p className="mt-0.5 text-xs leading-relaxed text-stone-500 dark:text-zinc-400">
                    {r.detail}
                  </p>
                  <p className="mt-0.5 text-[10px] tabular-nums text-stone-400 dark:text-zinc-600">
                    checked {fmtChecked(r.checked_at)}
                  </p>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
