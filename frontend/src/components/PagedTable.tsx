// Shared bits for the Posts and Snippets tables — both mirror Optionality's
// Journal tab: the BE does the ORDER BY + offset pagination, the FE renders
// sortable column headers and First/Prev/Page X of Y/Next/Last controls.

import type { ReactNode } from "react";
import type { SortDir } from "../lib/mcp";

/// A sortable (or static) column header cell. Clicking a sortable header that
/// is already active flips the direction; a new column starts descending.
export function SortHeader({
  label, col, activeCol, dir, onSort, className = "",
}: {
  label: string;
  col?: string; // omit → not sortable
  activeCol: string;
  dir: SortDir;
  onSort: (col: string, dir: SortDir) => void;
  className?: string;
}) {
  const active = col && col === activeCol;
  const base = "px-3 py-2 text-left text-[11px] font-mono uppercase tracking-widest text-stone-400 dark:text-zinc-500";
  if (!col) return <th className={`${base} ${className}`}>{label}</th>;
  return (
    <th className={`${base} ${className}`}>
      <button
        onClick={() => onSort(col, active && dir === "desc" ? "asc" : "desc")}
        className={`inline-flex items-center gap-1 hover:text-amber-600 dark:hover:text-amber-400 transition-colors ${active ? "text-amber-600 dark:text-amber-400" : ""}`}
      >
        {label}
        {active && <span aria-hidden>{dir === "desc" ? "▾" : "▴"}</span>}
      </button>
    </th>
  );
}

/// First / ← Prev / Page N of M · K total / Next → / Last footer. Hidden when
/// there is only a single page of results.
export function PageControls({
  page, pageSize, total, onPage,
}: {
  page: number;
  pageSize: number;
  total: number;
  onPage: (p: number) => void;
}) {
  const lastPage = Math.max(0, Math.ceil(total / pageSize) - 1);
  const btn = "px-2.5 py-1 rounded-lg text-stone-500 enabled:hover:bg-stone-100 disabled:opacity-30 dark:text-zinc-400 dark:enabled:hover:bg-zinc-800 transition-colors";
  return (
    <div className="flex items-center justify-center gap-2 mt-4 text-xs">
      <button className={btn} disabled={page === 0} onClick={() => onPage(0)} title="First page">⏮</button>
      <button className={btn} disabled={page === 0} onClick={() => onPage(Math.max(0, page - 1))}>← Prev</button>
      <span className="text-stone-400 dark:text-zinc-500 tabular-nums">
        Page {Math.min(page + 1, lastPage + 1)} of {lastPage + 1} · {total} total
      </span>
      <button className={btn} disabled={page >= lastPage} onClick={() => onPage(page + 1)}>Next →</button>
      <button className={btn} disabled={page >= lastPage} onClick={() => onPage(lastPage)} title="Last page">⏭</button>
    </div>
  );
}

/// A thin wrapper so both pages frame their table identically.
export function TableShell({ children }: { children: ReactNode }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-stone-200 dark:border-zinc-800">
      <table className="w-full text-sm">{children}</table>
    </div>
  );
}
