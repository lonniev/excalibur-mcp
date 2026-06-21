// Shared content+date filter bar for the Posts and Snippets tables, mirroring
// TaxSort's filter UX: a monospace regex search (submit on Enter or the button —
// no live debounce), a date-field selector + from/to range, and a Clear button
// shown only when a filter is active. Presentational: the parent owns the applied
// state and runs the (server-side) query, so pagination reflects the filtered set.

import { useEffect, useState } from "react";
import { Search, X } from "lucide-react";

export interface DateFieldOption {
  value: string;
  label: string;
}

const field =
  "text-xs rounded-lg border border-stone-200 bg-stone-50 px-2 py-1.5 focus:outline-none focus:border-stone-400 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-200 dark:focus:border-zinc-500";

export default function TableFilter({
  search,
  onSearch,
  dateField,
  dateFieldOptions,
  onDateField,
  dateFrom,
  dateTo,
  onDateFrom,
  onDateTo,
  onClear,
}: {
  search: string;
  onSearch: (text: string) => void;
  dateField: string;
  dateFieldOptions: DateFieldOption[];
  onDateField: (v: string) => void;
  dateFrom: string;
  dateTo: string;
  onDateFrom: (v: string) => void;
  onDateTo: (v: string) => void;
  onClear: () => void;
}) {
  // The box is edited freely and only applied on Enter / the button; keep it in
  // sync when the applied value changes elsewhere (e.g. Clear).
  const [input, setInput] = useState(search);
  useEffect(() => setInput(search), [search]);

  const active = !!(search || dateFrom || dateTo);

  return (
    <div className="mb-4 flex flex-wrap items-center gap-2">
      <div className="flex items-center gap-1">
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") onSearch(input); }}
          placeholder="Search content (regex)…"
          title="Case-insensitive regular expression matched against the content"
          className={`${field} w-56 font-mono`}
        />
        <button
          onClick={() => onSearch(input)}
          title="Search"
          className="inline-flex items-center gap-1 rounded-lg bg-stone-900 px-2.5 py-1.5 text-xs text-white hover:bg-stone-700 dark:bg-zinc-700 dark:hover:bg-zinc-600"
        >
          <Search className="h-3.5 w-3.5" />
        </button>
      </div>

      <div className="flex items-center gap-1 text-xs text-stone-400 dark:text-zinc-500">
        <select
          value={dateField}
          onChange={(e) => onDateField(e.target.value)}
          title="Which date the range filters"
          className={field}
        >
          {dateFieldOptions.map((o) => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>
        <input
          type="date"
          value={dateFrom}
          onChange={(e) => onDateFrom(e.target.value)}
          title="From date (inclusive)"
          className={field}
        />
        <span>–</span>
        <input
          type="date"
          value={dateTo}
          onChange={(e) => onDateTo(e.target.value)}
          title="To date (inclusive)"
          className={field}
        />
      </div>

      {active && (
        <button
          onClick={onClear}
          className="inline-flex items-center gap-1 rounded-lg border border-red-200 px-2 py-1 text-xs text-red-500 hover:text-red-700 dark:border-red-500/30 dark:text-red-400"
        >
          <X className="h-3.5 w-3.5" /> Clear
        </button>
      )}
    </div>
  );
}
