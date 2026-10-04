import { Loader2, Pencil, Plus, Radar, Shield, ShieldOff, Trash2 } from "lucide-react";
import type { ConversationQueryRow } from "../lib/mcp";
import { lastRunLabel } from "../lib/conversationsPresentation";

/// The patron's saved-query catalog: one row each, with Run / Edit / Delete.
/// Selecting a row filters the leads below to that query.
export default function ConversationQueriesPanel({
  queries, selected, runningId, onSelect, onRun, onEdit, onDelete, onNew,
}: {
  queries: ConversationQueryRow[];
  selected: string;
  runningId: string | null;
  onSelect: (id: string) => void;
  onRun: (q: ConversationQueryRow) => void;
  onEdit: (q: ConversationQueryRow) => void;
  onDelete: (q: ConversationQueryRow) => void;
  onNew: () => void;
}) {
  return (
    <div className="mb-4 rounded-lg border border-stone-200 dark:border-zinc-800">
      <div className="flex items-center border-b border-stone-200 px-3 py-2 dark:border-zinc-800">
        <h2 className="text-sm font-medium text-stone-700 dark:text-zinc-300">Saved queries</h2>
        <span className="ml-2 text-xs text-stone-400 dark:text-zinc-500">{queries.length}/50</span>
        <button
          onClick={onNew}
          className="ml-auto inline-flex items-center gap-1 text-xs text-amber-600 hover:underline dark:text-amber-400"
        >
          <Plus className="h-3.5 w-3.5" /> New
        </button>
      </div>
      {queries.length === 0 ? (
        <p className="px-3 py-4 text-xs text-stone-400 dark:text-zinc-500">
          No saved queries yet — save one to re-run it and read only what's new.
        </p>
      ) : (
        <table className="w-full text-sm">
          <tbody>
            {queries.map((q) => {
              const on = q.id === selected;
              const running = runningId === q.id;
              const tuned = Object.keys(q.weights ?? {}).length;
              return (
                <tr
                  key={q.id}
                  onClick={() => onSelect(on ? "" : q.id)}
                  className={`cursor-pointer border-b border-stone-100 last:border-0 dark:border-zinc-900 ${
                    on ? "bg-amber-50 dark:bg-amber-500/10" : "hover:bg-stone-50 dark:hover:bg-zinc-900/60"
                  }`}
                  title={q.query}
                >
                  <td className="px-3 py-2 align-top font-medium whitespace-nowrap text-stone-800 dark:text-zinc-200">
                    {q.name}
                    {tuned > 0 && (
                      <span className="ml-1.5 rounded-full bg-amber-100 px-1.5 text-[10px] text-amber-800 dark:bg-amber-500/20 dark:text-amber-200">
                        {tuned} tuned
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2 align-top max-w-xl">
                    <code className="block truncate text-xs text-stone-500 dark:text-zinc-400">{q.query}</code>
                  </td>
                  <td className="px-3 py-2 align-top text-stone-400 dark:text-zinc-500" title={q.safe_defaults ? "Safe defaults on" : "Safe defaults off"}>
                    {q.safe_defaults ? <Shield className="h-3.5 w-3.5" /> : <ShieldOff className="h-3.5 w-3.5" />}
                  </td>
                  <td className="px-3 py-2 align-top text-xs whitespace-nowrap text-stone-400 dark:text-zinc-500">
                    {lastRunLabel(q.last_run_at, q.last_run_posts_read)}
                  </td>
                  <td className="px-3 py-2 align-top text-right whitespace-nowrap">
                    <span className="inline-flex gap-2 text-stone-400 dark:text-zinc-500">
                      <button
                        onClick={(e) => { e.stopPropagation(); onRun(q); }}
                        disabled={runningId !== null}
                        title="Run — searches X's last 7 days, newer than the last run"
                        className="hover:text-amber-600 disabled:opacity-40 dark:hover:text-amber-400"
                      >
                        {running ? <Loader2 className="h-4 w-4 animate-spin" /> : <Radar className="h-4 w-4" />}
                      </button>
                      <button onClick={(e) => { e.stopPropagation(); onEdit(q); }} title="Edit" className="hover:text-amber-600 dark:hover:text-amber-400">
                        <Pencil className="h-4 w-4" />
                      </button>
                      <button onClick={(e) => { e.stopPropagation(); onDelete(q); }} title="Delete (its leads are kept)" className="hover:text-red-500">
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}
