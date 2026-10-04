import { useState } from "react";
import { ChevronDown, ChevronRight, RotateCcw, Save, Trash2, X } from "lucide-react";
import { saveConversationQuery, type ConversationQueryRow } from "../lib/mcp";
import {
  DEFAULT_WEIGHTS, mergedWeights, weightOverrides, weightsProblem, WEIGHT_FIELDS,
} from "../lib/conversationsPresentation";

/// A blank row for "New saved query".
export function emptyQuery(): ConversationQueryRow {
  return {
    id: "", name: "", query: "", weights: {}, safe_defaults: true,
    since_id: null, last_run_at: null, last_run_posts_read: null, created_at: "", updated_at: "",
  };
}

const INPUT = "rounded-lg border border-stone-300 bg-white px-3 py-1.5 text-sm dark:border-zinc-700 dark:bg-zinc-950";

export default function ConversationQueryEditor({ row, onClose, onSaved, onDelete }: {
  row: ConversationQueryRow;
  onClose: () => void;
  onSaved: (saved: ConversationQueryRow) => void;
  onDelete?: (id: string) => void;
}) {
  const [name, setName] = useState(row.name);
  const [query, setQuery] = useState(row.query);
  const [safe, setSafe] = useState(row.safe_defaults);
  const [weights, setWeights] = useState<Record<string, number>>(() => mergedWeights(row.weights));
  const [advanced, setAdvanced] = useState(Object.keys(row.weights ?? {}).length > 0);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const problem = weightsProblem(weights);
  const tuned = Object.keys(weightOverrides(weights)).length;
  const canSave = !saving && name.trim().length > 0 && query.trim().length > 0 && !problem;

  async function save() {
    setSaving(true);
    setError(null);
    try {
      const r = await saveConversationQuery({
        id: row.id || undefined, name: name.trim(), query: query.trim(), safeDefaults: safe,
        weights: weightOverrides(weights),
      });
      if (r.error || r.success === false || !r.query) {
        setError(r.message || r.error || "Couldn't save the query.");
        return;
      }
      onSaved(r.query);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="mb-3 rounded-lg border border-stone-200 bg-stone-50 p-3 dark:border-zinc-800 dark:bg-zinc-900/60">
      <div className="flex flex-wrap items-center gap-2">
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Name"
          maxLength={120}
          className={`w-48 ${INPUT}`}
          autoFocus={!row.id}
        />
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder='X search clause — your own nouns, e.g. ("sound money" OR mises) (recommend OR "what should I read")'
          maxLength={256}
          className={`min-w-72 flex-1 ${INPUT}`}
        />
        <label
          className="inline-flex items-center gap-1.5 text-xs text-stone-500 dark:text-zinc-400"
          title="Append -is:retweet -has:links -has:cashtags lang:en (a photo is not a link)"
        >
          <input type="checkbox" checked={safe} onChange={(e) => setSafe(e.target.checked)} />
          safe defaults
        </label>
        <button
          onClick={save}
          disabled={!canSave}
          className="inline-flex items-center gap-1 rounded-lg bg-amber-600 px-3 py-1.5 text-sm text-white hover:bg-amber-500 disabled:opacity-40"
          title={problem ?? "Save"}
        >
          <Save className="h-4 w-4" /> Save
        </button>
        {row.id && onDelete && (
          <button onClick={() => onDelete(row.id)} title="Delete saved query (its leads are kept)" className="text-stone-400 hover:text-red-500">
            <Trash2 className="h-4 w-4" />
          </button>
        )}
        <button onClick={onClose} title="Close" className="text-stone-400 hover:text-stone-600">
          <X className="h-4 w-4" />
        </button>
      </div>

      <button
        onClick={() => setAdvanced((v) => !v)}
        className="mt-2 inline-flex items-center gap-1 text-xs text-stone-500 hover:text-amber-600 dark:text-zinc-400 dark:hover:text-amber-400"
      >
        {advanced ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
        Scoring{tuned > 0 && <span className="ml-1 rounded-full bg-amber-100 px-1.5 text-amber-800 dark:bg-amber-500/20 dark:text-amber-200">{tuned} tuned</span>}
      </button>

      {advanced && (
        <div className="mt-2 grid grid-cols-2 gap-x-6 gap-y-2 sm:grid-cols-3">
          {WEIGHT_FIELDS.map((f) => {
            const changed = weights[f.key] !== DEFAULT_WEIGHTS[f.key];
            return (
              <label key={f.key} className="flex items-center justify-between gap-2 text-xs" title={f.hint}>
                <span className={changed ? "text-amber-700 dark:text-amber-300" : "text-stone-600 dark:text-zinc-400"}>
                  {f.label}
                </span>
                <span className="inline-flex items-center gap-1">
                  <input
                    type="number"
                    value={Number.isFinite(weights[f.key]) ? weights[f.key] : ""}
                    min={f.min}
                    max={f.max}
                    step={1}
                    onChange={(e) => setWeights((w) => ({ ...w, [f.key]: e.target.value === "" ? NaN : Number(e.target.value) }))}
                    className={`w-24 ${INPUT} text-right tabular-nums`}
                  />
                  <button
                    onClick={() => setWeights((w) => ({ ...w, [f.key]: DEFAULT_WEIGHTS[f.key] }))}
                    disabled={!changed}
                    title={`Reset to ${DEFAULT_WEIGHTS[f.key]}`}
                    className="text-stone-300 hover:text-amber-500 disabled:opacity-0 dark:text-zinc-600"
                  >
                    <RotateCcw className="h-3.5 w-3.5" />
                  </button>
                </span>
              </label>
            );
          })}
        </div>
      )}

      {(error || problem) && (
        <div className="mt-2 text-xs text-red-600 dark:text-red-400">{error ?? problem}</div>
      )}
    </div>
  );
}
