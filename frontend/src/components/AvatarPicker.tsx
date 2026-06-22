// Avatar chooser — folded in from optionality-mcp. Paginated Iconify SVG
// catalog + the legacy emoji-glyph palette + a custom URL/glyph fallback.
// Iconify (api.iconify.design) is a free public REST endpoint; SVGs are
// lazy-loaded per tile, never bundled. Re-skinned to Tailwind/dark.

import { useEffect, useState } from "react";
import { Loader2 } from "lucide-react";
import Avatar, { AVATAR_CHOICES } from "./Avatar";

interface Collection {
  prefix: string;
  label: string;
}
const COLLECTIONS: ReadonlyArray<Collection> = [
  { prefix: "fluent-emoji-flat", label: "Fluent — Microsoft, flat" },
  { prefix: "twemoji", label: "Twemoji — Twitter's set" },
  { prefix: "noto", label: "Noto — Google" },
  { prefix: "openmoji", label: "OpenMoji — CC-BY-SA" },
  { prefix: "emojione-v1", label: "EmojiOne — classic" },
];
const PAGE_SIZE = 30;

function iconUrl(prefix: string, name: string): string {
  return `https://api.iconify.design/${prefix}/${name}.svg`;
}

const tile = (selected: boolean) =>
  `flex items-center justify-center aspect-square rounded-md p-1 border transition-colors ${
    selected
      ? "border-amber-400 bg-amber-50 dark:border-amber-500 dark:bg-amber-500/15"
      : "border-stone-200 dark:border-zinc-800 hover:border-amber-300 dark:hover:border-amber-500/40"
  }`;

export default function AvatarPicker({ value, onChange }: { value: string; onChange: (next: string) => void }) {
  const [tab, setTab] = useState<"catalog" | "glyphs">("catalog");
  const [collection, setCollection] = useState(COLLECTIONS[0].prefix);
  const [names, setNames] = useState<string[]>([]);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError("");
    setNames([]);
    setPage(0);
    void fetch(`https://api.iconify.design/collection?prefix=${collection}`)
      .then((r) => {
        if (!r.ok) throw new Error(`Iconify returned ${r.status}`);
        return r.json();
      })
      .then((data: { uncategorized?: string[]; categories?: Record<string, string[]> }) => {
        if (!alive) return;
        const out: string[] = [];
        if (data.categories) for (const cat of Object.keys(data.categories)) out.push(...data.categories[cat]);
        if (data.uncategorized) out.push(...data.uncategorized);
        setNames(out);
        setLoading(false);
      })
      .catch((e) => {
        if (!alive) return;
        setError((e as Error).message);
        setLoading(false);
      });
    return () => { alive = false; };
  }, [collection]);

  const totalPages = Math.max(1, Math.ceil(names.length / PAGE_SIZE));
  const visible = names.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  return (
    <div>
      <div className="flex gap-2 mb-3 text-xs">
        {(["catalog", "glyphs"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-3 py-1.5 rounded-lg transition-colors ${
              tab === t
                ? "bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-400"
                : "text-stone-500 hover:bg-stone-100 dark:text-zinc-400 dark:hover:bg-zinc-800"
            }`}
          >
            {t === "catalog" ? "Catalog" : "Glyphs"}
          </button>
        ))}
      </div>

      {tab === "catalog" && (
        <>
          <div className="flex items-center gap-2 mb-3">
            <select
              value={collection}
              onChange={(e) => setCollection(e.target.value)}
              className="flex-1 rounded-lg px-2 py-1.5 text-xs bg-white dark:bg-zinc-950 border border-stone-300 dark:border-zinc-700"
            >
              {COLLECTIONS.map((c) => (
                <option key={c.prefix} value={c.prefix}>{c.label}</option>
              ))}
            </select>
            {!loading && !error && names.length > 0 && (
              <span className="text-xs text-stone-400 dark:text-zinc-500 whitespace-nowrap">
                {page + 1}/{totalPages}
              </span>
            )}
          </div>

          {loading && <p className="flex items-center justify-center gap-1.5 py-6 text-center text-xs text-stone-400 dark:text-zinc-500"><Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading catalog…</p>}
          {error && (
            <div className="rounded-lg p-2.5 text-xs bg-red-50 border border-red-200 text-red-700 dark:bg-red-500/10 dark:border-red-500/30 dark:text-red-400">
              Couldn't reach Iconify: {error}
            </div>
          )}

          {!loading && !error && (
            <>
              <div className="grid grid-cols-10 gap-1.5">
                {visible.map((name) => {
                  const url = iconUrl(collection, name);
                  return (
                    <button key={name} onClick={() => onChange(url)} title={name.replace(/-/g, " ")} className={tile(value === url)}>
                      <img src={url} alt={name} loading="lazy" className="h-full w-full object-contain" />
                    </button>
                  );
                })}
              </div>
              <div className="flex items-center justify-center gap-3 mt-3 text-xs">
                <button onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={page === 0} className="px-3 py-1 rounded-lg border border-stone-300 dark:border-zinc-700 disabled:opacity-30 hover:bg-stone-100 dark:hover:bg-zinc-800 transition-colors">← Prev</button>
                <span className="font-mono text-stone-400 dark:text-zinc-500">{page + 1} / {totalPages}</span>
                <button onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1} className="px-3 py-1 rounded-lg border border-stone-300 dark:border-zinc-700 disabled:opacity-30 hover:bg-stone-100 dark:hover:bg-zinc-800 transition-colors">Next →</button>
              </div>
            </>
          )}
        </>
      )}

      {tab === "glyphs" && (
        <div className="grid grid-cols-10 gap-1.5">
          {AVATAR_CHOICES.map((emoji) => (
            <button key={emoji} onClick={() => onChange(emoji)} className={`${tile(value === emoji)} text-lg`}>
              {emoji}
            </button>
          ))}
        </div>
      )}

      <details className="mt-3">
        <summary className="text-xs uppercase tracking-wider text-stone-400 dark:text-zinc-500 cursor-pointer">
          Custom (image URL or glyph)
        </summary>
        <input
          type="text"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder="https://… or a single emoji"
          className="mt-2 w-full rounded-lg px-2 py-1.5 text-xs font-mono bg-white dark:bg-zinc-950 border border-stone-300 dark:border-zinc-700 focus:outline-none focus:border-amber-400"
        />
      </details>

      {value && (
        <div className="mt-4 flex items-center gap-3">
          <Avatar value={value} size={48} />
          <span className="text-xs text-stone-400 dark:text-zinc-500">Selected — applies immediately.</span>
        </div>
      )}
    </div>
  );
}
