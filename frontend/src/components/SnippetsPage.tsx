import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Star } from "lucide-react";
import {
  deleteSnippet, listSnippets, saveSnippet,
  type SnippetRow, type SortDir,
} from "../lib/mcp";
import { PageControls, SortHeader, TableShell } from "./PagedTable";
import TableFilter from "./TableFilter";

const DATE_FIELDS = [
  { value: "created", label: "Created" },
  { value: "updated", label: "Updated" },
];
const PAGE_SIZE = 25;

export default function SnippetsPage() {
  const nav = useNavigate();
  const [snippets, setSnippets] = useState<SnippetRow[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [sortCol, setSortCol] = useState("favorite");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [search, setSearch] = useState("");
  const [dateField, setDateField] = useState("created");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await listSnippets({
        sortCol, sortDir, page, pageSize: PAGE_SIZE, search, dateFrom, dateTo, dateField,
      });
      if (r.error) setError(r.error);
      setSnippets(r.snippets ?? []);
      setTotal(r.total ?? 0);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [sortCol, sortDir, page, search, dateFrom, dateTo, dateField]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  function onSort(col: string, dir: SortDir) {
    setSortCol(col);
    setSortDir(dir);
    setPage(0);
  }

  async function toggleFav(e: React.MouseEvent, s: SnippetRow) {
    e.stopPropagation();
    e.preventDefault();
    setError(null);
    try {
      await saveSnippet({ id: s.id, favorite: !s.favorite });
      await refresh();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function handleDelete(e: React.MouseEvent, id: string) {
    e.stopPropagation();
    e.preventDefault();
    if (!window.confirm("Delete this snippet? This cannot be undone.")) return;
    setError(null);
    try {
      await deleteSnippet(id);
      await refresh();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <div className="max-w-4xl mx-auto px-4 py-6">
      <div className="flex items-center mb-4">
        <h1 className="text-lg font-semibold">Snippets</h1>
        <Link
          to="/snippets/new"
          className="ml-auto bg-amber-600 hover:bg-amber-500 text-white text-sm px-4 py-2 rounded-lg transition-colors"
        >
          + New snippet
        </Link>
      </div>

      <p className="text-xs text-stone-400 dark:text-zinc-500 mb-4">
        Reusable content for your posts — favorites appear as one-click chiclets in the editor.
      </p>

      <TableFilter
        search={search}
        onSearch={(t) => { setSearch(t); setPage(0); }}
        dateField={dateField}
        dateFieldOptions={DATE_FIELDS}
        onDateField={(v) => { setDateField(v); setPage(0); }}
        dateFrom={dateFrom}
        dateTo={dateTo}
        onDateFrom={(v) => { setDateFrom(v); setPage(0); }}
        onDateTo={(v) => { setDateTo(v); setPage(0); }}
        onClear={() => { setSearch(""); setDateFrom(""); setDateTo(""); setDateField("created"); setPage(0); }}
      />

      {error && (
        <div className="rounded-lg p-3 mb-3 text-xs bg-red-50 border border-red-200 text-red-700 dark:bg-red-500/10 dark:border-red-500/30 dark:text-red-400">
          {error}
        </div>
      )}

      {loading && snippets.length === 0 ? (
        <p className="text-sm text-stone-400 dark:text-zinc-500 py-10 text-center">Loading…</p>
      ) : snippets.length === 0 ? (
        (search || dateFrom || dateTo) ? (
          <div className="text-center py-12">
            <p className="text-sm text-stone-400 dark:text-zinc-500">No snippets match this filter.</p>
          </div>
        ) : (
          <div className="text-center py-12">
            <p className="text-sm text-stone-400 dark:text-zinc-500 mb-3">No snippets yet.</p>
            <Link to="/snippets/new" className="text-sm text-amber-600 dark:text-amber-400 hover:underline">
              Create your first snippet →
            </Link>
          </div>
        )
      ) : (
        <>
          <TableShell>
            <thead className="border-b border-stone-200 dark:border-zinc-800">
              <tr>
                <SortHeader label="★" col="favorite" activeCol={sortCol} dir={sortDir} onSort={onSort} />
                <SortHeader label="Name" col="name" activeCol={sortCol} dir={sortDir} onSort={onSort} />
                <SortHeader label="Content" activeCol={sortCol} dir={sortDir} onSort={onSort} />
                <SortHeader label="Edited" col="updated" activeCol={sortCol} dir={sortDir} onSort={onSort} />
                <SortHeader label="" activeCol={sortCol} dir={sortDir} onSort={onSort} className="text-right" />
              </tr>
            </thead>
            <tbody>
              {snippets.map((s) => (
                <tr
                  key={s.id}
                  onClick={() => nav(`/snippet/${s.id}`)}
                  className="border-b border-stone-100 last:border-0 dark:border-zinc-900 hover:bg-stone-50 dark:hover:bg-zinc-900/60 cursor-pointer"
                >
                  <td className="px-3 py-2.5 align-top">
                    <button
                      onClick={(e) => toggleFav(e, s)}
                      title={s.favorite ? "Unfavorite" : "Favorite — adds a one-click chiclet in the editor"}
                      className={s.favorite ? "text-amber-500" : "text-stone-300 hover:text-amber-500 dark:text-zinc-600"}
                    >
                      <Star className={`h-4 w-4 ${s.favorite ? "fill-current" : ""}`} />
                    </button>
                  </td>
                  <td className="px-3 py-2.5 align-top font-medium text-stone-800 dark:text-zinc-200 whitespace-nowrap max-w-[12rem] truncate">
                    {s.name}
                  </td>
                  <td className="px-3 py-2.5 align-top max-w-md">
                    <p className="truncate text-stone-500 dark:text-zinc-400">{s.text}</p>
                  </td>
                  <td className="px-3 py-2.5 align-top text-xs text-stone-400 dark:text-zinc-500 whitespace-nowrap">
                    {s.updated_at ? fmt(s.updated_at) : "—"}
                  </td>
                  <td className="px-3 py-2.5 align-top text-right whitespace-nowrap">
                    <span className="inline-flex gap-2 text-xs text-stone-400 dark:text-zinc-500">
                      <span role="button" onClick={(e) => { e.stopPropagation(); e.preventDefault(); nav(`/snippet/${s.id}`); }} className="hover:text-amber-600 dark:hover:text-amber-400 cursor-pointer" title="Edit">
                        edit
                      </span>
                      <span role="button" onClick={(e) => handleDelete(e, s.id)} className="hover:text-red-500 dark:hover:text-red-400 cursor-pointer" title="Delete">
                        delete
                      </span>
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </TableShell>
          <PageControls page={page} pageSize={PAGE_SIZE} total={total} onPage={setPage} />
        </>
      )}
    </div>
  );
}

function fmt(iso: string): string {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString();
}
