// On-screen MCP activity log, ported from taxsort-mcp. A fixed bottom bar that
// shows every MCP call/result/error so you can see what the FE is doing —
// invaluable for diagnosing "Post does nothing" and the OAuth flow.

import { useState } from "react";
import { clearDebug, useDebugLog, type DebugEntry } from "../lib/debugLog";

const TYPE_COLOR: Record<DebugEntry["type"], string> = {
  info: "text-sky-400",
  call: "text-amber-400",
  result: "text-green-400",
  error: "text-red-400",
};

function isFailure(entry: DebugEntry): boolean {
  if (entry.type === "error") return true;
  if (entry.type === "result") {
    const m = entry.message;
    return m.includes('"success":false') || m.includes('"error"') || m.includes("error_code");
  }
  return false;
}

export default function DebugPanel() {
  const log = useDebugLog();
  const [open, setOpen] = useState(false);

  const errorCount = log.filter(isFailure).length;

  return (
    <div className="fixed bottom-0 left-0 right-0 z-50">
      <div className="absolute bottom-0 right-3 flex gap-1">
        {open && (
          <button
            onClick={clearDebug}
            className="rounded-t-lg bg-zinc-700 px-3 py-1 text-xs text-zinc-200 hover:bg-zinc-600"
          >
            Clear
          </button>
        )}
        <button
          onClick={() => setOpen(!open)}
          className={`rounded-t-lg px-3 py-1 text-xs text-white ${
            errorCount > 0 ? "bg-red-700 hover:bg-red-600" : "bg-zinc-800 hover:bg-zinc-700"
          }`}
        >
          {open ? "Hide" : "Debug"} ({log.length}
          {errorCount > 0 ? ` · ${errorCount} err` : ""})
        </button>
      </div>
      {open && (
        <div className="max-h-64 overflow-y-auto border-t border-zinc-700 bg-zinc-950/95 p-3 font-mono text-xs backdrop-blur">
          {log.length === 0 && <div className="text-zinc-500">No MCP activity yet.</div>}
          {log.map((entry, i) => {
            const failed = isFailure(entry);
            return (
              <div
                key={i}
                className={`flex gap-2 py-0.5 ${failed ? "-mx-1 rounded bg-red-950/60 px-1" : ""}`}
              >
                <span className="shrink-0 text-zinc-600">{entry.ts}</span>
                <span className={`w-12 shrink-0 ${failed ? "font-bold text-red-400" : TYPE_COLOR[entry.type]}`}>
                  {entry.type}
                  {failed && entry.type !== "error" ? " !" : ""}
                </span>
                <span className={`break-all ${failed ? "text-red-300" : "text-zinc-300"}`}>{entry.message}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
