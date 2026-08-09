// On-screen MCP activity log (ported from taxsort-mcp's DebugPanel UX).
// A module-level ring buffer with pub/sub so the central callTool can push
// entries and a single DebugPanel can subscribe. Survives route changes; not
// persisted across reloads.

import { useRef, useState } from "react";

export interface DebugEntry {
  ts: string;
  type: "info" | "call" | "result" | "error";
  message: string;
}

const _log: DebugEntry[] = [];
const _listeners = new Set<() => void>();
const MAX = 60;

export function debugPush(type: DebugEntry["type"], message: string): void {
  // Prefer the patron display zone (#367); fall back to browser local on failure.
  let ts: string;
  try {
    // Lazy import path avoided — keep this module free of React. Read the same
    // storage key theme/timezone use so the stamp matches the rest of the UI.
    const pref =
      (typeof window !== "undefined" && window.localStorage.getItem("excalibur:timezone")) ||
      "auto";
    const zone =
      pref === "auto"
        ? Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC"
        : pref;
    ts = new Date().toLocaleTimeString(undefined, { timeZone: zone });
  } catch {
    ts = new Date().toLocaleTimeString();
  }
  _log.unshift({ ts, type, message });
  if (_log.length > MAX) _log.length = MAX;
  _listeners.forEach((fn) => fn());
}

export function clearDebug(): void {
  _log.length = 0;
  _listeners.forEach((fn) => fn());
}

export function useDebugLog(): DebugEntry[] {
  const [, setTick] = useState(0);
  const ref = useRef<(() => void) | undefined>(undefined);
  if (!ref.current) {
    ref.current = () => setTick((t) => t + 1);
    _listeners.add(ref.current);
  }
  return _log;
}
