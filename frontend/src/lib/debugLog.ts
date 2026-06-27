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
  _log.unshift({ ts: new Date().toLocaleTimeString(), type, message });
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
