// React hook for the display-timezone preference (see timezone.ts).
// Mirrors useTheme: localStorage + live updates + cross-tab storage sync.

import { useEffect, useState } from "react";
import {
  STORAGE_KEY,
  readStoredTimezonePref,
  resolveTimeZone,
  writeTimezonePref,
  type TimezonePref,
} from "./timezone";

/** preference, resolved IANA zone, setter. Default pref is Auto (browser zone). */
export function useTimezone(): [TimezonePref, string, (next: TimezonePref) => void] {
  const [pref, setPref] = useState<TimezonePref>(() => readStoredTimezonePref());
  const [resolved, setResolved] = useState<string>(() =>
    resolveTimeZone(readStoredTimezonePref()),
  );

  useEffect(() => {
    function sync(): void {
      const next = readStoredTimezonePref();
      setPref(next);
      setResolved(resolveTimeZone(next));
    }
    function onStorage(e: StorageEvent): void {
      if (e.key === STORAGE_KEY) sync();
    }
    window.addEventListener("storage", onStorage);
    window.addEventListener("excalibur:timezone", sync);
    return () => {
      window.removeEventListener("storage", onStorage);
      window.removeEventListener("excalibur:timezone", sync);
    };
  }, []);

  function update(next: TimezonePref): void {
    const value = writeTimezonePref(next);
    setPref(value);
    setResolved(resolveTimeZone(value));
  }

  return [pref, resolved, update];
}
