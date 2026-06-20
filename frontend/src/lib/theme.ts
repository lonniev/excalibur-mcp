// Theme — dark by default. Persisted in localStorage so a returning user
// keeps their pick. Applied by toggling the `dark` class on <html>
// (Tailwind darkMode: "class"). Three modes: dark | light | system.
//
// Two consumers:
//   - bootstrapTheme() runs in main.tsx before first paint (no flash).
//   - useTheme() React hook (ProfilePage) for live switching + cross-tab sync.

import { useEffect, useState } from "react";

export type Theme = "dark" | "light" | "system";

const STORAGE_KEY = "excalibur:theme";

export function readStoredTheme(): Theme {
  const raw = window.localStorage.getItem(STORAGE_KEY);
  return raw === "light" || raw === "system" ? raw : "dark"; // default dark
}

function prefersDark(): boolean {
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

function resolve(theme: Theme): "dark" | "light" {
  if (theme === "system") return prefersDark() ? "dark" : "light";
  return theme;
}

function apply(theme: Theme): void {
  const effective = resolve(theme);
  const root = document.documentElement;
  root.classList.toggle("dark", effective === "dark");
  root.style.colorScheme = effective;
}

/// Run once on boot, before React paints, so the palette is correct on
/// first frame.
export function bootstrapTheme(): void {
  apply(readStoredTheme());
}

/// React hook — current theme + setter that persists, re-applies, and keeps
/// "system" mode reactive to OS changes. Cross-tab sync via the storage event.
export function useTheme(): [Theme, (next: Theme) => void] {
  const [theme, setTheme] = useState<Theme>(() => readStoredTheme());

  useEffect(() => {
    function onStorage(e: StorageEvent): void {
      if (e.key === STORAGE_KEY) {
        const next = readStoredTheme();
        setTheme(next);
        apply(next);
      }
    }
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  // When in "system" mode, follow OS changes live.
  useEffect(() => {
    if (theme !== "system") return;
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => apply("system");
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, [theme]);

  function update(next: Theme): void {
    window.localStorage.setItem(STORAGE_KEY, next);
    apply(next);
    setTheme(next);
  }

  return [theme, update];
}
