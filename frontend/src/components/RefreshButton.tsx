// One refresh control, used everywhere something can be re-read.
//
// Posts had a 48px icon button that spun while loading; Scheduler had a small
// text button that did neither. Same verb, same job, two different affordances —
// so the same action had to be re-learned per page, and only one of them told
// you it was working.
//
// `size` is the only knob: "lg" for a table toolbar, "sm" for a page header
// sitting beside a title. Everything that carries meaning — the glyph, the spin
// while busy, the disabled state, the accessible name — is fixed here so it
// cannot drift again.
//
// "sm" is smaller than a toolbar button, not small: at h-4 the spin was too
// faint to read as "working". The scale lives here rather than in a per-page
// override, so both page headers stay the same size.

import { RefreshCw } from "lucide-react";

export default function RefreshButton({
  onClick,
  busy = false,
  size = "lg",
  title = "Refresh",
}: {
  onClick: () => void;
  busy?: boolean;
  /** "lg" — table toolbars. "sm" — page headers beside a title. */
  size?: "lg" | "sm";
  /** Override only to say WHAT refreshes; the accessible name follows it. */
  title?: string;
}) {
  const box = size === "lg" ? "h-12 w-12" : "h-10 w-10";
  const glyph = size === "lg" ? "h-6 w-6" : "h-5 w-5";

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={busy}
      title={title}
      aria-label={title}
      className={`inline-flex ${box} items-center justify-center rounded-lg text-stone-400 transition-colors hover:bg-stone-100 disabled:cursor-not-allowed disabled:opacity-50 dark:text-zinc-500 dark:hover:bg-zinc-800`}
    >
      <RefreshCw className={`${glyph} ${busy ? "animate-spin" : ""}`} aria-hidden />
    </button>
  );
}
