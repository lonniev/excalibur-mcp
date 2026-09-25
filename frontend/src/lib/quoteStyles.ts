// How eXcalibur's loading quotes look. @tollbooth-dpyc/web's QuoteScroller
// brings only the mechanics (rotation, fade, reserved height); every loading
// screen passes this, so the look lives here and nowhere else. It is the
// scroller eXcalibur always had: an amber mono status line with a spinner,
// the quote in italic serif between amber marks, the author in small spaced
// capitals. Dark keeps the original zinc; light swaps in stone of the same
// weight so the quote stays readable on the light pages.

import type { QuoteScrollerClassNames } from "@tollbooth-dpyc/web/react";

export const quoteStyles: QuoteScrollerClassNames = {
  root: "flex flex-col items-center justify-center px-6 text-center",
  heading:
    "mb-6 flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.32em] text-amber-500",
  spinner: "h-3.5 w-3.5",
  figure: "mx-auto flex min-h-28 max-w-xl flex-col justify-center gap-3",
  text: "font-serif text-lg italic leading-relaxed text-stone-700 dark:text-zinc-300",
  mark: "text-amber-500",
  author: "font-mono text-[10px] uppercase tracking-[0.28em] text-stone-500 dark:text-zinc-500",
};
