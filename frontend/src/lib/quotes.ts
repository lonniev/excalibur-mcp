// eXcalibur's quotes for a wait: the greats of copywriting, advertising and
// brevity, on-brand for a posting tool. The scroller that shows them is
// @tollbooth-dpyc/web's QuoteScroller; these are the site's own set, inline so
// a loading screen never itself fails on a network hiccup.

import type { Quote } from "@tollbooth-dpyc/web";
import { tr } from "../i18n/index.ts";
import type { MessageKey } from "../i18n/en.ts";

// Curated — copywriting / advertising / brevity. Keep it tight and quotable.
// The words are the catalog's (lib.quotes.*); each `text` is read when the
// scroller draws it, so a quote follows a language change. Authors stay as named.
const quote = (key: MessageKey, author: string): Quote => ({
  get text() {
    return tr(key);
  },
  author,
});

export const QUOTES: ReadonlyArray<Quote> = [
  quote("lib.quotes.q1", "David Ogilvy"),
  quote("lib.quotes.q2", "David Ogilvy"),
  quote("lib.quotes.q3", "David Ogilvy"),
  quote("lib.quotes.q4", "David Ogilvy"),
  quote("lib.quotes.q5", "Bill Bernbach"),
  quote("lib.quotes.q6", "Bill Bernbach"),
  quote("lib.quotes.q7", "John E. Kennedy"),
  quote("lib.quotes.q8", "Claude C. Hopkins"),
  quote("lib.quotes.q9", "William Howard Taft"),
  quote("lib.quotes.q10", "John Caples"),
  quote("lib.quotes.q11", "Leo Burnett"),
  quote("lib.quotes.q12", "Shirley Polykoff"),
  quote("lib.quotes.q13", "George Gribbin"),
  quote("lib.quotes.q14", "David Ogilvy"),
  quote("lib.quotes.q15", "William Strunk Jr."),
  quote("lib.quotes.q16", "Mark Twain"),
  quote("lib.quotes.q17", "Nathaniel Hawthorne"),
  quote("lib.quotes.q18", "Albert Einstein"),
];
