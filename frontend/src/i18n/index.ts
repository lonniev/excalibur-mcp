/**
 * eXcalibur's words, handed to the shared web package. The package does all
 * the translating (i18next): which language to start in, fetching a language
 * when chosen, falling back to English, the chooser. eXcalibur supplies only
 * the English and its translations.
 */

import { registerNamespace, translate, type Vars } from "@tollbooth-dpyc/web";
import { useT as useWords } from "@tollbooth-dpyc/web/react";
import en, { type MessageKey } from "./en.ts";

/** eXcalibur's words, for `useT`, `tr` and `<Tx ns={WORDS} …/>`. */
export const WORDS = "excalibur";

/** Hand eXcalibur's English to the package, and say where each translation is fetched from. Once, before render. */
export function registerExcalibur(): Promise<void> {
  return registerNamespace(WORDS, en, {});
}

export type Translate = (key: MessageKey, vars?: Vars) => string;

/** `t(key, vars?)` in a component: re-renders when the language changes. */
export const useT = (): Translate => useWords<MessageKey>(WORDS);

/**
 * `tr(key, vars?)` outside a component, in the language on screen now. Call it
 * when the words are needed (at render time), never at module load, or the
 * words are stuck in the language the page opened in.
 */
export const tr: Translate = (key, vars) => translate(key, vars, WORDS);
