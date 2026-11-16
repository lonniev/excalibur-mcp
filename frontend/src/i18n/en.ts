/**
 * Every word eXcalibur's own pages say, in English: the bedrock the other
 * languages translate.
 *
 * Keys are "<area>.<file>.<name>" (areas: views, ui, lib). A `{{name}}` is
 * filled with a word or number; a `<name/>` or `<name>…</name>` is drawn as an
 * element. A translation keeps each one exactly as written and may move it.
 * "eXcalibur", X handles, post text and emoji stay as they are.
 */

export const en = {
};

/** A key as written in the catalog, plural suffix and all. */
export type EnglishKey = keyof typeof en;
type StripPlural<K> = K extends `${infer Base}_${"zero" | "one" | "two" | "few" | "many" | "other"}` ? Base : K;
/** A key as code asks for it: `x` stands for `x_one` / `x_other`, read with `{ count }`. */
export type MessageKey = StripPlural<EnglishKey>;
export type Messages = Record<EnglishKey, string>;
type PluralBase = EnglishKey extends infer K ? (K extends `${infer Base}_other` ? Base : never) : never;
/** One language's words: English's keys, plus the plural forms that language has beyond English's two. */
export type Translation = Partial<Messages> & Partial<Record<`${PluralBase}_${"zero" | "two" | "few" | "many"}`, string>>;

export default en as Messages;
