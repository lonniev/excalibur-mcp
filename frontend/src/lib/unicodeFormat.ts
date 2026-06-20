// X-aware Unicode text styling. X has no native rich text, so "bold" /
// "italic" / "monospace" are rendered with Mathematical Alphanumeric Symbols
// (the same trick the MCP's markdown_to_unicode uses on post). We apply the
// styled code points directly in the editor so what you see is what posts.

export type UnicodeStyle = "bold" | "italic" | "boldItalic" | "mono";

interface StyleMap {
  upper: number;
  lower: number;
  digit?: number;
}

const MAPS: Record<UnicodeStyle, StyleMap> = {
  bold: { upper: 0x1d400, lower: 0x1d41a, digit: 0x1d7ce },
  italic: { upper: 0x1d434, lower: 0x1d44e }, // italic has no styled digits
  boldItalic: { upper: 0x1d468, lower: 0x1d482 },
  mono: { upper: 0x1d670, lower: 0x1d68a, digit: 0x1d7f6 },
};

// Reserved code points in the math-italic block fall back to letterlike forms.
const ITALIC_OVERRIDES: Record<string, string> = { h: "ℎ" };

/// Map ASCII A–Z / a–z / 0–9 in `s` to the chosen Unicode style; everything
/// else (including already-styled text and emoji) passes through unchanged.
export function styleText(s: string, style: UnicodeStyle): string {
  const m = MAPS[style];
  let out = "";
  for (const ch of s) {
    if (ch >= "A" && ch <= "Z") {
      out += String.fromCodePoint(m.upper + (ch.charCodeAt(0) - 0x41));
    } else if (ch >= "a" && ch <= "z") {
      out += style === "italic" && ITALIC_OVERRIDES[ch]
        ? ITALIC_OVERRIDES[ch]
        : String.fromCodePoint(m.lower + (ch.charCodeAt(0) - 0x61));
    } else if (ch >= "0" && ch <= "9" && m.digit !== undefined) {
      out += String.fromCodePoint(m.digit + (ch.charCodeAt(0) - 0x30));
    } else {
      out += ch;
    }
  }
  return out;
}
