// Avatar renderer — an emoji glyph or an image (Iconify SVG / data: URI /
// hosted image) in a bordered circle. Folded in from optionality-mcp and
// re-skinned for eXcalibur's Tailwind dark theme.

export const AVATAR_CHOICES: string[] = [
  "🐂", "🐻", "🦂", "🦅", "🐺", "🦉",
  "🦊", "🐉", "🦄", "🐢", "🦈", "🦀",
  "🎩", "🎭", "🃏", "🎯", "🪙", "💎",
  "⚡", "🔥", "🌪️", "🌊", "🏔️", "🌋",
  "♟️", "♛", "🛡️", "⚔️", "🗝️", "📜",
];

/// A URL-shaped value (http(s) or data:image) renders as an <img>;
/// anything else renders as centered text (emoji / single char).
export function isAvatarUrl(value: string): boolean {
  return /^(https?:\/\/|data:image\/)/i.test(value);
}

/// Compact npub for display — first 8 + last 4.
export function shortNpub(npub?: string | null): string {
  if (!npub) return "";
  return npub.length <= 16 ? npub : `${npub.slice(0, 8)}…${npub.slice(-4)}`;
}

export default function Avatar({
  value,
  size = 40,
  onClick,
  title,
  className = "",
}: {
  value?: string | null;
  size?: number;
  onClick?: () => void;
  title?: string;
  className?: string;
}) {
  const raw = value && value.trim() ? value : "🃏";
  const urlMode = isAvatarUrl(raw);
  const clickable = !!onClick;
  return (
    <span
      onClick={onClick}
      title={title}
      role={clickable ? "button" : undefined}
      tabIndex={clickable ? 0 : undefined}
      onKeyDown={
        clickable
          ? (e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                onClick();
              }
            }
          : undefined
      }
      style={{ width: size, height: size, minWidth: size, fontSize: Math.round(size * 0.55), lineHeight: 1 }}
      className={`inline-flex items-center justify-center overflow-hidden rounded-full select-none border bg-stone-100 dark:bg-zinc-800 border-stone-300 dark:border-zinc-700 text-amber-600 dark:text-amber-400 ${
        clickable ? "cursor-pointer hover:border-amber-400 dark:hover:border-amber-500 transition-colors" : ""
      } ${className}`}
    >
      {urlMode ? (
        <img src={raw} alt="" loading="lazy" className="block h-full w-full object-cover" />
      ) : (
        raw
      )}
    </span>
  );
}
