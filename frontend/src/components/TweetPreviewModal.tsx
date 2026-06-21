// Popup preview of a posted tweet. Uses X's embed widget (widgets.js upgrades
// the blockquote into the live rendered tweet); if the script is blocked or
// slow, the blockquote itself shows the text + an "Open on X" link, so there is
// always something to see. Esc / backdrop click closes.

import { useEffect, useRef } from "react";
import { X, ExternalLink } from "lucide-react";

declare global {
  interface Window {
    twttr?: { widgets?: { load: (el?: HTMLElement) => void } };
  }
}

const WIDGETS_SRC = "https://platform.twitter.com/widgets.js";

export default function TweetPreviewModal({
  url,
  text,
  onClose,
}: {
  url: string;
  text: string;
  onClose: () => void;
}) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  useEffect(() => {
    const render = () => window.twttr?.widgets?.load(ref.current ?? undefined);
    if (window.twttr?.widgets) {
      render();
      return;
    }
    let s = document.querySelector<HTMLScriptElement>(`script[src="${WIDGETS_SRC}"]`);
    if (!s) {
      s = document.createElement("script");
      s.src = WIDGETS_SRC;
      s.async = true;
      document.body.appendChild(s);
    }
    s.addEventListener("load", render, { once: true });
  }, [url]);

  return (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-4"
      onClick={onClose}
    >
      <div
        className="max-h-[85vh] w-full max-w-lg overflow-y-auto rounded-2xl border border-zinc-800 bg-zinc-950 p-5 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-3 flex items-center gap-2">
          <span className="text-sm font-medium text-zinc-100">Posted to X</span>
          <button onClick={onClose} className="ml-auto text-zinc-500 hover:text-zinc-200" title="Close">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div ref={ref}>
          {/* widgets.js upgrades this into the live tweet; until/unless it does,
              the text + link below are the visible preview. */}
          <blockquote className="twitter-tweet" data-theme="dark" data-dnt="true">
            <p style={{ whiteSpace: "pre-wrap" }}>{text}</p>
            {url && <a href={url}>View on X</a>}
          </blockquote>
        </div>

        {url && (
          <a
            href={url}
            target="_blank"
            rel="noopener noreferrer"
            className="mt-4 inline-flex items-center gap-1.5 rounded-lg bg-amber-600 px-4 py-2 text-sm text-white transition-colors hover:bg-amber-500"
          >
            <ExternalLink className="h-4 w-4" /> Open on X
          </a>
        )}
      </div>
    </div>
  );
}
