// Nostr profile (kind-0) panel — the canonical, self-sovereign home for the
// patron's avatar + contact info. Reads the latest kind-0 from relays; edits
// publish a new signed kind-0 (visible in every Nostr client). Avatar picks
// also mirror to localStorage so the Nav/editor update instantly.
//
// #378 — single avatar with accessible chooser badge; collapsible fields;
// read-only mode replaces disabled "Publish" with an enabled "How to set…"
// control that opens a tap/click explainer (not hover).

import { useEffect, useId, useRef, useState } from "react";
import { Camera, ChevronDown, Loader2, X } from "lucide-react";
import Avatar, { isAvatarUrl } from "./Avatar";
import AvatarPicker from "./AvatarPicker";
import { setStoredAvatar } from "../lib/avatar";
import {
  canSignProfile,
  fetchProfile,
  publishProfile,
  type Kind0,
} from "../lib/nostrProfile";
import {
  HOW_TO_SET_EXPLAINER,
  collapsedDisplayName,
  collapsedNpubLabel,
  publishControlDisabled,
  publishControlLabel,
  publishControlMode,
} from "../lib/nostrProfilePresentation";

const card = "rounded-xl border border-stone-200 dark:border-zinc-800 bg-white dark:bg-zinc-900";
const field =
  "w-full rounded-lg px-3 py-2 text-sm bg-white dark:bg-zinc-950 border border-stone-300 dark:border-zinc-700 focus:outline-hidden focus:border-amber-400";

export default function NostrProfilePanel({ npub }: { npub: string }) {
  const [picture, setPicture] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [about, setAbout] = useState("");
  const [nip05, setNip05] = useState("");
  const [lud16, setLud16] = useState("");
  const [website, setWebsite] = useState("");

  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(false);
  const [showPicker, setShowPicker] = useState(false);
  const [showHowTo, setShowHowTo] = useState(false);
  const [publishing, setPublishing] = useState(false);
  const [msg, setMsg] = useState<{ tone: "ok" | "err"; text: string } | null>(null);
  const [npubCopied, setNpubCopied] = useState(false);

  const fieldsId = useId();
  const explainerTitleId = useId();
  const howToWrapRef = useRef<HTMLDivElement | null>(null);

  const signer = canSignProfile();
  const pubMode = publishControlMode(signer);

  useEffect(() => {
    let live = true;
    setLoading(true);
    fetchProfile(npub)
      .then((p: Kind0 | null) => {
        if (!live || !p) return;
        setPicture(p.picture ?? "");
        setDisplayName(p.display_name || p.name || "");
        setAbout(p.about ?? "");
        setNip05(p.nip05 ?? "");
        setLud16(p.lud16 ?? "");
        setWebsite(p.website ?? "");
        if (p.picture) setStoredAvatar(npub, p.picture); // mirror to nav/editor
      })
      .finally(() => { if (live) setLoading(false); });
    return () => { live = false; };
  }, [npub]);

  // Dismiss the explainer on outside tap/click or Escape (touch-friendly; no hover).
  useEffect(() => {
    if (!showHowTo) return;
    function onPointer(e: MouseEvent | TouchEvent) {
      const el = howToWrapRef.current;
      if (!el) return;
      if (e.target instanceof Node && !el.contains(e.target)) {
        setShowHowTo(false);
      }
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setShowHowTo(false);
    }
    document.addEventListener("mousedown", onPointer);
    document.addEventListener("touchstart", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onPointer);
      document.removeEventListener("touchstart", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [showHowTo]);

  function pickAvatar(v: string) {
    setPicture(v);
    setStoredAvatar(npub, v); // instant local effect across eXcalibur
  }

  function copyNpub() {
    navigator.clipboard?.writeText(npub).then(
      () => {
        setNpubCopied(true);
        window.setTimeout(() => setNpubCopied(false), 1500);
      },
      () => {},
    );
  }

  async function publish() {
    setPublishing(true);
    setMsg(null);
    const emojiAvatar = picture && !isAvatarUrl(picture);
    const content: Kind0 = {
      name: displayName,
      display_name: displayName,
      about,
      nip05,
      lud16,
      website,
      // kind-0 picture is a URL; an emoji glyph stays eXcalibur-local.
      picture: emojiAvatar ? "" : picture,
    };
    try {
      const r = await publishProfile(content);
      const note = emojiAvatar ? " (Emoji avatar kept local — Nostr picture must be a URL.)" : "";
      if (r.error) {
        setMsg({ tone: "err", text: r.error });
      } else {
        const ok = r.ok ?? 0;
        setMsg({
          tone: ok > 0 ? "ok" : "err",
          text: (ok > 0 ? `Published to ${ok}/${r.total} relays.` : "No relay accepted the event.") + note,
        });
      }
    } catch (e) {
      setMsg({ tone: "err", text: (e as Error).message });
    } finally {
      setPublishing(false);
    }
  }

  const nameLine = collapsedDisplayName(displayName);
  const npubLine = collapsedNpubLabel(npub);

  return (
    <div className={`${card} p-5`}>
      {/* Collapsed header: one avatar + badge, display name, truncated npub, read-only cue */}
      <div className="flex items-start gap-3">
        <div className="relative flex-none">
          <Avatar value={picture} size={56} />
          <button
            type="button"
            onClick={() => {
              setExpanded(true);
              setShowPicker((v) => !v);
            }}
            aria-label={showPicker ? "Done changing avatar" : "Change avatar"}
            aria-expanded={showPicker}
            title="Change avatar"
            className="absolute -bottom-0.5 -right-0.5 inline-flex h-6 w-6 items-center justify-center rounded-full border border-stone-300 bg-white text-stone-600 shadow-sm transition-colors hover:border-amber-400 hover:text-amber-600 focus:outline-hidden focus-visible:ring-2 focus-visible:ring-amber-400 dark:border-zinc-600 dark:bg-zinc-800 dark:text-zinc-200 dark:hover:border-amber-500 dark:hover:text-amber-400"
          >
            <Camera className="h-3.5 w-3.5" aria-hidden="true" />
          </button>
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <div
              className="text-sm font-medium truncate"
              title="Your kind-0 metadata — self-sovereign, shown in every Nostr client."
            >
              {nameLine}
            </div>
            {!signer && (
              <span
                className="text-[11px] px-1.5 py-0.5 rounded-md bg-stone-100 text-stone-500 dark:bg-zinc-800 dark:text-zinc-400"
                title="Sign in with a session key or a NIP-07 extension to publish. Avatar picks still apply locally."
              >
                Read-only
              </span>
            )}
          </div>
          <button
            type="button"
            onClick={copyNpub}
            title="Copy full npub"
            className="mt-0.5 font-mono text-xs text-stone-500 dark:text-zinc-400 hover:text-amber-600 dark:hover:text-amber-400 transition-colors"
          >
            {npubCopied ? "Copied" : npubLine}
          </button>
        </div>

        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          aria-expanded={expanded}
          aria-controls={fieldsId}
          className="flex-none inline-flex items-center gap-1 rounded-lg border border-stone-300 px-2.5 py-1.5 text-xs text-stone-600 transition-colors hover:bg-stone-100 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800"
        >
          {expanded ? "Hide" : "Edit"}
          <ChevronDown
            className={`h-3.5 w-3.5 transition-transform ${expanded ? "rotate-180" : ""}`}
            aria-hidden="true"
          />
        </button>
      </div>

      {showPicker && (
        <div className="mt-3">
          <AvatarPicker value={picture} onChange={pickAvatar} />
        </div>
      )}

      {loading ? (
        <div className="flex items-center gap-1.5 text-xs text-stone-400 dark:text-zinc-500 py-2 mt-3">
          <Loader2 className="h-3.5 w-3.5 animate-spin" /> Reading from relays…
        </div>
      ) : (
        <div
          id={fieldsId}
          hidden={!expanded}
          className={expanded ? "mt-4 space-y-3" : undefined}
        >
          <label className="block text-xs text-stone-500 dark:text-zinc-400">
            Display name
            <input
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              className={`mt-1 ${field}`}
              placeholder="Satoshi"
              readOnly={!signer}
            />
          </label>
          <label className="block text-xs text-stone-500 dark:text-zinc-400">
            Lightning address (lud16)
            <input
              value={lud16}
              onChange={(e) => setLud16(e.target.value)}
              className={`mt-1 ${field}`}
              placeholder="you@walletofsatoshi.com"
              readOnly={!signer}
            />
          </label>
          <label className="block text-xs text-stone-500 dark:text-zinc-400">
            NIP-05
            <input
              value={nip05}
              onChange={(e) => setNip05(e.target.value)}
              className={`mt-1 ${field}`}
              placeholder="name@domain.com"
              readOnly={!signer}
            />
          </label>
          <label className="block text-xs text-stone-500 dark:text-zinc-400">
            Website
            <input
              value={website}
              onChange={(e) => setWebsite(e.target.value)}
              className={`mt-1 ${field}`}
              placeholder="https://…"
              readOnly={!signer}
            />
          </label>
          <label className="block text-xs text-stone-500 dark:text-zinc-400">
            About
            <textarea
              value={about}
              onChange={(e) => setAbout(e.target.value)}
              rows={2}
              className={`mt-1 ${field} resize-none`}
              placeholder="A short bio…"
              readOnly={!signer}
            />
          </label>

          {msg && (
            <div className={`rounded-lg p-2.5 text-xs ${
              msg.tone === "ok"
                ? "bg-green-50 border border-green-200 text-green-700 dark:bg-green-500/10 dark:border-green-500/30 dark:text-green-400"
                : "bg-red-50 border border-red-200 text-red-700 dark:bg-red-500/10 dark:border-red-500/30 dark:text-red-400"
            }`}>
              {msg.text}
            </div>
          )}

          <div className="relative flex items-center gap-3" ref={howToWrapRef}>
            <button
              type="button"
              onClick={() => {
                if (pubMode === "how-to-set") {
                  setShowHowTo((v) => !v);
                  return;
                }
                void publish();
              }}
              disabled={publishControlDisabled(pubMode, publishing)}
              aria-haspopup={pubMode === "how-to-set" ? "dialog" : undefined}
              aria-expanded={pubMode === "how-to-set" ? showHowTo : undefined}
              title={
                pubMode === "publish"
                  ? "Sign and publish your kind-0 to relays"
                  : "Why these fields are read-only, and how to change them"
              }
              className={
                pubMode === "publish"
                  ? "bg-amber-600 hover:bg-amber-500 text-white text-sm px-4 py-2 rounded-lg disabled:opacity-40 transition-colors"
                  : "rounded-lg border border-stone-300 px-4 py-2 text-sm text-stone-700 transition-colors hover:bg-stone-100 dark:border-zinc-600 dark:text-zinc-200 dark:hover:bg-zinc-800"
              }
            >
              {publishControlLabel(pubMode, publishing)}
            </button>

            {showHowTo && pubMode === "how-to-set" && (
              <div
                role="dialog"
                aria-modal="false"
                aria-labelledby={explainerTitleId}
                className="absolute left-0 bottom-full z-20 mb-2 w-[min(100%,22rem)] rounded-xl border border-stone-200 bg-white p-3 shadow-lg dark:border-zinc-700 dark:bg-zinc-900"
              >
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div
                    id={explainerTitleId}
                    className="text-sm font-medium text-stone-800 dark:text-zinc-100"
                  >
                    {HOW_TO_SET_EXPLAINER.title}
                  </div>
                  <button
                    type="button"
                    onClick={() => setShowHowTo(false)}
                    aria-label="Close explainer"
                    className="flex-none rounded-md p-1 text-stone-400 hover:bg-stone-100 hover:text-stone-600 dark:hover:bg-zinc-800 dark:hover:text-zinc-200"
                  >
                    <X className="h-3.5 w-3.5" aria-hidden="true" />
                  </button>
                </div>
                <div className="space-y-2 text-xs leading-relaxed text-stone-600 dark:text-zinc-300">
                  {HOW_TO_SET_EXPLAINER.paragraphs.map((p) => (
                    <p key={p.slice(0, 24)}>{p}</p>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
