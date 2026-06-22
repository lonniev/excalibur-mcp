// Nostr profile (kind-0) panel — the canonical, self-sovereign home for the
// patron's avatar + contact info. Reads the latest kind-0 from relays; edits
// publish a new signed kind-0 (visible in every Nostr client). Avatar picks
// also mirror to localStorage so the Nav/editor update instantly.

import { useEffect, useState } from "react";
import { Loader2 } from "lucide-react";
import Avatar, { isAvatarUrl } from "./Avatar";
import AvatarPicker from "./AvatarPicker";
import { setStoredAvatar } from "../lib/avatar";
import {
  canSignProfile,
  fetchProfile,
  publishProfile,
  type Kind0,
} from "../lib/nostrProfile";

const card = "rounded-xl border border-stone-200 dark:border-zinc-800 bg-white dark:bg-zinc-900";
const field =
  "w-full rounded-lg px-3 py-2 text-sm bg-white dark:bg-zinc-950 border border-stone-300 dark:border-zinc-700 focus:outline-none focus:border-amber-400";

export default function NostrProfilePanel({ npub }: { npub: string }) {
  const [picture, setPicture] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [about, setAbout] = useState("");
  const [nip05, setNip05] = useState("");
  const [lud16, setLud16] = useState("");
  const [website, setWebsite] = useState("");

  const [loading, setLoading] = useState(true);
  const [showPicker, setShowPicker] = useState(false);
  const [publishing, setPublishing] = useState(false);
  const [msg, setMsg] = useState<{ tone: "ok" | "err"; text: string } | null>(null);

  const signer = canSignProfile();

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

  function pickAvatar(v: string) {
    setPicture(v);
    setStoredAvatar(npub, v); // instant local effect across eXcalibur
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

  return (
    <div className={`${card} p-5`}>
      <div className="flex items-center gap-3 mb-3">
        <Avatar value={picture} size={56} />
        <div
          className="text-sm font-medium"
          title="Your kind-0 metadata — self-sovereign, shown in every Nostr client."
        >
          Nostr profile
        </div>
      </div>

      {loading ? (
        <div className="flex items-center gap-1.5 text-xs text-stone-400 dark:text-zinc-500 py-2"><Loader2 className="h-3.5 w-3.5 animate-spin" /> Reading from relays…</div>
      ) : (
        <>
          <div className="flex items-center gap-3">
            <Avatar value={picture} size={48} className="flex-none" />
            <button
              onClick={() => setShowPicker((v) => !v)}
              className="rounded-lg border border-stone-300 px-3 py-1.5 text-xs text-stone-600 transition-colors hover:bg-stone-100 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800"
            >
              {showPicker ? "Done" : "Change avatar"}
            </button>
          </div>
          {showPicker && (
            <div className="mt-3">
              <AvatarPicker value={picture} onChange={pickAvatar} />
            </div>
          )}

          <div className="mt-4 space-y-3">
            <label className="block text-xs text-stone-500 dark:text-zinc-400">
              Display name
              <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} className={`mt-1 ${field}`} placeholder="Satoshi" />
            </label>
            <label className="block text-xs text-stone-500 dark:text-zinc-400">
              Lightning address (lud16)
              <input value={lud16} onChange={(e) => setLud16(e.target.value)} className={`mt-1 ${field}`} placeholder="you@walletofsatoshi.com" />
            </label>
            <label className="block text-xs text-stone-500 dark:text-zinc-400">
              NIP-05
              <input value={nip05} onChange={(e) => setNip05(e.target.value)} className={`mt-1 ${field}`} placeholder="name@domain.com" />
            </label>
            <label className="block text-xs text-stone-500 dark:text-zinc-400">
              Website
              <input value={website} onChange={(e) => setWebsite(e.target.value)} className={`mt-1 ${field}`} placeholder="https://…" />
            </label>
            <label className="block text-xs text-stone-500 dark:text-zinc-400">
              About
              <textarea value={about} onChange={(e) => setAbout(e.target.value)} rows={2} className={`mt-1 ${field} resize-none`} placeholder="A short bio…" />
            </label>
          </div>

          {msg && (
            <div className={`mt-3 rounded-lg p-2.5 text-xs ${
              msg.tone === "ok"
                ? "bg-green-50 border border-green-200 text-green-700 dark:bg-green-500/10 dark:border-green-500/30 dark:text-green-400"
                : "bg-red-50 border border-red-200 text-red-700 dark:bg-red-500/10 dark:border-red-500/30 dark:text-red-400"
            }`}>
              {msg.text}
            </div>
          )}

          <div className="mt-3 flex items-center gap-3">
            <button
              onClick={publish}
              disabled={publishing || !signer}
              title={signer ? "Sign and publish your kind-0 to relays" : "Needs a session-key login or a NIP-07 extension"}
              className="bg-amber-600 hover:bg-amber-500 text-white text-sm px-4 py-2 rounded-lg disabled:opacity-40 transition-colors"
            >
              {publishing ? "Publishing…" : "Publish to Nostr"}
            </button>
            {!signer && (
              <span
                className="text-xs text-stone-400 dark:text-zinc-500"
                title="Sign in with a session key or a NIP-07 extension to publish. Avatar picks still apply locally."
              >
                Read-only
              </span>
            )}
          </div>
        </>
      )}
    </div>
  );
}
