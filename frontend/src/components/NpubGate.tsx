import { useState } from "react";
import { generateSecretKey, getPublicKey, nip19 } from "nostr-tools";
import {
  receiveNpubProof,
  requestNpubProof,
  setStoredNpub,
  setStoredProof,
} from "../lib/mcp";
import { setSessionNsec } from "../lib/sessionNsec";

type Tab = "dm" | "direct";

const card =
  "rounded-xl border border-stone-200 dark:border-zinc-800 bg-white dark:bg-zinc-900";
const input =
  "w-full rounded-lg px-3 py-2.5 text-sm bg-white dark:bg-zinc-950 border border-stone-300 dark:border-zinc-700 focus:outline-none focus:border-amber-400 dark:focus:border-amber-500";
const primary =
  "w-full bg-amber-600 hover:bg-amber-500 text-white text-sm py-2.5 rounded-lg disabled:opacity-40 transition-colors";
const errBox =
  "rounded-lg p-3 text-xs bg-red-50 border border-red-200 text-red-700 dark:bg-red-500/10 dark:border-red-500/30 dark:text-red-400";

export default function NpubGate({ onLogin }: { onLogin: () => void }) {
  const [tab, setTab] = useState<Tab>("dm");

  return (
    <div className="max-w-md mx-auto mt-16 px-4">
      <div className="flex items-center gap-2 mb-1">
        <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
        <h1 className="text-lg font-semibold">Sign in to eXcalibur</h1>
      </div>
      <p className="text-sm text-stone-500 dark:text-zinc-400 mb-5">
        Your Nostr npub is your identity. Posts and credits are keyed to it.
      </p>

      <div className="flex gap-2 mb-5 text-sm">
        {(["dm", "direct"] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-3 py-1.5 rounded-lg transition-colors ${
              tab === t
                ? "bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-400"
                : "text-stone-500 hover:bg-stone-100 dark:text-zinc-400 dark:hover:bg-zinc-800"
            }`}
          >
            {t === "dm" ? "Sign in with DM" : "Use a session key"}
          </button>
        ))}
      </div>

      <div className={`${card} p-4`}>
        {tab === "dm" ? <DmFlow onLogin={onLogin} /> : <DirectFlow onLogin={onLogin} />}
      </div>
    </div>
  );
}

function DmFlow({ onLogin }: { onLogin: () => void }) {
  const [npub, setNpub] = useState("");
  const [token, setToken] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function sendChallenge() {
    const clean = npub.trim();
    if (!clean.startsWith("npub1")) {
      setError("Enter a valid npub1… identity.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const r = await requestNpubProof(clean);
      if (r.proof_token) setToken(r.proof_token);
      else setError(r.error || r.message || "Could not start the proof challenge.");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function verify() {
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      const r = await receiveNpubProof(npub.trim(), token);
      // Current wheel signals success via `success: true` (+ `proven_npub`);
      // older builds used `verified`. Accept either.
      if (r.success === true || r.verified === true) {
        setStoredNpub(r.proven_npub || npub.trim());
        setStoredProof(r.proof_token || token);
        onLogin();
      } else {
        setError(r.error || r.message || "No matching reply found yet — reply to the DM, then retry.");
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-3">
      <input
        type="text"
        value={npub}
        onChange={(e) => setNpub(e.target.value)}
        placeholder="npub1…"
        disabled={!!token}
        className={`${input} font-mono disabled:opacity-60`}
      />
      {!token ? (
        <button onClick={sendChallenge} disabled={busy} className={primary}>
          {busy ? "Sending…" : "Send proof DM"}
        </button>
      ) : (
        <div className="space-y-3">
          <div className="rounded-lg p-3 text-xs bg-amber-50 border border-amber-200 text-stone-600 dark:bg-amber-500/10 dark:border-amber-500/30 dark:text-zinc-300">
            A challenge DM was sent to your npub. Open your Nostr client, reply to it
            (your client signs the reply), then verify below.
            <div className="mt-2 font-mono">
              session phrase: <span className="text-amber-700 dark:text-amber-400">{token}</span>
            </div>
          </div>
          <button onClick={verify} disabled={busy} className={primary}>
            {busy ? "Verifying…" : "I've replied — verify"}
          </button>
        </div>
      )}
      {error && <div className={errBox}>{error}</div>}
    </div>
  );
}

function DirectFlow({ onLogin }: { onLogin: () => void }) {
  const [nsec, setNsec] = useState("");
  const [error, setError] = useState<string | null>(null);

  function generate() {
    setNsec(nip19.nsecEncode(generateSecretKey()));
    setError(null);
  }

  function signIn() {
    const clean = nsec.trim();
    try {
      setSessionNsec(clean);
      const decoded = nip19.decode(clean);
      if (decoded.type !== "nsec") throw new Error("Not an nsec");
      setStoredNpub(nip19.npubEncode(getPublicKey(decoded.data as Uint8Array)));
      onLogin();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-stone-500 dark:text-zinc-400">
        A session key lives only in this browser and signs each paid call inline.
        Anyone with access to this browser can use it — generate a fresh one for a kiosk.
      </p>
      <textarea
        value={nsec}
        onChange={(e) => setNsec(e.target.value)}
        placeholder="nsec1…"
        rows={2}
        className={`${input} font-mono`}
      />
      <div className="flex gap-2">
        <button
          onClick={generate}
          className="flex-1 border border-stone-300 dark:border-zinc-700 text-stone-600 dark:text-zinc-300 text-sm py-2.5 rounded-lg hover:bg-stone-100 dark:hover:bg-zinc-800 transition-colors"
        >
          Generate
        </button>
        <button onClick={signIn} disabled={!nsec.trim()} className={primary}>
          Sign in
        </button>
      </div>
      {error && <div className={errBox}>{error}</div>}
    </div>
  );
}
