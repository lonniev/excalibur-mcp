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

export default function NpubGate({ onLogin }: { onLogin: () => void }) {
  const [tab, setTab] = useState<Tab>("dm");

  return (
    <div className="max-w-md mx-auto mt-12 px-4">
      <h1 className="text-lg font-semibold text-stone-800 mb-1">Sign in</h1>
      <p className="text-sm text-stone-500 mb-5">
        Your Nostr npub is your identity. Posts and credits are keyed to it.
      </p>

      <div className="flex gap-2 mb-5 text-sm">
        <button
          onClick={() => setTab("dm")}
          className={`px-3 py-1.5 rounded transition-colors ${
            tab === "dm" ? "bg-amber-100 text-amber-800" : "text-stone-500 hover:bg-stone-100"
          }`}
        >
          Sign in with DM
        </button>
        <button
          onClick={() => setTab("direct")}
          className={`px-3 py-1.5 rounded transition-colors ${
            tab === "direct" ? "bg-amber-100 text-amber-800" : "text-stone-500 hover:bg-stone-100"
          }`}
        >
          Use a session key
        </button>
      </div>

      {tab === "dm" ? <DmFlow onLogin={onLogin} /> : <DirectFlow onLogin={onLogin} />}
    </div>
  );
}

// ── Tactic A: existing npub, prove ownership via a Secure Courier DM ──────

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
      if (r.proof_token) {
        setToken(r.proof_token);
      } else {
        setError(r.error || r.message || "Could not start the proof challenge.");
      }
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
      if (r.verified) {
        setStoredNpub(npub.trim());
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
        className="w-full border border-stone-200 rounded-lg px-3 py-2.5 text-sm font-mono focus:outline-none focus:border-amber-400 disabled:bg-stone-100"
      />

      {!token ? (
        <button
          onClick={sendChallenge}
          disabled={busy}
          className="w-full bg-amber-600 text-white text-sm py-2.5 rounded-lg hover:bg-amber-500 disabled:opacity-40 transition-colors"
        >
          {busy ? "Sending…" : "Send proof DM"}
        </button>
      ) : (
        <div className="space-y-3">
          <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 text-xs text-stone-600">
            A challenge DM was sent to your npub. Open your Nostr client, reply to
            it (your client signs the reply), then click verify below.
            <div className="mt-2 font-mono text-stone-500">
              session phrase: <span className="text-amber-700">{token}</span>
            </div>
          </div>
          <button
            onClick={verify}
            disabled={busy}
            className="w-full bg-amber-600 text-white text-sm py-2.5 rounded-lg hover:bg-amber-500 disabled:opacity-40 transition-colors"
          >
            {busy ? "Verifying…" : "I've replied — verify"}
          </button>
        </div>
      )}

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-xs text-red-700">
          {error}
        </div>
      )}
    </div>
  );
}

// ── Tactic B: a browser-held session key that inline-signs each call ──────

function DirectFlow({ onLogin }: { onLogin: () => void }) {
  const [nsec, setNsec] = useState("");
  const [error, setError] = useState<string | null>(null);

  function generate() {
    const sk = generateSecretKey();
    setNsec(nip19.nsecEncode(sk));
    setError(null);
  }

  function signIn() {
    const clean = nsec.trim();
    try {
      setSessionNsec(clean);
      const decoded = nip19.decode(clean);
      if (decoded.type !== "nsec") throw new Error("Not an nsec");
      const npub = nip19.npubEncode(getPublicKey(decoded.data as Uint8Array));
      setStoredNpub(npub);
      onLogin();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-stone-500">
        A session key lives only in this browser and signs each paid call
        inline. Anyone with access to this browser can use it — generate a
        fresh one for a kiosk.
      </p>
      <textarea
        value={nsec}
        onChange={(e) => setNsec(e.target.value)}
        placeholder="nsec1…"
        rows={2}
        className="w-full border border-stone-200 rounded-lg px-3 py-2.5 text-sm font-mono focus:outline-none focus:border-amber-400"
      />
      <div className="flex gap-2">
        <button
          onClick={generate}
          className="flex-1 border border-stone-300 text-stone-600 text-sm py-2.5 rounded-lg hover:bg-stone-100 transition-colors"
        >
          Generate
        </button>
        <button
          onClick={signIn}
          disabled={!nsec.trim()}
          className="flex-1 bg-amber-600 text-white text-sm py-2.5 rounded-lg hover:bg-amber-500 disabled:opacity-40 transition-colors"
        >
          Sign in
        </button>
      </div>
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-xs text-red-700">
          {error}
        </div>
      )}
    </div>
  );
}
