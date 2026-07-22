import { useState } from "react";
import { generateSecretKey, getPublicKey, nip19 } from "nostr-tools";
import {
  forgetRecentLogin,
  getStoredNpub,
  getValidRecentLogins,
  receiveNpubProof,
  recordRecentLogin,
  requestNpubProof,
  setStoredNpub,
  setStoredProof,
  type RecentLogin,
} from "../lib/mcp";
import { setSessionNsec } from "../lib/sessionNsec";

// Flow mirrors optionality-mcp's NpubGate (the reference "good" npub-login):
//   begin → request_npub_proof → awaiting-reply → receive_npub_proof → app.
// Success criterion matches optionality: NOT a `verified` flag, but
// "no `error` field AND a proof_token came back". A single input accepts
// either an npub (DM challenge) or an nsec (instant in-browser session key).

type Stage = "begin" | "awaiting" | "checking";

const card = "rounded-xl border border-stone-200 dark:border-zinc-800 bg-white dark:bg-zinc-900";
const input =
  "w-full rounded-lg px-3 py-2.5 text-sm bg-white dark:bg-zinc-950 border border-stone-300 dark:border-zinc-700 focus:outline-none focus:border-amber-400 dark:focus:border-amber-500 font-mono";
const primary =
  "w-full bg-amber-600 hover:bg-amber-500 text-white text-sm py-2.5 rounded-lg disabled:opacity-40 transition-colors";
const ghost =
  "w-full text-sm py-2 rounded-lg border border-stone-300 dark:border-zinc-700 text-stone-600 dark:text-zinc-300 hover:bg-stone-100 dark:hover:bg-zinc-800 disabled:opacity-40 transition-colors";
const errBox =
  "rounded-lg p-3 text-xs bg-red-50 border border-red-200 text-red-700 dark:bg-red-500/10 dark:border-red-500/30 dark:text-red-400";

export default function NpubGate({
  onLogin,
  operatorHash,
  notice,
}: {
  onLogin: () => void;
  operatorHash?: string;
  // A routine re-auth prompt (e.g. the cached proof lapsed while the user was
  // working). Rendered as a calm amber note, not a red error — nothing broke.
  notice?: string;
}) {
  const [value, setValue] = useState(getStoredNpub());
  const [stage, setStage] = useState<Stage>("begin");
  const [pendingProof, setPendingProof] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const [recents, setRecents] = useState<RecentLogin[]>(() => getValidRecentLogins());
  const [generatedHint, setGeneratedHint] = useState(false);

  const trimmed = value.trim();
  const isNsec = trimmed.startsWith("nsec1") && trimmed.length > 8;
  const isNpub = trimmed.startsWith("npub1") && trimmed.length >= 60;
  const valid = isNsec || isNpub;

  function reuseRecent(entry: RecentLogin) {
    setStoredNpub(entry.npub);
    setStoredProof(entry.proof);
    recordRecentLogin(entry.npub, entry.proof, Math.floor((entry.expiresAt - Date.now()) / 1000));
    onLogin();
  }

  function forget(npub: string) {
    forgetRecentLogin(npub);
    setRecents(getValidRecentLogins());
  }

  function generateKey() {
    const nsec = nip19.nsecEncode(generateSecretKey());
    setValue(nsec);
    setGeneratedHint(true);
    setError("");
  }

  // nsec path — derive npub, stash the session key, sign in. Every paid call
  // then signs a fresh inline kind-27235 proof from this key.
  function signInWithNsec() {
    setError("");
    try {
      const decoded = nip19.decode(trimmed);
      if (decoded.type !== "nsec") throw new Error("Not a bech32 nsec");
      setSessionNsec(trimmed);
      setStoredNpub(nip19.npubEncode(getPublicKey(decoded.data as Uint8Array)));
      onLogin();
    } catch (e) {
      setError(`Couldn't read that nsec: ${(e as Error).message}`);
    }
  }

  async function begin() {
    if (!isNpub) {
      setError("Enter a valid npub1… key.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      // Name THIS page as the Device-Grant verification venue (RFC 8628): the
      // DM will tell the human the phrase below was shown here, so a phrase
      // that doesn't match this tab is not to be trusted. The reason states,
      // in the human's own terms, why the DM arrived — they started this login.
      const r = await requestNpubProof(
        trimmed,
        window.location.origin,
        `You requested to log in to eXcalibur (${window.location.host}).`,
      );
      if (r.error) {
        setError(r.error);
        return;
      }
      if (!r.dpop_token) {
        setError("The service did not return a session phrase. Try again.");
        return;
      }
      setStoredNpub(trimmed);
      setPendingProof(r.dpop_token);
      setStage("awaiting");
    } catch (e) {
      setError(`Could not send the proof DM: ${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  async function finish() {
    setBusy(true);
    setError("");
    setStage("checking");
    try {
      const r = await receiveNpubProof(trimmed, pendingProof);
      // optionality's criterion: an error means not yet / failed; otherwise a
      // returned token (or the one we already hold) means verified.
      if (r.error) {
        setError(r.error);
        setStage("awaiting");
        return;
      }
      const token = r.dpop_token || pendingProof;
      if (!token) {
        setError("No session phrase came back. Resend the DM and try again.");
        setStage("awaiting");
        return;
      }
      setStoredNpub(r.proven_npub || trimmed);
      setStoredProof(token);
      if (r.expires_in_seconds && r.expires_in_seconds > 0) {
        recordRecentLogin(r.proven_npub || trimmed, token, r.expires_in_seconds);
        const h = Math.floor(r.expires_in_seconds / 3600);
        setNote(`Proof cached for ~${h > 0 ? `${h}h` : `${Math.round(r.expires_in_seconds / 60)}m`}.`);
      }
      onLogin();
    } catch (e) {
      setError(`Verification failed: ${(e as Error).message}`);
      setStage("awaiting");
    } finally {
      setBusy(false);
    }
  }

  function reset() {
    setStage("begin");
    setPendingProof("");
    setError("");
  }

  return (
    <div className="max-w-md mx-auto mt-16 px-4">
      <div className="flex items-center gap-2 mb-1">
        <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
        <h1 className="text-lg font-semibold">Sign in to eXcalibur</h1>
      </div>
      <p className="text-sm text-stone-500 dark:text-zinc-400 mb-5">
        Your Nostr npub is your identity. No email, no password, no KYC.
      </p>

      {notice && (
        <div className="mb-5 rounded-lg p-3 text-xs bg-amber-50 border border-amber-200 text-amber-800 dark:bg-amber-500/10 dark:border-amber-500/30 dark:text-amber-300">
          {notice}
        </div>
      )}

      {stage === "begin" && recents.length > 0 && (
        <div className="mb-5">
          <div className="text-xs uppercase tracking-wider text-stone-400 dark:text-zinc-500 mb-2">
            Recent identities
          </div>
          <div className="space-y-1.5">
            {recents.map((e) => (
              <div key={e.npub} className="flex gap-1.5">
                <button
                  onClick={() => reuseRecent(e)}
                  disabled={busy}
                  title={`Re-enter as ${e.npub} on the cached proof`}
                  className={`${card} flex-1 flex items-center justify-between px-3 py-2.5 text-left hover:border-amber-300 dark:hover:border-amber-500/40 transition-colors`}
                >
                  <span className="font-mono text-xs truncate">
                    {e.npub.slice(0, 12)}…{e.npub.slice(-6)}
                  </span>
                  <span className="text-xs text-amber-600 dark:text-amber-400 shrink-0 ml-2">
                    {ttl(e.expiresAt)} left
                  </span>
                </button>
                <button
                  onClick={() => forget(e.npub)}
                  disabled={busy}
                  title="Forget this identity"
                  className="w-9 rounded-lg border border-stone-300 dark:border-zinc-700 text-stone-400 dark:text-zinc-500 hover:bg-stone-100 dark:hover:bg-zinc-800 transition-colors"
                >
                  ×
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className={`${card} p-4 space-y-3`}>
        {stage === "begin" ? (
          <>
            <label className="block text-xs uppercase tracking-wider text-stone-400 dark:text-zinc-500">
              Paste your npub or nsec
            </label>
            <input
              type={isNsec ? "password" : "text"}
              value={value}
              onChange={(e) => {
                setValue(e.target.value);
                setGeneratedHint(false);
              }}
              onKeyDown={(e) => {
                if (e.key !== "Enter" || !valid || busy) return;
                isNsec ? signInWithNsec() : void begin();
              }}
              placeholder="npub1… (DM challenge) or nsec1… (instant)"
              spellCheck={false}
              autoCapitalize="off"
              autoCorrect="off"
              className={input}
            />
            {generatedHint && (
              <div className="rounded-lg p-2.5 text-xs bg-amber-50 border border-amber-200 text-stone-600 dark:bg-amber-500/10 dark:border-amber-500/30 dark:text-zinc-300">
                New key generated. <b>Save this nsec</b> somewhere safe — it's the only
                copy and it lives only in this browser.
              </div>
            )}
            <button
              onClick={() => (isNsec ? signInWithNsec() : void begin())}
              disabled={!valid || busy}
              className={primary}
            >
              {busy ? "Sending…" : isNsec ? "Sign in" : isNpub ? "Send proof DM" : "Sign in"}
            </button>
            <p className="text-xs text-stone-500 dark:text-zinc-400">
              {isNsec
                ? "Your nsec stays in this browser and signs each call inline."
                : "We send a Secure Courier DM to your npub. Reply from your Nostr client — your signature is the proof."}
            </p>
            <button onClick={generateKey} className={ghost}>
              Generate a new key
            </button>
          </>
        ) : (
          <>
            <div className="rounded-lg p-3 text-xs bg-amber-50 border border-amber-200 text-stone-600 dark:bg-amber-500/10 dark:border-amber-500/30 dark:text-zinc-300 space-y-1.5">
              <div className="font-medium text-amber-700 dark:text-amber-400">
                DM sent — check your Nostr client.
              </div>
              <div>Reply with any text. Your signature on that DM is the proof.</div>
              {operatorHash && (
                <div>
                  Verify the sender — operator fingerprint:{" "}
                  <span className="font-mono text-amber-700 dark:text-amber-400">🔒 {operatorHash}</span>
                </div>
              )}
            </div>
            {pendingProof && (
              <div className="rounded-lg p-3 text-xs bg-white dark:bg-zinc-950 border border-amber-300 dark:border-amber-500/40 space-y-2">
                <div className="uppercase tracking-wider text-[10px] text-stone-400 dark:text-zinc-500">
                  Confirmation code
                </div>
                <div className="font-mono text-base text-amber-700 dark:text-amber-400 select-all">
                  {pendingProof}
                </div>
                <div className="text-stone-500 dark:text-zinc-400 leading-relaxed">
                  This same code appears in the DM. <b>Approve the DM only if the
                  code there matches the one shown here.</b> If they differ — or the
                  DM points you somewhere other than this site — do not reply.
                </div>
              </div>
            )}
            <button onClick={() => void finish()} disabled={busy} className={primary}>
              {stage === "checking" || busy ? "Checking…" : "I've replied — verify"}
            </button>
            <button onClick={() => void begin()} disabled={busy} className={ghost}>
              Resend DM
            </button>
            <button
              onClick={reset}
              disabled={busy}
              className="w-full text-xs py-1.5 text-stone-400 dark:text-zinc-500 hover:text-stone-700 dark:hover:text-zinc-200 transition-colors"
            >
              Use a different npub
            </button>
          </>
        )}

        {error && <div className={errBox}>{error}</div>}
        {note && (
          <div className="text-xs text-center text-stone-400 dark:text-zinc-500 italic">{note}</div>
        )}
      </div>
    </div>
  );
}

function ttl(expiresAt: number): string {
  const min = Math.max(0, Math.floor((expiresAt - Date.now()) / 60000));
  const hr = Math.floor(min / 60);
  return hr >= 1 ? `${hr}h ${min % 60}m` : `${min}m`;
}
