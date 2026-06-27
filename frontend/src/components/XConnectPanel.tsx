// X account connection — the per-patron OAuth2 dance, made fluid.
//
// post_tweet posts to the logged-in npub's OWN X account, which requires an
// OAuth2 token. The same MCP tools the Claude.ai chat uses drive this:
//   begin_oauth → open authorize_url in a browser → check_oauth_status (poll)
// The callback lands at the Tollbooth OAuth2 collector; the wheel exchanges the
// code for a token server-side. This panel just sequences the clicks.

import { useEffect, useRef, useState } from "react";
import { AtSign, ExternalLink, CheckCircle2, Loader2, RefreshCw } from "lucide-react";
import { beginOauth, checkOauthStatus, getXConnection, getStoredNpub } from "../lib/mcp";
import { ensureXProfile } from "../lib/xProfile";

const card = "rounded-xl border border-stone-200 dark:border-zinc-800 bg-white dark:bg-zinc-900";

// "indeterminate" = we couldn't read the connection (cold/warming MCP or a
// transient error). It is NOT "disconnected" — we never show the misleading
// "Connect X" CTA in that case, only an honest "couldn't verify" + retry.
type Stage = "loading" | "disconnected" | "authorizing" | "connected" | "indeterminate";

// Cold-start retry budget: ~4s × 3 ≈ 12s, matching the MCP's "warming up,
// retry in 10–15s" guidance before we settle on an honest indeterminate state.
const RETRY_DELAY_MS = 4000;
const MAX_RETRIES = 3;

export default function XConnectPanel() {
  const [stage, setStage] = useState<Stage>("loading");
  const [authorizeUrl, setAuthorizeUrl] = useState("");
  const [expiresInSec, setExpiresInSec] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const [handle, setHandle] = useState("");
  const mounted = useRef(true);

  async function refreshConnection(retriesLeft = MAX_RETRIES): Promise<void> {
    const r = await getXConnection();
    if (!mounted.current) return;

    if (r.kind === "connected") {
      setExpiresInSec(r.oauth.access_token_expires_in_seconds ?? null);
      setStage("connected");
      try {
        const p = await ensureXProfile(getStoredNpub());
        if (mounted.current && p?.username) setHandle(`@${p.username}`);
      } catch {
        /* handle is a nicety — ignore */
      }
      return;
    }

    if (r.kind === "disconnected") {
      setStage((s) => (s === "authorizing" ? "authorizing" : "disconnected"));
      return;
    }

    // indeterminate — retry quietly while the MCP warms, then be honest.
    if (retriesLeft > 0) {
      setStage((s) => (s === "authorizing" || s === "connected" ? s : "loading"));
      await new Promise((res) => setTimeout(res, RETRY_DELAY_MS));
      if (!mounted.current) return;
      return refreshConnection(retriesLeft - 1);
    }
    setStage((s) => (s === "authorizing" || s === "connected" ? s : "indeterminate"));
  }

  useEffect(() => {
    mounted.current = true;
    void refreshConnection();
    return () => { mounted.current = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function connect() {
    setBusy(true);
    setError("");
    setNote("");
    // Open the popup SYNCHRONOUSLY within the click gesture — a window.open after
    // the `await` below is treated as non-user-initiated and gets popup-blocked
    // (that's why the tab "didn't appear"). We keep the handle (no noopener) so
    // we can point it at the authorize URL once begin_oauth returns. X can't be
    // framed in an iframe, so a popup window is the right vehicle.
    const popup = window.open("about:blank", "x-oauth", "width=600,height=760");
    try {
      const r = await beginOauth();
      if (r.error || r.success === false || !r.authorize_url) {
        popup?.close();
        setError(r.error || r.message || "Couldn't start the X authorization.");
        return;
      }
      setAuthorizeUrl(r.authorize_url);
      setStage("authorizing");
      if (popup && !popup.closed) {
        popup.location.href = r.authorize_url; // drive the already-open popup
      } else {
        // Popup was blocked anyway — the authorizing stage shows a click-through link.
        setNote("Popup blocked — use the “Open X authorization” button below.");
      }
    } catch (e) {
      popup?.close();
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function verify() {
    setBusy(true);
    setError("");
    setNote("");
    try {
      const r = await checkOauthStatus();
      if (r.status === "completed") {
        await refreshConnection();
        setNote("X account connected.");
        return;
      }
      if (r.error || r.success === false) {
        setError(r.error || "Couldn't check authorization status.");
        return;
      }
      setNote(r.message || "Still waiting — finish authorizing in the X tab, then check again.");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={`${card} p-5`}>
      <div className="mb-1 flex items-center gap-2">
        <AtSign className="h-4 w-4 text-amber-500" />
        <span className="text-sm font-medium">X account</span>
        {stage === "connected" && (
          <span className="ml-auto inline-flex items-center gap-1 text-xs text-green-600 dark:text-green-400">
            <CheckCircle2 className="h-3.5 w-3.5" /> Connected{handle && ` · ${handle}`}
          </span>
        )}
      </div>

      {stage === "loading" && (
        <p className="flex items-center gap-1.5 text-xs text-stone-400 dark:text-zinc-500"><Loader2 className="h-3.5 w-3.5 animate-spin" /> Checking connection…</p>
      )}

      {stage === "indeterminate" && (
        <>
          <p className="mb-3 text-xs leading-relaxed text-stone-500 dark:text-zinc-400">
            Couldn't read your X connection status — the service may be waking up.
            This doesn't mean you're disconnected; if you connected before, you still are.
          </p>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => { setStage("loading"); void refreshConnection(); }}
              disabled={busy}
              className="inline-flex items-center gap-1.5 rounded-lg border border-stone-300 px-4 py-2 text-sm text-stone-600 transition-colors hover:bg-stone-100 disabled:opacity-40 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800"
            >
              <RefreshCw className="h-4 w-4" /> Check again
            </button>
            <button
              onClick={connect}
              disabled={busy}
              className="inline-flex items-center gap-1.5 rounded-lg px-4 py-2 text-sm text-stone-500 transition-colors hover:bg-stone-100 disabled:opacity-40 dark:text-zinc-400 dark:hover:bg-zinc-800"
              title="Only if you've never linked an X account"
            >
              <ExternalLink className="h-4 w-4" /> Set up X
            </button>
          </div>
        </>
      )}

      {stage === "disconnected" && (
        <>
          <p className="mb-3 text-xs leading-relaxed text-stone-500 dark:text-zinc-400">
            Connect your X account so eXcalibur can post on your behalf. You'll authorize on X in a
            new tab; the callback returns through the Tollbooth OAuth2 collector — eXcalibur never
            sees your X password.
          </p>
          <button
            onClick={connect}
            disabled={busy}
            className="inline-flex items-center gap-1.5 rounded-lg bg-amber-600 px-4 py-2 text-sm text-white transition-colors hover:bg-amber-500 disabled:opacity-40"
          >
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <ExternalLink className="h-4 w-4" />}
            Connect X
          </button>
        </>
      )}

      {stage === "authorizing" && (
        <>
          <p className="mb-3 text-xs leading-relaxed text-stone-500 dark:text-zinc-400">
            Authorize eXcalibur on X, then come back and verify. If the popup didn't open,
            use the button below — it opens X in a new tab.
          </p>
          <div className="flex flex-wrap gap-2">
            <a
              href={authorizeUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 rounded-lg bg-amber-600 px-4 py-2 text-sm text-white transition-colors hover:bg-amber-500"
            >
              <ExternalLink className="h-4 w-4" /> Open X authorization
            </a>
            <button
              onClick={verify}
              disabled={busy}
              className="inline-flex items-center gap-1.5 rounded-lg border border-stone-300 px-4 py-2 text-sm text-stone-600 transition-colors hover:bg-stone-100 disabled:opacity-40 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800"
            >
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <CheckCircle2 className="h-4 w-4" />}
              I've authorized — verify
            </button>
            <button
              onClick={() => setStage("disconnected")}
              disabled={busy}
              className="rounded-lg border border-stone-300 px-3 py-2 text-sm text-stone-600 transition-colors hover:bg-stone-100 disabled:opacity-40 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800"
            >
              Cancel
            </button>
          </div>
        </>
      )}

      {stage === "connected" && (
        <>
          <p className="mb-3 text-xs leading-relaxed text-stone-500 dark:text-zinc-400">
            eXcalibur can post to your X account{handle ? ` as ${handle}` : ""}.
            {expiresInSec != null && expiresInSec > 0 && ` Access renews in about ${fmtDuration(expiresInSec)}.`}
          </p>
          <button
            onClick={connect}
            disabled={busy}
            className="inline-flex items-center gap-1.5 rounded-lg border border-stone-300 px-3 py-2 text-sm text-stone-600 transition-colors hover:bg-stone-100 disabled:opacity-40 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800"
          >
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            Reconnect
          </button>
        </>
      )}

      {error && (
        <div className="mt-3 rounded-lg border border-red-200 bg-red-50 p-2.5 text-xs text-red-700 dark:border-red-500/30 dark:bg-red-500/10 dark:text-red-400">
          {error}
        </div>
      )}
      {note && <div className="mt-3 text-xs italic text-stone-400 dark:text-zinc-500">{note}</div>}
    </div>
  );
}

function fmtDuration(sec: number): string {
  const h = Math.floor(sec / 3600);
  if (h >= 24) return `${Math.floor(h / 24)}d`;
  if (h >= 1) return `${h}h`;
  return `${Math.max(1, Math.floor(sec / 60))}m`;
}
