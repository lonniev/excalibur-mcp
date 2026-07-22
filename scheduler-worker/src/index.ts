/**
 * eXcalibur scheduled-post cron Worker — protocol-honoring edition.
 *
 * A worker that wants to act on an npub's behalf is just another actor: it does
 * NOT store that npub's nsec or a baked proof token. It obtains authorization
 * the same way the FE and the Claude.ai chat do — the Secure Courier npub-proof
 * dance — and caches only the short-lived token it gets back (in KV, the way the
 * FE caches its proof in localStorage).
 *
 * It doesn't even carry the operator's npub. The MCP IS the operator (it holds
 * the operator nsec), so the worker just asks it "who are you?" via the free,
 * unauthenticated `list_canonical_identities` tool, which returns `operator_npub`.
 * The only configuration is the PUBLIC MCP URL. No secrets, no provisioned npub.
 *
 * Per tick:
 *   0. Ask the MCP for its operator npub (list_canonical_identities).
 *   1. Valid cached token  → call process_scheduled_posts (steady state; no
 *      courier traffic at all).
 *   2. Pending proof       → receive_npub_proof (poison-scoped, so polling only
 *      pops the matching reply — safe). On success, cache the token and fire.
 *   3. No / expired token  → request_npub_proof, which DMs the operator npub.
 *      A key-holder (the operator, via Studio or any nsec-holding agent) replies
 *      once; the next tick completes the proof. Re-runs ~monthly at token expiry.
 *
 * All domain logic — selecting due posts, billing each owner for post_tweet,
 * posting, rescheduling — stays server-side in excalibur-mcp.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { nip19, verifyEvent } from "nostr-tools";

export interface Env {
  MCP_URL: string; // public streamable-HTTP endpoint
  PROOF_KV: KVNamespace; // caches the protocol-issued, short-lived proof token
  FE_URL?: string; // public FE origin — the `verify_at` venue the DM points at
}

const SLUG = "excalibur";
const KEY = "proof_state";
const WORKER_VERSION = "0.2.0";
const RENEW_BEFORE_MS = 24 * 60 * 60 * 1000; // re-request a day before expiry
const REREQUEST_AFTER_MS = 60 * 60 * 1000; // resend the DM if unanswered for 1h
// Human description of the cron trigger — mirrors `crons` in wrangler.toml.
const CADENCE = "every 30 minutes (on the hour and the half hour)";

// The human-worded purpose the operator sees in the proof DM (Device-Grant
// `reason`). Names the actor (this scheduler), the ask (post the queued
// tweets), and the cadence (renews ~monthly) so a legit 3am renewal reads
// differently from an unsolicited impostor request.
const REASON =
  "eXcalibur's scheduled-post worker is asking to post the tweets you've queued, " +
  "on your behalf. Approving authorizes it for about 30 days; it renews roughly monthly.";

// The `u`-tag the FE signs (and this worker checks) on the kind-27235 event
// that gates GET /pending — the same inline-proof shape a paid tool call uses,
// bound here to the pending-view "capability" rather than a tool name.
const PENDING_U_TAG = "excalibur_scheduler_pending";
const PROOF_KIND = 27235;
const PENDING_PROOF_SKEW_S = 120; // clock-skew tolerance for the read gate

type ProofState =
  | { phase: "pending"; poison: string; requestedAt: number; reason: string }
  | { phase: "active"; token: string; expiresAt: number };

type Call = <R = any>(name: string, args?: Record<string, unknown>) => Promise<R>;

export default {
  async scheduled(_event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(tick(env).then((m) => console.log(`excalibur scheduler: ${m}`)));
  },
  // GET routes (all read server-side by the operator MCP, so no CORS to manage):
  //   /status  → non-sensitive config + current phase (no code, no token).
  //   /pending → the pending challenge phrase; gated to the operator npub.
  //   anything else → manual tick trigger for testing.
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname === "/status") return statusView(env);
    if (url.pathname === "/pending") return pendingView(req, env);
    return new Response(await tick(env), { status: 200 });
  },
};

// GET /status — what the scheduler is and what it's doing, minus anything
// sensitive. Never the challenge phrase (that's /pending, operator-gated) nor
// the active token. Config is global (not npub-specific), so this needs no gate.
async function statusView(env: Env): Promise<Response> {
  const raw = await env.PROOF_KV.get(KEY);
  const state: ProofState | null = raw ? (JSON.parse(raw) as ProofState) : null;
  const authorization =
    state?.phase === "pending"
      ? { phase: "pending" as const, reason: state.reason, requestedAt: state.requestedAt }
      : state?.phase === "active"
        ? { phase: "active" as const, expiresAt: state.expiresAt }
        : { phase: "idle" as const };
  return json({
    version: WORKER_VERSION,
    cadence: CADENCE,
    renewsBeforeExpiryHours: RENEW_BEFORE_MS / 3_600_000,
    rerequestAfterHours: REREQUEST_AFTER_MS / 3_600_000,
    mcpUrl: env.MCP_URL,
    verifyAt: env.FE_URL ?? null,
    authorization,
  });
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

// GET /pending?proof=<url-encoded kind-27235 event JSON>. Returns the pending
// challenge phrase ONLY to a caller proving they are the operator npub. The MCP
// satisfies this by signing with the operator key it already holds — no shared
// secret, just the identity the request is addressed to. The active bearer
// token is NEVER surfaced; the pending phrase is the string already DM'd.
async function pendingView(req: Request, env: Env): Promise<Response> {
  const proofRaw = new URL(req.url).searchParams.get("proof");
  if (!proofRaw) return json({ error: "proof_required" }, 401);

  return withClient(env.MCP_URL, async (call) => {
    const whoami = await call("list_canonical_identities");
    const operatorNpub = String(whoami?.operator_npub ?? "");
    if (!operatorNpub.startsWith("npub1")) {
      return json({ error: "operator_npub_unresolved" }, 502);
    }
    if (!verifyPendingProof(proofRaw, operatorNpub)) {
      // Same 403 whether the signature is bad or the signer simply isn't the
      // operator — a non-operator learns nothing about the scheduler's state.
      return json({ error: "not_operator" }, 403);
    }

    const raw = await env.PROOF_KV.get(KEY);
    const state: ProofState | null = raw ? (JSON.parse(raw) as ProofState) : null;
    if (state?.phase === "pending") {
      return json({
        phase: "pending",
        code: state.poison, // the phrase the operator matches against the DM
        reason: state.reason,
        requestedAt: state.requestedAt,
      });
    }
    if (state?.phase === "active") return json({ phase: "active", expiresAt: state.expiresAt });
    return json({ phase: "idle" });
  }).catch((e) => json({ error: `pending_view_failed: ${(e as Error).message}` }, 502));
}

// Verify a kind-27235 event authorizes reading the pending view: valid Schnorr
// signature, our `u`-tag, fresh, and signed by the operator npub. Keyless —
// signature verification needs no secret on the worker.
function verifyPendingProof(proofRaw: string, operatorNpub: string): boolean {
  try {
    const ev = JSON.parse(proofRaw);
    if (ev?.kind !== PROOF_KIND) return false;
    const u = (ev.tags ?? []).find((t: string[]) => t[0] === "u")?.[1];
    if (u !== PENDING_U_TAG) return false;
    const age = Math.floor(Date.now() / 1000) - Number(ev.created_at ?? 0);
    if (!Number.isFinite(age) || Math.abs(age) > PENDING_PROOF_SKEW_S) return false;
    const decoded = nip19.decode(operatorNpub);
    if (decoded.type !== "npub" || ev.pubkey !== decoded.data) return false;
    return verifyEvent(ev);
  } catch {
    return false;
  }
}

async function tick(env: Env): Promise<string> {
  const raw = await env.PROOF_KV.get(KEY);
  const state: ProofState | null = raw ? (JSON.parse(raw) as ProofState) : null;
  const now = Date.now();

  return withClient(env.MCP_URL, async (call) => {
    // 0) Ask the MCP who it is — it holds the operator nsec, so it's the source
    // of truth for its own npub. Free, unauthenticated, no npub input.
    const whoami = await call("list_canonical_identities");
    const operatorNpub = String(whoami?.operator_npub ?? "");
    if (!operatorNpub.startsWith("npub1")) {
      return `could not resolve operator npub from MCP: ${JSON.stringify(whoami).slice(0, 200)}`;
    }

    // 1) Fresh cached token → fire due posts. No courier traffic.
    if (state?.phase === "active" && state.expiresAt - now > RENEW_BEFORE_MS) {
      return fire(call, env, operatorNpub, state.token);
    }

    // 2) Proof in flight → try to complete it (poison-scoped: safe to poll).
    if (state?.phase === "pending") {
      const r = await call("receive_npub_proof", {
        patron_npub: operatorNpub,
        dpop_token: state.poison,
      });
      if (r?.success && r?.dpop_token) {
        const expiresAt = now + (Number(r.expires_in_seconds) || 0) * 1000;
        await env.PROOF_KV.put(KEY, JSON.stringify({ phase: "active", token: r.dpop_token, expiresAt }));
        return fire(call, env, operatorNpub, r.dpop_token);
      }
      if (now - state.requestedAt > REREQUEST_AFTER_MS) return request(call, env, operatorNpub);
      return "Awaiting operator reply to the proof DM.";
    }

    // 3) No / expiring token → request a fresh proof (DMs the operator npub).
    return request(call, env, operatorNpub);
  });
}

async function request(call: Call, env: Env, operatorNpub: string): Promise<string> {
  // Carry a human-worded `reason` (what/why) and a `verify_at` venue (RFC 8628
  // Device-Grant): the DM tells the operator this same phrase is shown, owner-
  // private, at the FE — approve ONLY if the two surfaces match. The FE view is
  // fed from this worker's KV, which an impostor can't write, so an unfamiliar
  // or unreachable venue fails safe.
  const r = await call("request_npub_proof", {
    patron_npub: operatorNpub,
    reason: REASON,
    ...(env.FE_URL ? { verify_at: env.FE_URL } : {}),
  });
  if (!r?.dpop_token) return `request_npub_proof returned no session phrase: ${JSON.stringify(r)}`;
  await env.PROOF_KV.put(
    KEY,
    JSON.stringify({
      phase: "pending",
      poison: r.dpop_token,
      requestedAt: Date.now(),
      reason: REASON,
    }),
  );
  return "Sent a proof-request DM to the operator npub — reply from a key-holder (Studio) to authorize the scheduler.";
}

async function fire(call: Call, env: Env, operatorNpub: string, dpopToken: string): Promise<string> {
  const r = await call("process_scheduled_posts", { npub: operatorNpub, dpop_token: dpopToken });
  // If the token was rejected (expired/revoked), drop it so the next tick
  // re-runs the proof dance rather than wedging on a dead token.
  const code = String(r?.error_code ?? "").toLowerCase();
  if (r?.success === false && (code.includes("proof") || code.includes("dpop_token"))) {
    await env.PROOF_KV.delete(KEY);
    return `proof rejected (${code}); cleared — will re-request next tick.`;
  }
  return `process_scheduled_posts: ${JSON.stringify(r)}`;
}

async function withClient<T>(url: string, fn: (call: Call) => Promise<T>): Promise<T> {
  const client = new Client({ name: "excalibur-scheduler", version: "1.0.0" }, { capabilities: {} });
  const transport = new StreamableHTTPClientTransport(new URL(url));
  await client.connect(transport);
  const call: Call = async (name, args = {}) => {
    const res: any = await client.callTool(
      { name: `${SLUG}_${name}`, arguments: args },
      undefined,
      // process_scheduled_posts resolves due posts' dynamic blocks inline (LLM +
      // web search), which can run minutes — well past the old 60s. The MCP
      // claims each post atomically (scheduled→sending) before working it, so a
      // timeout here can never double-post: an unfinished post stays claimed and
      // is reclaimed later. 5min covers the default 210s runtime budget; longer
      // budgets are the durable-executor follow-up. (The quick proof/whoami
      // calls return immediately regardless of this ceiling.)
      { timeout: 300_000 },
    );
    if (res?.structuredContent !== undefined) return res.structuredContent;
    const text = (res?.content ?? []).find((b: any) => b.type === "text")?.text;
    try {
      return JSON.parse(String(text));
    } catch {
      return text;
    }
  };
  try {
    return await fn(call);
  } finally {
    await client.close().catch(() => {});
  }
}
