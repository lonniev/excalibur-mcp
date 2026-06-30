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

export interface Env {
  MCP_URL: string; // public streamable-HTTP endpoint
  PROOF_KV: KVNamespace; // caches the protocol-issued, short-lived proof token
}

const SLUG = "excalibur";
const KEY = "proof_state";
const RENEW_BEFORE_MS = 24 * 60 * 60 * 1000; // re-request a day before expiry
const REREQUEST_AFTER_MS = 60 * 60 * 1000; // resend the DM if unanswered for 1h

type ProofState =
  | { phase: "pending"; poison: string; requestedAt: number }
  | { phase: "active"; token: string; expiresAt: number };

type Call = <R = any>(name: string, args?: Record<string, unknown>) => Promise<R>;

export default {
  async scheduled(_event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(tick(env).then((m) => console.log(`excalibur scheduler: ${m}`)));
  },
  // Manual trigger for testing: GET the worker URL to run one tick.
  async fetch(_req: Request, env: Env): Promise<Response> {
    return new Response(await tick(env), { status: 200 });
  },
};

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
  const r = await call("request_npub_proof", { patron_npub: operatorNpub });
  if (!r?.dpop_token) return `request_npub_proof returned no session phrase: ${JSON.stringify(r)}`;
  await env.PROOF_KV.put(
    KEY,
    JSON.stringify({ phase: "pending", poison: r.dpop_token, requestedAt: Date.now() }),
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
