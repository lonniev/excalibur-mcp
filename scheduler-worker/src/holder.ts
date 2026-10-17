/**
 * The worker as a *holder*: a connection the operator MCP knows, into whose
 * wallet the operator npub is proven by DM. The worker holds no key and keeps
 * no grant; it keeps only this connection's OAuth tokens, in KV, and names the
 * npub on each call.
 *
 * Becoming a holder is the OAuth Authorization Code flow, run headless: the
 * operator's `/authorize` approves at once (a holder holds nothing until a DM
 * proves an npub into it), so the worker reads the code from its redirect
 * instead of sending a browser there. A refresh token is single-use, so each
 * refresh stores the pair it returns.
 */

const HOLDER_KEY = "holder";
const REFRESH_EARLY_MS = 60_000;
const REDIRECT_URI = "http://127.0.0.1/holder";

interface Tokens {
  clientId: string;
  accessToken: string;
  refreshToken: string;
  /** Unix ms. */
  expiresAt: number;
}

function b64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function token(origin: string, form: Record<string, string>, clientId: string): Promise<Tokens> {
  const r = await fetch(`${origin}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ ...form, client_id: clientId, resource: `${origin}/mcp` }),
  });
  if (!r.ok) throw new Error(`holder token refused (${r.status})`);
  const t: any = await r.json();
  return {
    clientId,
    accessToken: t.access_token,
    refreshToken: t.refresh_token,
    expiresAt: Date.now() + Number(t.expires_in ?? 3600) * 1000,
  };
}

async function login(origin: string): Promise<Tokens> {
  const reg = await fetch(`${origin}/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: "excalibur-scheduler",
      redirect_uris: [REDIRECT_URI],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
    }),
  });
  if (!reg.ok) throw new Error(`holder registration refused (${reg.status})`);
  const clientId: string = ((await reg.json()) as any).client_id;

  const verifier = b64url(crypto.getRandomValues(new Uint8Array(48)));
  const challenge = b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
  const state = b64url(crypto.getRandomValues(new Uint8Array(16)));
  const authorize = new URL(`${origin}/authorize`);
  authorize.search = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
    resource: `${origin}/mcp`,
  }).toString();
  const r = await fetch(authorize.toString(), { redirect: "manual" });
  const back = new URL(r.headers.get("location") ?? "", REDIRECT_URI);
  const code = back.searchParams.get("code");
  if (!code || back.searchParams.get("state") !== state) throw new Error(`holder authorize gave no code (${r.status})`);
  return token(origin, { grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: verifier }, clientId);
}

/**
 * The bearer for this tick: the stored access token, refreshed when it is
 * about to lapse, or a fresh connection when there is none or it was dropped.
 */
export async function holderBearer(kv: KVNamespace, mcpUrl: string): Promise<string> {
  const origin = new URL(mcpUrl).origin;
  const raw = await kv.get(HOLDER_KEY);
  let t: Tokens | null = raw ? (JSON.parse(raw) as Tokens) : null;
  if (t && t.expiresAt - REFRESH_EARLY_MS <= Date.now()) {
    t = await token(origin, { grant_type: "refresh_token", refresh_token: t.refreshToken }, t.clientId).catch(() => null);
  }
  if (!t) t = await login(origin);
  await kv.put(HOLDER_KEY, JSON.stringify(t));
  return t.accessToken;
}

/** Drop the connection; the next tick connects afresh (and asks for a new DM). */
export async function forgetHolder(kv: KVNamespace): Promise<void> {
  await kv.delete(HOLDER_KEY);
}
