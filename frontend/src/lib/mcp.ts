/**
 * eXcalibur MCP client.
 *
 * Pattern modeled on optionality-mcp/frontend/src/lib/mcp.ts:
 *
 * 1. One singleton @modelcontextprotocol/sdk Client over the
 *    StreamableHTTPClientTransport. The SDK handles the initialize
 *    handshake, SSE session tracking, and reconnection.
 * 2. Auth = uniform npub-proof. Two tactics, transparent to callers:
 *      - session nsec in browser → fresh kind-27235 inline proof per call
 *        (signInlineProof), scoped to the runtime tool name.
 *      - npub + DM login → the poison-phrase proof_token the wheel cached
 *        at receive_npub_proof time, sent verbatim.
 * 3. Bootstrap/auth/balance tools are free and pre-login-safe.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import { clearSessionNsec, hasSessionNsec, sessionNsecNpub } from "./sessionNsec";
import { signInlineProof } from "./inlineProof";

const SLUG = "excalibur";

const _envUrl = (import.meta.env.VITE_MCP_URL as string | undefined) ?? "";
const MCP_URL = _envUrl.startsWith("/")
  ? `${window.location.origin}${_envUrl}`
  : _envUrl;

const NPUB_STORAGE_KEY = "excalibur:patron_npub:v1";
const PROOF_STORAGE_KEY = "excalibur:proof_token:v1";

let client: Client | null = null;
let connecting: Promise<void> | null = null;

function requireUrl(): string {
  if (!MCP_URL) {
    throw new Error("VITE_MCP_URL is not configured. Set it in .env (e.g. /mcp).");
  }
  return MCP_URL;
}

async function getClient(): Promise<Client> {
  if (client) return client;
  if (connecting) {
    await connecting;
    return client!;
  }
  connecting = (async () => {
    const url = requireUrl();
    const c = new Client({ name: "excalibur-frontend", version: "0.1.0" });
    const transport = new StreamableHTTPClientTransport(new URL(url));
    await c.connect(transport);
    client = c;
    connecting = null;
  })();
  await connecting;
  return client!;
}

// ─── Stored identity ─────────────────────────────────────────────────────

export function getStoredNpub(): string {
  return window.localStorage.getItem(NPUB_STORAGE_KEY) ?? "";
}

export function setStoredNpub(npub: string): void {
  window.localStorage.setItem(NPUB_STORAGE_KEY, npub);
}

export function getStoredProof(): string {
  return window.localStorage.getItem(PROOF_STORAGE_KEY) ?? "";
}

export function setStoredProof(proof: string): void {
  window.localStorage.setItem(PROOF_STORAGE_KEY, proof);
}

/// "Logged in" = we have the patron's npub AND a way to prove ownership:
/// either a cached DM proof_token, or a session nsec whose npub matches.
export function isLoggedIn(): boolean {
  const npub = getStoredNpub();
  if (!npub) return false;
  if (getStoredProof()) return true;
  if (hasSessionNsec() && sessionNsecNpub() === npub) return true;
  return false;
}

export function logOut(): void {
  window.localStorage.removeItem(NPUB_STORAGE_KEY);
  window.localStorage.removeItem(PROOF_STORAGE_KEY);
  try {
    clearSessionNsec();
  } catch {
    /* noop */
  }
}

/// Resolve the proof for a paid call: prefer a fresh inline proof signed
/// by the session nsec (if it matches the stored npub), else the cached
/// DM proof_token. Stale session-nsec entries (from a prior identity) are
/// evicted so they don't poison the call.
function getCachedProof(toolName: string): string {
  try {
    const currentNpub = getStoredNpub();
    const sessionNpub = hasSessionNsec() ? sessionNsecNpub() : null;
    if (sessionNpub && sessionNpub === currentNpub) {
      return signInlineProof(`${SLUG}_${toolName}`);
    }
    if (sessionNpub && sessionNpub !== currentNpub) {
      clearSessionNsec();
    }
  } catch {
    /* fall through to the cached poison token */
  }
  return getStoredProof();
}

// ─── callTool ────────────────────────────────────────────────────────────

interface ToolResultText {
  type: string;
  text?: string;
}

interface ToolResult {
  isError?: boolean;
  content?: ToolResultText[];
  structuredContent?: unknown;
}

/// Thrown when the server rejects a paid call because the proof expired or
/// was never sent. The gate catches this and bounces the user to sign-in.
export class ProofRequiredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProofRequiredError";
  }
}

/// Tools whose wheel signature takes no npub/proof envelope. Pydantic
/// strict mode rejects unexpected kwargs, so we must NOT inject them here.
const BOOTSTRAP_TOOLS = new Set(["request_npub_proof", "receive_npub_proof", "service_status"]);

async function callTool<T = unknown>(
  toolName: string,
  args: Record<string, unknown> = {},
): Promise<T> {
  const c = await getClient();
  const merged: Record<string, unknown> = BOOTSTRAP_TOOLS.has(toolName)
    ? { ...args }
    : { npub: getStoredNpub(), proof: getCachedProof(toolName), ...args };

  let result: ToolResult;
  try {
    result = (await c.callTool(
      { name: `${SLUG}_${toolName}`, arguments: merged },
      undefined,
      { timeout: 120_000 },
    )) as ToolResult;
  } catch (e) {
    throw new Error(`${SLUG}_${toolName}: ${(e as Error).message}`);
  }

  if (result.isError) {
    const errText = (result.content ?? [])
      .filter((b) => b.type === "text" && typeof b.text === "string")
      .map((b) => String(b.text))
      .join("\n") || "Tool call failed";
    throw new Error(errText);
  }

  let payload: unknown;
  if (result.structuredContent !== undefined) {
    payload = result.structuredContent;
  } else {
    const textBlocks = (result.content ?? []).filter((b) => b.type === "text");
    if (textBlocks.length > 0) {
      const text = String(textBlocks[0].text ?? "");
      try {
        payload = JSON.parse(text);
      } catch {
        payload = text;
      }
    } else {
      payload = result;
    }
  }

  // Soft proof failures arrive as {success:false, error_code:...} with no
  // isError flag. Treat them as auth bounces: clear the stale token and
  // let the gate re-arm sign-in.
  if (payload && typeof payload === "object") {
    const p = payload as Record<string, unknown>;
    const errCode = String(p.error_code ?? "");
    if (p.success === false && (errCode === "PROOF_REQUIRED" || errCode === "PROOF_REFRESH_NEEDED")) {
      window.localStorage.removeItem(PROOF_STORAGE_KEY);
      throw new ProofRequiredError(String(p.error ?? "Sign-in required."));
    }
  }
  return payload as T;
}

// ─── Service / auth (free) ───────────────────────────────────────────────

export interface ServiceStatus {
  operator_npub_hash?: string;
  lifecycle?: string;
  message?: string;
  version?: string;
  tollbooth_dpyc_version?: string;
  process_id?: number;
  service?: string;
  slug?: string;
}

export async function serviceStatus(): Promise<ServiceStatus> {
  return callTool<ServiceStatus>("service_status", {});
}

export interface NpubProofResult {
  verified?: boolean;
  status?: string;
  message?: string;
  proof_token?: string;
  popped_dms?: number;
  expires_in_seconds?: number;
  expires_at?: string;
  error?: string;
}

/// Step 1 of DM login. Sends a Secure Courier challenge DM to the npub.
/// The user replies in their own Nostr client. Free.
export async function requestNpubProof(patronNpub: string): Promise<NpubProofResult> {
  return callTool<NpubProofResult>("request_npub_proof", { patron_npub: patronNpub });
}

/// Step 2 of DM login. Destructively drains DMs looking for the signed
/// reply to step 1. Call ONLY after the user has actually replied — do not
/// poll or speculatively retry (feedback_human_in_loop_courier). `poison`
/// is the proof_token from step 1.
export async function receiveNpubProof(patronNpub: string, poison: string): Promise<NpubProofResult> {
  return callTool<NpubProofResult>("receive_npub_proof", {
    patron_npub: patronNpub,
    poison,
  });
}

export interface CreditTranche {
  id: string;
  amount_sats: number;
  remaining_sats: number;
  expires_at: string | null;
  created_at: string | null;
}

export interface CheckBalanceResult {
  success?: boolean;
  balance_api_sats?: number;
  total_deposited_api_sats?: number;
  total_consumed_api_sats?: number;
  active_tranches?: number;
  tranches?: CreditTranche[];
  next_expiration_iso?: string;
  seed_balance_granted?: boolean;
  vault_unavailable?: boolean;
  warning?: string;
  npub?: string;
  error?: string;
  error_code?: string;
}

export async function checkBalance(): Promise<CheckBalanceResult> {
  return callTool<CheckBalanceResult>("check_balance", {});
}

export interface CheckPriceResult {
  success: boolean;
  tool_id?: string;
  tool_name?: string;
  base_cost?: number;
  effective_cost?: number;
  cost?: number;
  error?: string;
  error_code?: string;
}

export async function checkPrice(
  toolCapability: string,
  toolKwargs: Record<string, unknown> = {},
): Promise<CheckPriceResult> {
  return callTool<CheckPriceResult>("check_price", {
    tool_id: toolCapability,
    tool_kwargs: JSON.stringify(toolKwargs),
  });
}

export interface PurchaseCreditsResult {
  success?: boolean;
  invoice_id?: string;
  checkout_link?: string;
  lightning_invoice?: string;
  payment_request?: string;
  expires_at?: string;
  amount_sats?: number;
  error?: string;
  error_code?: string;
}

export async function purchaseCredits(sats: number): Promise<PurchaseCreditsResult> {
  return callTool<PurchaseCreditsResult>("purchase_credits", { amount_sats: sats });
}

export interface CheckPaymentResult {
  success?: boolean;
  status?: "New" | "Processing" | "Settled" | "Expired" | "Invalid" | string;
  message?: string;
  invoice_id?: string;
  credits_granted?: number;
  balance_api_sats?: number;
  error?: string;
  error_code?: string;
}

export async function checkPayment(invoiceId: string): Promise<CheckPaymentResult> {
  return callTool<CheckPaymentResult>("check_payment", { invoice_id: invoiceId });
}

export interface AccountStatementResult {
  success?: boolean;
  npub?: string;
  balance_api_sats?: number;
  total_deposited_api_sats?: number;
  total_consumed_api_sats?: number;
  total_expired_api_sats?: number;
  active_tranches?: number;
  today_usage?: Record<string, { calls: number; api_sats: number }>;
  error?: string;
}

export async function getAccountStatement(days = 30): Promise<AccountStatementResult> {
  return callTool<AccountStatementResult>("account_statement", { days });
}

// ─── Posts CRUD (paid) ───────────────────────────────────────────────────

export interface PostSummary {
  post_id: string;
  status: string;
  excerpt: string;
  publish_at: string | null;
  updated_at: string | null;
}

export interface ListPostsResult {
  posts?: PostSummary[];
  next_cursor?: string | null;
  error?: string;
}

export async function listPosts(
  opts: { status?: string; limit?: number; cursor?: string } = {},
): Promise<ListPostsResult> {
  const args: Record<string, unknown> = { limit: opts.limit ?? 25 };
  if (opts.status) args.status = opts.status;
  if (opts.cursor) args.cursor = opts.cursor;
  return callTool<ListPostsResult>("list_posts", args);
}

export interface PostRow {
  post_id?: string;
  id?: string;
  npub?: string;
  status?: string;
  doc?: unknown;
  text_cache?: string;
  publish_at?: string | null;
  recurrence?: unknown;
  cease_at?: string | null;
  last_sent_at?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  error?: string;
}

export async function getPost(postId: string): Promise<PostRow> {
  return callTool<PostRow>("get_post", { post_id: postId });
}

export interface CreatePostResult {
  post_id?: string;
  status?: string;
  created_at?: string;
  idempotent?: boolean;
  error?: string;
}

export async function createPost(opts: {
  doc: unknown;
  textCache?: string;
  status?: string;
  publishAt?: string;
  clientReqId?: string;
}): Promise<CreatePostResult> {
  const args: Record<string, unknown> = {
    doc: opts.doc,
    text_cache: opts.textCache ?? "",
    status: opts.status ?? "draft",
  };
  if (opts.publishAt) args.publish_at = opts.publishAt;
  if (opts.clientReqId) args.client_req_id = opts.clientReqId;
  return callTool<CreatePostResult>("create_post", args);
}

export interface UpdatePostResult {
  post_id?: string;
  status?: string;
  updated_at?: string;
  idempotent?: boolean;
  error?: string;
}

export async function updatePost(opts: {
  postId: string;
  patch: Record<string, unknown>;
  textCache?: string;
  clientReqId?: string;
}): Promise<UpdatePostResult> {
  const args: Record<string, unknown> = {
    post_id: opts.postId,
    patch: opts.patch,
  };
  if (opts.textCache !== undefined) args.text_cache = opts.textCache;
  if (opts.clientReqId) args.client_req_id = opts.clientReqId;
  return callTool<UpdatePostResult>("update_post", args);
}

export interface DeletePostResult {
  post_id?: string;
  status?: string;
  deleted?: boolean;
  error?: string;
}

export async function deletePost(postId: string, hard = false): Promise<DeletePostResult> {
  return callTool<DeletePostResult>("delete_post", { post_id: postId, hard });
}

// ─── Anthropic key (free, proof-gated — TaxSort tactic) ──────────────────

export interface AnthropicKeyResult {
  key?: string | null;
  message?: string;
  error?: string;
}

export async function getAnthropicKey(): Promise<AnthropicKeyResult> {
  return callTool<AnthropicKeyResult>("get_anthropic_key", {});
}
