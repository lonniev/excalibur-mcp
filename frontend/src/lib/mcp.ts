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
import { debugPush } from "./debugLog";
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

// ─── Recent logins (skip the DM on return) ───────────────────────────────
// Ported from optionality-mcp's proven pattern: cache (npub, proof_token,
// expiresAt) tuples so a returning patron re-enters on the cached proof
// until the server-side cache actually expires.

const RECENT_LOGINS_KEY = "excalibur:recent-logins:v1";
const MAX_RECENT_LOGINS = 5;

export interface RecentLogin {
  npub: string;
  proof: string;
  expiresAt: number; // unix ms
  lastUsed: number; // unix ms
}

function readRecentLogins(): RecentLogin[] {
  try {
    const raw = window.localStorage.getItem(RECENT_LOGINS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (e): e is RecentLogin =>
        typeof e === "object" && e !== null &&
        typeof e.npub === "string" && typeof e.proof === "string" &&
        typeof e.expiresAt === "number" && typeof e.lastUsed === "number",
    );
  } catch {
    return [];
  }
}

function writeRecentLogins(entries: RecentLogin[]): void {
  window.localStorage.setItem(RECENT_LOGINS_KEY, JSON.stringify(entries));
}

/// Unexpired recent logins, MRU-sorted. Prunes expired entries as a side effect.
export function getValidRecentLogins(): RecentLogin[] {
  const now = Date.now();
  const entries = readRecentLogins();
  const valid = entries.filter((e) => e.expiresAt > now);
  if (valid.length !== entries.length) writeRecentLogins(valid);
  valid.sort((a, b) => b.lastUsed - a.lastUsed);
  return valid;
}

/// Record (or refresh) a successful login. Derate the TTL by 30s so a
/// straggler can't serve an already-expired token to the next paid call.
export function recordRecentLogin(npub: string, proof: string, expiresInSec: number): void {
  const safeTtl = Math.max(0, expiresInSec - 30);
  const next: RecentLogin = {
    npub,
    proof,
    expiresAt: Date.now() + safeTtl * 1000,
    lastUsed: Date.now(),
  };
  const others = readRecentLogins().filter((e) => e.npub !== npub);
  writeRecentLogins(
    [next, ...others].sort((a, b) => b.lastUsed - a.lastUsed).slice(0, MAX_RECENT_LOGINS),
  );
}

export function forgetRecentLogin(npub: string): void {
  writeRecentLogins(readRecentLogins().filter((e) => e.npub !== npub));
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
const BOOTSTRAP_TOOLS = new Set([
  "request_npub_proof",
  "receive_npub_proof",
  "service_status",
  // Takes an explicit patron_npub, no proof envelope (free readiness probe).
  "session_status",
  // Public kind-0 profile reads/relays — take explicit npub, no proof envelope.
  "get_nostr_profile",
  "publish_nostr_profile",
]);

/// Tools too noisy/background to clutter the debug log (polled liveness +
/// profile hydration). Everything else — posting, OAuth, posts, snippets,
/// credits — is logged so the panel shows what the FE is actually doing.
const QUIET_TOOLS = new Set([
  "service_status",
  "get_nostr_profile",
  // The scheduler-log poll feeds the debug panel its own synthesized entries;
  // logging the poll call itself would just be noise.
  "get_scheduler_log",
  // Background personalization hydration (the editor's @handle) — not noteworthy.
  "get_x_profile",
  // NOTE: `fetch_dynamic_block` (the claim-check poll for a resolving dynamic
  // block) is intentionally NOT quiet. Each poll's status (pending → done/error)
  // must be visible in the debug panel — otherwise a resolve looks like it never
  // calls back, and a silent poll failure (e.g. a proof bounce) is undiagnosable.
]);

async function callTool<T = unknown>(
  toolName: string,
  args: Record<string, unknown> = {},
  opts: { bestEffort?: boolean; timeoutMs?: number } = {},
): Promise<T> {
  const quiet = QUIET_TOOLS.has(toolName);
  // `args` holds only the wrapper's own params — never npub/proof (those are
  // injected below), so it is safe to log verbatim.
  if (!quiet) debugPush("call", `${SLUG}_${toolName}(${JSON.stringify(args).slice(0, 140)})`);

  const c = await getClient();
  const merged: Record<string, unknown> = BOOTSTRAP_TOOLS.has(toolName)
    ? { ...args }
    : { npub: getStoredNpub(), dpop_token: getCachedProof(toolName), ...args };

  let result: ToolResult;
  try {
    result = (await c.callTool(
      { name: `${SLUG}_${toolName}`, arguments: merged },
      undefined,
      { timeout: opts.timeoutMs ?? 120_000 },
    )) as ToolResult;
  } catch (e) {
    if (!quiet) debugPush("error", `${SLUG}_${toolName}: ${(e as Error).message}`);
    throw new Error(`${SLUG}_${toolName}: ${(e as Error).message}`);
  }

  if (result.isError) {
    const errText = (result.content ?? [])
      .filter((b) => b.type === "text" && typeof b.text === "string")
      .map((b) => String(b.text))
      .join("\n") || "Tool call failed";
    if (!quiet) debugPush("error", `${SLUG}_${toolName}: ${errText.slice(0, 200)}`);
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

  if (!quiet) {
    const preview = typeof payload === "string" ? payload : JSON.stringify(payload);
    const p = payload as Record<string, unknown> | null;
    const failed = p && typeof p === "object" && (p.success === false || p.error);
    debugPush(failed ? "error" : "result", `${SLUG}_${toolName} → ${String(preview).slice(0, 220)}`);
  }

  // Soft proof failures arrive as {success:false, error_code:...} with no
  // isError flag. Treat them as auth bounces: clear the stale token and let the
  // gate re-arm sign-in. NOT for best-effort calls (personalization/diagnostics)
  // — a non-essential tool must never be able to log the user out of everything.
  if (!opts.bestEffort && payload && typeof payload === "object") {
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
  build_info?: {
    fastmcp_cloud_url?: string;
    fastmcp_cloud_git_commit_sha?: string;
    fastmcp_cloud_git_repo?: string;
  };
}

export async function serviceStatus(): Promise<ServiceStatus> {
  return callTool<ServiceStatus>("service_status", {});
}

export interface NpubProofResult {
  success?: boolean;
  proven_npub?: string;
  verified?: boolean; // legacy field; current wheel uses `success`
  status?: string;
  message?: string;
  dpop_token?: string; // wheel 0.57.0+ (was proof_token)
  popped_dms?: number;
  expires_in_seconds?: number;
  expires_at?: string;
  error?: string;
  error_code?: string;
}

/// Step 1 of DM login. Sends a Secure Courier challenge DM to the npub.
/// The user replies in their own Nostr client. Free.
export async function requestNpubProof(patronNpub: string): Promise<NpubProofResult> {
  return callTool<NpubProofResult>("request_npub_proof", { patron_npub: patronNpub });
}

/// Step 2 of DM login. Destructively drains DMs looking for the signed
/// reply to step 1. Call ONLY after the user has actually replied — do not
/// poll or speculatively retry (feedback_human_in_loop_courier). `dpopToken`
/// is the dpop_token from step 1 (wheel 0.57.0+; was the poison/proof_token).
export async function receiveNpubProof(patronNpub: string, dpopToken: string): Promise<NpubProofResult> {
  return callTool<NpubProofResult>("receive_npub_proof", {
    patron_npub: patronNpub,
    dpop_token: dpopToken,
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
  // Optional human label; the list falls back to `excerpt` (first body line)
  // when it's blank.
  title?: string;
  excerpt: string;
  publish_at: string | null;
  updated_at: string | null;
  tweet_url?: string | null;
  // Set when the scheduler last successfully fired this post (even a recurring
  // post that then rescheduled to its next date). Pairs with tweet_url.
  last_sent_at?: string | null;
  // Set when the scheduler TRIED to fire a scheduled post but held it back —
  // the reason (insufficient_balance / oauth_token_expired / x_api_error / …)
  // and when. The post stays scheduled and retries on the next due tick.
  last_attempt_at?: string | null;
  last_attempt_reason?: string | null;
}

export type SortDir = "asc" | "desc";

export interface ListPostsResult {
  posts?: PostSummary[];
  total?: number;
  page?: number;
  page_size?: number;
  error?: string;
}

/// Server-side sorted + offset-paginated post list (the Journal-tab model).
/// `sortCol` ∈ created|updated|status|scheduled. Returns `{posts, total, page,
/// page_size}`.
export interface ListFilterOpts {
  search?: string;
  dateFrom?: string;
  dateTo?: string;
  dateField?: string;
}

export async function listPosts(
  opts: { status?: string; sortCol?: string; sortDir?: SortDir; page?: number; pageSize?: number } & ListFilterOpts = {},
): Promise<ListPostsResult> {
  const args: Record<string, unknown> = {
    sort_col: opts.sortCol ?? "created",
    sort_dir: opts.sortDir ?? "desc",
    page: opts.page ?? 0,
    page_size: opts.pageSize ?? 25,
  };
  if (opts.status) args.status = opts.status;
  if (opts.search) args.search = opts.search;
  if (opts.dateFrom) args.date_from = opts.dateFrom;
  if (opts.dateTo) args.date_to = opts.dateTo;
  if (opts.dateField) args.date_field = opts.dateField;
  return callTool<ListPostsResult>("list_posts", args);
}

export interface PostRow {
  post_id?: string;
  id?: string;
  npub?: string;
  status?: string;
  title?: string;
  doc?: unknown;
  text_cache?: string;
  publish_at?: string | null;
  recurrence?: unknown;
  cease_at?: string | null;
  last_sent_at?: string | null;
  tweet_url?: string | null;
  last_attempt_at?: string | null;
  last_attempt_reason?: string | null;
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
  // Soft-error fields (the tool's catch_errors returns these instead of a post_id).
  success?: boolean;
  error?: string;
  error_code?: string;
  message?: string;
}

export interface Recurrence {
  freq: "daily" | "weekdays" | "weekly" | "monthly";
  interval: number;
}

export async function createPost(opts: {
  doc: unknown;
  textCache?: string;
  status?: string;
  publishAt?: string;
  recurrence?: Recurrence;
  ceaseAt?: string;
  clientReqId?: string;
  tweetUrl?: string;
  title?: string;
}): Promise<CreatePostResult> {
  const args: Record<string, unknown> = {
    doc: opts.doc,
    text_cache: opts.textCache ?? "",
    status: opts.status ?? "draft",
  };
  if (opts.publishAt) args.publish_at = opts.publishAt;
  if (opts.recurrence) args.recurrence = opts.recurrence;
  if (opts.ceaseAt) args.cease_at = opts.ceaseAt;
  if (opts.clientReqId) args.client_req_id = opts.clientReqId;
  if (opts.tweetUrl) args.tweet_url = opts.tweetUrl;
  if (opts.title) args.title = opts.title;
  return callTool<CreatePostResult>("create_post", args);
}

export interface UpdatePostResult {
  post_id?: string;
  status?: string;
  updated_at?: string;
  idempotent?: boolean;
  // Soft-error fields (the tool's catch_errors returns these instead of a post_id).
  success?: boolean;
  error?: string;
  error_code?: string;
  message?: string;
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

// ─── Post to X (paid) ─────────────────────────────────────────────────────

export interface PostTweetResult {
  success?: boolean;
  tweet_id?: string;
  tweet_url?: string;
  text_posted?: string;
  error?: string;
  error_code?: string;
  message?: string;
}

/// Post text to X now via the operator's X credentials (paid tool). Markdown
/// is converted to Unicode server-side; already-styled text passes through.
export async function postTweet(text: string): Promise<PostTweetResult> {
  return callTool<PostTweetResult>("post_tweet", { text });
}

// ─── Refine with Claude (server-side; the operator's key never leaves the BE) ──

export interface RefineResult {
  success: boolean;
  suggestions?: string[];
  error?: string;
  error_code?: string;
  message?: string;
}

/// Ask the MCP to refine a flagged region. The wheel calls Anthropic with the
/// operator's vaulted key and meters the call as a paid fare — the browser
/// never sees a key. Paid tool (npub/proof envelope injected by callTool).
export async function refinePostRegion(args: {
  region: string;
  fullText?: string;
  instruction?: string;
  voice?: string;
  bans?: string[];
}): Promise<RefineResult> {
  return callTool<RefineResult>("refine_post_region", {
    region: args.region,
    full_text: args.fullText ?? "",
    instruction: args.instruction ?? "",
    voice: args.voice ?? "",
    bans: JSON.stringify(args.bans ?? []),
  });
}

// ─── Resolve a dynamic block (server-side; operator's vaulted Claude key) ──

export interface ResolveDynamicResult {
  success: boolean;
  text?: string;
  error?: string;
  error_code?: string;
  message?: string;
  next_steps?: string;
  transient?: boolean;
}

// Claim-check shapes (mirrors optionality-mcp's async-job pattern). The start
// tool returns a claim check immediately; the free fetch companion is polled.
interface ClaimCheckStart {
  success?: boolean;
  claim_check?: string;
  poll_after_seconds?: number;
  error?: string;
  error_code?: string;
  message?: string;
}
interface ClaimFetch {
  status?: "pending" | "running" | "done" | "error" | "expired" | string;
  result?: { text?: string };
  poll_after_seconds?: number;
  error?: string;
  error_code?: string;
  message?: string;
  next_steps?: string;
  transient?: boolean;
}

const RESOLVE_MAX_WAIT_MS = 300_000; // give a heavy paginate+fetch+search resolve room
// The poll cadence is the BACKEND's call. Every claim-check response carries a
// `poll_after_seconds` — a budget-aware countdown: a long first wait sized to the
// author's declared runtime, then tightening as the deadline nears. We follow it
// verbatim so there is ONE cadence algorithm, owned server-side (no duplicate
// client backoff to drift out of sync). This fallback applies only if an older
// server omits the field.
const DEFAULT_POLL_SECONDS = 5;

/// Resolve a dynamic block's prompt server-side via the **claim-check** pattern:
/// `resolve_dynamic_block` starts a background job and returns a claim check
/// instantly (so no single request idles past the ~100s edge cap); we then poll
/// the free `fetch_dynamic_block` until it's done. The operator's vaulted key
/// never leaves the server. Paid on the start call (refunded if the job fails).
export async function resolveDynamicBlock(args: {
  prompt: string;
  context?: string;
  voice?: string;
  bans?: string[];
  allowedDomains?: string[];
  maxFetches?: number;
  runtimeLimitSeconds?: number;
}): Promise<ResolveDynamicResult> {
  const budgetSeconds = Math.max(60, Math.min(args.runtimeLimitSeconds ?? 210, 900));
  const start = await callTool<ClaimCheckStart>("resolve_dynamic_block", {
    prompt: args.prompt,
    context: args.context ?? "",
    voice: args.voice ?? "",
    bans: JSON.stringify(args.bans ?? []),
    allowed_domains: JSON.stringify(args.allowedDomains ?? []),
    max_fetches: args.maxFetches ?? 5,
    runtime_limit_seconds: budgetSeconds,
  });
  if (start.success === false || !start.claim_check) {
    return { success: false, error_code: start.error_code, error: start.error, message: start.message };
  }

  const claim = start.claim_check;
  // Give the browser at least the author's budget (+ a poll/result buffer) so a
  // long block doesn't time out client-side before the job finishes.
  const deadline = Date.now() + Math.max(RESOLVE_MAX_WAIT_MS, budgetSeconds * 1000 + 60_000);
  let waitMs = (start.poll_after_seconds ?? DEFAULT_POLL_SECONDS) * 1000;
  for (;;) {
    await new Promise((r) => setTimeout(r, waitMs));
    const f = await callTool<ClaimFetch>("fetch_dynamic_block", { claim_check: claim });
    if (f.status === "done") return { success: true, text: f.result?.text ?? "" };
    if (f.status === "error") {
      // Surface the curated situation: the message already explains the cause
      // ("…temporarily unavailable. No fare was charged."); append next_steps so
      // the author gets the actionable hint, and pass the structured fields
      // through (error_code/transient) for any UX that wants to branch on them.
      const base = f.error || f.message || "The resolve failed — your fare was refunded.";
      return {
        success: false,
        error_code: f.error_code,
        message: f.next_steps ? `${base} ${f.next_steps}` : base,
        next_steps: f.next_steps,
        transient: f.transient,
      };
    }
    if (f.status === "expired") return { success: false, message: f.next_steps || f.message || "The resolve claim expired — try again." };
    if (Date.now() > deadline) return { success: false, message: "Timed out waiting for the dynamic block to resolve." };
    // Honor the backend's next-poll advice (its countdown tightens toward done).
    waitMs = (f.poll_after_seconds ?? DEFAULT_POLL_SECONDS) * 1000;
  }
}

// ─── X account OAuth2 (per-patron connect dance) ───────────────────────────
// post_tweet posts to the logged-in npub's OWN X account, which needs a
// per-patron OAuth2 token. The dance: begin_oauth → open authorize_url in a
// browser → check_oauth_status (poll) until status === "completed". The
// callback lands at the Tollbooth OAuth2 collector; the wheel does the token
// exchange server-side. Both tools are free but proof-gated (callTool injects).

export interface BeginOauthResult {
  success?: boolean;
  status?: string;
  authorize_url?: string;
  authorize_url_short?: string;
  message?: string;
  error?: string;
  error_code?: string;
}

export async function beginOauth(): Promise<BeginOauthResult> {
  return callTool<BeginOauthResult>("begin_oauth", {});
}

export interface OauthStatusResult {
  success?: boolean;
  status?: string; // "pending" | "completed"
  message?: string;
  error?: string;
}

export async function checkOauthStatus(): Promise<OauthStatusResult> {
  return callTool<OauthStatusResult>("check_oauth_status", {});
}

export interface UpstreamOauth {
  has_access_token?: boolean;
  has_refresh_token?: boolean;
  access_token_expires_at?: number;
  access_token_expires_in_seconds?: number;
}

interface SessionStatusResult {
  lifecycle?: string;
  upstream_oauth?: UpstreamOauth;
}

/// The X-connection reading, as a discriminated state so the UI can tell
/// "definitely not connected" from "couldn't read it right now". The wheel
/// OMITS `upstream_oauth` when there's no token, so the absence of the block is
/// NOT proof of disconnection — only `lifecycle === "ready"` makes a no-token
/// reading authoritative. A cold/warming MCP (or a transient error) is
/// `indeterminate`, never `disconnected`.
export type XConnectionState =
  | { kind: "connected"; oauth: UpstreamOauth }
  | { kind: "disconnected" }
  | { kind: "indeterminate"; reason: string };

export async function getXConnection(): Promise<XConnectionState> {
  try {
    const r = await callTool<SessionStatusResult>("session_status", {
      patron_npub: getStoredNpub(),
    });
    if (r.upstream_oauth?.has_access_token) {
      return { kind: "connected", oauth: r.upstream_oauth };
    }
    // session_status answered. Only when the operator is "ready" is the
    // absence of a token authoritative; anything else is still warming up.
    if (r.lifecycle === "ready") {
      return { kind: "disconnected" };
    }
    return { kind: "indeterminate", reason: r.lifecycle ?? "warming_up" };
  } catch (e) {
    return { kind: "indeterminate", reason: (e as Error).message };
  }
}

/// Error codes from a paid X tool that mean "the patron must connect/reconnect
/// their X account" (vs. a transient or operator-side problem).
export const OAUTH_NEEDED_CODES = new Set(["oauth_not_yet_authorized", "oauth_token_expired"]);

// ─── Snippet library (Neon-backed, npub-scoped, free + proof-gated) ────────

export interface SnippetRow {
  id: string;
  name: string;
  text: string;
  doc?: unknown;
  favorite: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface ListSnippetsResult {
  success?: boolean;
  snippets?: SnippetRow[];
  total?: number;
  page?: number;
  page_size?: number;
  error?: string;
}
interface SaveSnippetResult {
  success?: boolean;
  snippet?: SnippetRow;
  error?: string;
  error_code?: string;
}
interface GetSnippetResult {
  success?: boolean;
  snippet?: SnippetRow;
  error?: string;
  error_code?: string;
}
interface DeleteSnippetResult {
  success?: boolean;
  deleted?: boolean;
  id?: string;
  error?: string;
}

/// Server-side sorted + offset-paginated snippet list (the Journal-tab model).
/// `sortCol` ∈ favorite|created|updated|name. Returns full rows (incl. `doc`)
/// so editor chiclets can insert the text directly.
export async function listSnippets(
  opts: { sortCol?: string; sortDir?: SortDir; page?: number; pageSize?: number } & ListFilterOpts = {},
): Promise<ListSnippetsResult> {
  const args: Record<string, unknown> = {
    sort_col: opts.sortCol ?? "favorite",
    sort_dir: opts.sortDir ?? "desc",
    page: opts.page ?? 0,
    page_size: opts.pageSize ?? 25,
  };
  if (opts.search) args.search = opts.search;
  if (opts.dateFrom) args.date_from = opts.dateFrom;
  if (opts.dateTo) args.date_to = opts.dateTo;
  if (opts.dateField) args.date_field = opts.dateField;
  return callTool<ListSnippetsResult>("list_snippets", args);
}

/// Read one snippet by id (full row incl. `doc`) — used when the editor opens
/// `/snippet/:id`. Mirrors `getPost`.
export async function getSnippet(id: string): Promise<SnippetRow | null> {
  const r = await callTool<GetSnippetResult>("get_snippet", { snippet_id: id });
  return r.snippet ?? null;
}

/// Create (omit id) or update (pass id) a snippet; returns the stored row.
/// `doc` is the same block/flag document a post carries.
export async function saveSnippet(opts: {
  id?: string;
  name?: string;
  text?: string;
  favorite?: boolean;
  doc?: unknown;
}): Promise<SnippetRow | null> {
  // Only send fields the caller set. On update the server leaves omitted fields
  // untouched, so a doc-only patch (toggling dynamic) keeps favorite as-is.
  const args: Record<string, unknown> = {};
  if (opts.id) args.snippet_id = opts.id;
  if (opts.name !== undefined) args.name = opts.name;
  if (opts.text !== undefined) args.text = opts.text;
  if (opts.favorite !== undefined) args.favorite = opts.favorite;
  if (opts.doc !== undefined) args.doc = opts.doc;
  const r = await callTool<SaveSnippetResult>("save_snippet", args);
  return r.snippet ?? null;
}

export async function deleteSnippet(id: string): Promise<boolean> {
  const r = await callTool<DeleteSnippetResult>("delete_snippet", { snippet_id: id });
  return r.deleted === true;
}

// ─── Writing Voice (Neon-backed, npub-scoped singleton, free + proof-gated) ──

/// A ban chip: a construction to avoid, and whether it's an active constraint.
export interface VoiceBan {
  text: string;
  on: boolean;
}

/// The patron's writing Voice — one profile blurb + a list of ban chips. Mirrors
/// the BE `voice` singleton; an unsaved Voice comes back empty (not an error).
export interface VoiceData {
  profile: string;
  bans: VoiceBan[];
}

interface VoiceResult {
  success?: boolean;
  voice?: VoiceData & { updated_at?: string };
  error?: string;
  error_code?: string;
}

/// Read the patron's saved Voice. Returns `{profile:"", bans:[]}` when none has
/// been saved yet, so the caller can seed its own defaults.
export async function getVoice(): Promise<VoiceData> {
  const r = await callTool<VoiceResult>("get_voice", {});
  return { profile: r.voice?.profile ?? "", bans: r.voice?.bans ?? [] };
}

/// Save (replace) the patron's Voice — it is a per-npub singleton. Blank and
/// duplicate ban chips are dropped server-side; returns the stored Voice.
export async function saveVoice(opts: { profile: string; bans: VoiceBan[] }): Promise<VoiceData> {
  const r = await callTool<VoiceResult>("save_voice", {
    profile: opts.profile,
    bans: opts.bans,
  });
  return { profile: r.voice?.profile ?? "", bans: r.voice?.bans ?? [] };
}

// ─── Scheduler-tick audit log (operator-only) ──────────────────────────────

/// One outcome of a scheduled-post fire (per due post). Mirrors the BE summary.
export interface SchedulerOutcome {
  post_id?: string;
  reason?: string; // skip/error reason, e.g. insufficient_balance / oauth_token_expired
  next_status?: string;
  tweet_url?: string | null;
}
export interface SchedulerRun {
  run_at: string;
  summary: {
    processed?: number;
    posted?: SchedulerOutcome[];
    skipped?: SchedulerOutcome[];
    errors?: SchedulerOutcome[];
  };
}
interface SchedulerLogResult {
  success?: boolean;
  runs?: SchedulerRun[];
  error?: string;
  error_code?: string;
}

/// Recent scheduler ticks (newest first) — what the Cloudflare cron Worker has
/// been doing. Operator-gated: only succeeds when the active npub is the
/// operator's (with proof). Quiet so the poll itself doesn't clutter the log.
export async function getSchedulerLog(limit = 25): Promise<SchedulerRun[]> {
  const r = await callTool<SchedulerLogResult>("get_scheduler_log", { limit }, { bestEffort: true });
  return r.runs ?? [];
}

// ─── Connected X account (for personalizing the editor preview) ────────────

export interface XProfile {
  connected?: boolean;
  username?: string;
  name?: string;
  profile_image_url?: string;
  error?: string;
  error_code?: string;
}

/// The connected X account's handle/name for the active npub (free, proof-gated).
/// Returns `{connected:false,...}` / an oauth situation when X isn't linked.
export async function getXProfile(): Promise<XProfile> {
  return callTool<XProfile>("get_x_profile", {}, { bestEffort: true });
}

// ─── Nostr kind-0 profile (served by the wheel; no relay I/O in the FE) ────

export interface Kind0 {
  name?: string;
  display_name?: string;
  about?: string;
  picture?: string;
  banner?: string;
  nip05?: string;
  website?: string;
  lud16?: string;
}

export interface GetNostrProfileResult {
  success: boolean;
  npub?: string;
  profile?: Kind0;
  error?: string;
}

/// Read an npub's public kind-0 profile via the operator MCP (free, no proof).
export async function getNostrProfile(npub: string): Promise<GetNostrProfileResult> {
  return callTool<GetNostrProfileResult>("get_nostr_profile", { npub });
}

export interface PublishNostrProfileResult {
  success: boolean;
  ok?: number;
  total?: number;
  errors?: string[];
  error?: string;
}

/// Relay a CLIENT-signed kind-0 event through the operator MCP. The FE signs;
/// the wheel verifies pubkey+signature and fans out to relays.
export async function publishNostrProfile(
  npub: string,
  signedEvent: string,
): Promise<PublishNostrProfileResult> {
  return callTool<PublishNostrProfileResult>("publish_nostr_profile", {
    npub,
    signed_event: signedEvent,
  });
}

// ─── Coupons (wheel 0.41.0+) ─────────────────────────────────────────────

export interface PatronCoupon {
  coupon_id: string;
  name: string;
  discount_percent: number;
  valid_from: string;
  valid_until: string;
  uses_per_patron: number | null;
  use_count: number;
  uses_remaining: number | null;
  total_uses: number | null;
  total_remaining: number | null;
  status: string; // active | window_closed | window_not_started | patron_limit | total_limit
}

export interface ListMyCouponsResult {
  success: boolean;
  count: number;
  coupons: PatronCoupon[];
  error?: string;
}

export interface RedeemCouponResult {
  success: boolean;
  coupon_id?: string;
  name?: string;
  discount_percent?: number;
  valid_until?: string;
  uses_remaining?: number | null;
  uses_per_patron?: number | null;
  error?: string;
}

export interface ForgetCouponResult {
  success: boolean;
  coupon_id?: string;
  error?: string;
}

export async function listMyCoupons(): Promise<ListMyCouponsResult> {
  return callTool<ListMyCouponsResult>("list_my_coupons", {});
}

export async function redeemCoupon(code: string): Promise<RedeemCouponResult> {
  return callTool<RedeemCouponResult>("redeem_coupon", { code });
}

export async function forgetCoupon(couponId: string): Promise<ForgetCouponResult> {
  return callTool<ForgetCouponResult>("forget_coupon", { coupon_id: couponId });
}
