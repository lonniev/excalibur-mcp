/**
 * eXcalibur's own tools, called through @tollbooth-dpyc/web.
 *
 * The client core is the package's: the one MCP connection, the npub/proof
 * envelope (a fresh kind-27235 inline proof when this tab holds a session key
 * for the signed-in npub, else the cached DM proof), the proof-bounce signal,
 * the identity storage and the standard tools (balance, top-up, payment,
 * statement, proof status, profile). What stays here is eXcalibur's alone:
 *
 *   - posts, snippets, the writing Voice, metrics and performance;
 *   - the X OAuth dance and the X-connection reading;
 *   - dynamic blocks (the claim-check resolve) and region refinement;
 *   - the scheduler: its status, log, pending request and operator controls;
 *   - the operator's readiness probes and patron coupons, which the package
 *     does not wrap yet;
 *   - the wider readings of service_status and check_balance this site shows.
 */

import {
  callTool,
  getStoredNpub,
  type CheckBalanceResult,
  type ServiceStatus,
} from "@tollbooth-dpyc/web";

// ─── Wider readings of standard tools ────────────────────────────────────
// The package types the fields every site reads. The wheel answers with more,
// and eXcalibur shows it: the build footer, the operator's health panel and
// the wallet's tranche count. Same calls, read wider.

/// service_status as the build footer and the operator panel read it.
export interface WheelStatus extends ServiceStatus {
  process_id?: number;
  vault_configured?: boolean;
  courier_has_vault?: boolean;
  // Durable long-runner diagnostics (operator only; present when op_npub resolves).
  durable_jobs?: {
    key_id?: string;
    closure_key_block?: string;
    deployment?: string;
    detached_executor_active?: boolean;
    detached_executor_resolved?: boolean;
    detached_executor_error?: string | null;
  };
  // FastMCP Docket backend — durable_across_recycles is the real signal.
  async_jobs?: {
    docket_url_set?: boolean;
    backend?: string;
    durable_across_recycles?: boolean;
  };
  build_info?: {
    fastmcp_cloud_url?: string;
    fastmcp_cloud_git_commit_sha?: string;
    fastmcp_cloud_git_repo?: string;
  };
}

export interface CreditTranche {
  id: string;
  amount_sats: number;
  remaining_sats: number;
  expires_at: string | null;
  created_at: string | null;
}

/// check_balance as the wallet and the account-health panel read it.
export interface WheelBalance extends CheckBalanceResult {
  active_tranches?: number;
  tranches?: CreditTranche[];
  vault_unavailable?: boolean;
  warning?: string;
}

// ─── Operator readiness probes (free, no proof envelope) ─────────────────
// Operator rows use service_status + get_operator_onboarding_status +
// check_authority_balance + session_status, shown only when the signed-in npub
// is scheduler_status.operator_npub (see FundingStatusPanels).

export interface OnboardingField {
  field: string;
  category?: string;
  status?: string;
  lifecycle?: string;
  how?: string;
}

export interface OperatorOnboardingResult {
  ready?: boolean;
  configured?: OnboardingField[];
  missing?: OnboardingField[];
  optional_missing?: OnboardingField[];
  summary?: string;
  bootstrap_error?: string;
  vault_ok?: boolean;
  credential_service?: string;
  operator_name?: string;
  error?: string;
}

/// Operator credential readiness (BTCPay / X app / llm_api_key present-or-not).
/// A non-operator still gets the structural answer; the FE hides the panel
/// unless the viewer is the operator npub.
export async function getOperatorOnboardingStatus(): Promise<OperatorOnboardingResult> {
  return callTool<OperatorOnboardingResult>(
    "get_operator_onboarding_status",
    {},
    { bestEffort: true },
  );
}

export interface AuthorityBalanceResult {
  success?: boolean;
  balance_api_sats?: number;
  balance_sats?: number;
  error?: string;
  message?: string;
}

/// This operator's tax balance at the Authority (sats available to certify
/// patron purchases). Best-effort — a failure is itself a status signal.
export async function checkAuthorityBalance(): Promise<AuthorityBalanceResult> {
  return callTool<AuthorityBalanceResult>(
    "check_authority_balance",
    {},
    { bestEffort: true },
  );
}

export interface SessionLifecycleResult {
  success?: boolean;
  lifecycle?: string;
  message?: string;
  detail?: string;
  operator_npub?: string;
  upstream_oauth?: UpstreamOauth;
}

/// Operator lifecycle (ready / warming_up / misconfigured / quota_exceeded / …).
/// Optional patron_npub also yields upstream_oauth (used by getXConnection).
export async function getSessionLifecycle(
  patronNpub?: string,
): Promise<SessionLifecycleResult> {
  return callTool<SessionLifecycleResult>(
    "session_status",
    patronNpub ? { patron_npub: patronNpub } : {},
    { bestEffort: true },
  );
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
  // The evidence behind that reason, stamped on the post row itself — so the
  // real cause survives even when the audit-ring row doesn't.
  last_attempt_detail?: string | null;
  // True when the post carries a recurrence cadence (the live recurring template).
  is_recurring?: boolean;
  // True when the post's doc holds at least one dynamic (prompt-driven) block —
  // distinguishes a live template from a frozen static snapshot.
  has_dynamic?: boolean;
  // Set on a sent occurrence → the id of the recurring template it fired from.
  template_id?: string | null;
  // Blocks that went out as the author's FALLBACK instead of the post they wrote,
  // with the reason resolution gave up. A degraded send still reads "Sent" — the
  // tweet did go out — so without this the list showed a healthy green pill and
  // the only way to notice was to open the post and recognise the fallback
  // wording. One reason per block; empty on a clean send.
  fell_back?: { reason?: string | null; budget_s?: number | null }[];
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
  /** Local wall hour 0–23 of last_sent_at (Performance ToD deep-link #506). */
  sentHour?: number;
  /** IANA zone for sentHour (must match the chart's zone). */
  timeZone?: string;
}

export async function listPosts(
  opts: { status?: string; sortCol?: string; sortDir?: SortDir; page?: number; pageSize?: number; templateId?: string } & ListFilterOpts = {},
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
  if (opts.templateId) args.template_id = opts.templateId;
  if (opts.sentHour != null && opts.timeZone) {
    args.sent_hour = opts.sentHour;
    args.time_zone = opts.timeZone;
  }
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
  last_attempt_detail?: string | null;
  // Set on a sent occurrence → the id of the recurring template it fired from.
  template_id?: string | null;
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

// ─── Post a companion Nostr note (paid) ──────────────────────────────────────

export interface PostNostrMessageResult {
  success?: boolean;
  event_id?: string;
  note_id?: string;
  accepted?: number;
  attempted?: number;
  relays?: unknown;
  error?: string;
  error_code?: string;
  message?: string;
}

/// Publish a public Nostr note (kind 1) on behalf of the proven session npub via
/// an ephemeral scribe key. The tool takes the author from the proven session;
/// do not pass a free-form author. Paid tool (npub/proof envelope injected).
export async function postNostrMessage(message: string): Promise<PostNostrMessageResult> {
  return callTool<PostNostrMessageResult>("post_nostr_message", { message });
}

// ─── Refine a region (server-side; the operator's key never leaves the BE) ──

export interface RefineResult {
  success: boolean;
  suggestions?: string[];
  error?: string;
  error_code?: string;
  message?: string;
}

/// Ask the MCP to refine a flagged region. The wheel calls the model with the
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

// ─── Resolve a dynamic block (server-side; operator's vaulted LLM key) ──

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
  // Floor only. The CEILING is the server's, and a second clamp here carrying its own
  // copy of it is how a legal budget got silently cut back to a bound this file
  // happened to still believe in.
  const budgetSeconds = Math.max(60, args.runtimeLimitSeconds ?? 210);
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
  // Probe EARLY on the first poll. The backend's budget-sized first wait (~75% of
  // the author's runtime) is right for a job that runs the full budget — but a job
  // that fails fast (e.g. the operator's AI provider is unfunded, surfaced only
  // once the job starts) would otherwise sit "resolving…" for that whole first
  // wait before the error shows. One quick probe surfaces early failures in
  // seconds; after it we honor the backend's countdown verbatim for a live job.
  let waitMs = Math.min((start.poll_after_seconds ?? DEFAULT_POLL_SECONDS) * 1000, 8_000);
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
///
/// Membership is deliberately narrow, because offering "Connect X" is never
/// free: on a provider that rotates refresh tokens, re-authorizing to chase a
/// blip throws away a working grant. Only codes where the provider itself
/// named the authorization dead — or where there demonstrably isn't one —
/// belong here. Two near-misses that must stay OUT:
///   • oauth_refresh_unavailable — the refresh never got an answer; nobody
///     knows anything yet, and the next tick retries.
///   • oauth_token_rejected — the short-lived access token was refused; the
///     wheel has already retired its cached expiry so the next call renews.
export const OAUTH_NEEDED_CODES = new Set([
  "oauth_not_yet_authorized",
  "oauth_token_expired",
  "oauth_unavailable",
  // The grant really is dead — but killed by a renewal whose answer was lost,
  // not by expiry. Reconnecting IS the fix, so it belongs here; what changed is
  // that the message now says why, instead of blaming a clock.
  "oauth_refresh_token_lost",
  // Nothing to renew with. A reconnect helps only if the new grant carries
  // offline access, which the situation's own next_steps spell out.
  "oauth_no_refresh_token",
]);

/// Codes that LOOK like the set above and must never join it. Kept as a named
/// list rather than a comment, because every one of these has, at some point,
/// been answered with a "Connect X" button that could not possibly have helped:
/// two are operator-side faults and one is an outright unknown.
export const OAUTH_NOT_THE_PATRONS_FAULT = new Set([
  "operator_app_credentials_rejected",
  "oauth_refresh_request_malformed",
  "oauth_refresh_failed_unclassified",
]);

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
  // Why, in the words of whatever refused — the provider's own message, an
  // exception type, or the moment a lost token renewal killed the grant. The
  // `reason` alone is a verdict with its evidence stripped, and stripping it is
  // how five unrelated OAuth failures all read as "X access expired".
  detail?: string;
  // What the publisher settled on for this post: posted / held / paused / gone,
  // or `claim_lost_before_post` when it stood down rather than risk a duplicate.
  outcome?: string;
  next_status?: string;
  tweet_url?: string | null;
  // Present on a POSTED entry when a dynamic block didn't resolve and the
  // author's fallback text went out in its place — the tweet succeeded, but not
  // with the words that were asked for. `budget_s` is the ceiling that cut it.
  fallbacks?: { block?: number; reason?: string; budget_s?: number }[];
}
// The audit ring carries two kinds of row. A `tick` is the scheduler finding due
// posts and launching a publisher for each — it never publishes anything itself.
// A `publication` is one publisher's outcome for one post, written by the
// publisher when it finishes. Owner-scoped: a patron sees every tick's heartbeat
// with the lists narrowed to their own posts, and only their own publications.
export interface SchedulerRun {
  run_at: string;
  summary: {
    kind?: "tick" | "publication";
    // Present only while a run is open — "started" until the tick closes it.
    // A row still wearing it long after run_at is a tick that was cut off.
    status?: string;

    // --- tick rows ---
    // Which build answered this tick. A heartbeat that only says "alive" can't
    // tell you WHICH deployment is alive.
    who?: { version?: string; commit?: string; contract?: string };
    // The forecast: posts still ahead of the scheduler, and how far off the
    // soonest is. Owner-scoped before it reaches us — a patron sees their own
    // queue, the operator sees everyone's.
    upcoming?: { count?: number; next_in_minutes?: number };
    processed?: number;
    // These names must track `scheduler.process_due_posts`. A single `launched`
    // list became `posted` + `resolving` when publishing split into two phases,
    // and nothing here followed: every tick rendered as "0 launched" and the
    // Sending list derived from it was always empty — for months, including for
    // the operator. If the tick summary is renamed again, this type and the
    // readers below move with it.
    posted?: SchedulerOutcome[];
    resolving?: SchedulerOutcome[];
    contended?: SchedulerOutcome[];
    // Phase 0: posts a tick rescued from a stranded state, keyed by what was
    // done — `resumed`, `paused_unknown`, `paused_legacy`, `exhausted`.
    recovered?: Record<string, SchedulerOutcome[]>;

    // --- publication rows ---
    post_id?: string;
    owner?: string;
    outcome?: "posted" | "held" | "paused" | "gone";
    reason?: string;
    // The evidence behind `reason` — see SchedulerOutcome.detail. Absent on
    // rows written before publishers carried it.
    detail?: string;
    tweet_url?: string | null;
    fallbacks?: { block?: number; reason?: string; budget_s?: number }[];
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

/// What the cron Worker is waiting on (the Device-Grant second surface). When
/// the Worker's authorization lapses it DMs the operator a challenge phrase and
/// parks; this returns that phrase so the operator can match it against the DM.
/// Operator-gated: the MCP reads it from the Worker AS the operator, so the
/// browser signs nothing — a plain npub login is enough. Returns null when
/// there's nothing to show or the caller isn't the operator (card stays hidden).
export type SchedulerPending =
  | { phase: "pending"; code: string; reason: string; requestedAt: number; lastCheck?: SchedulerLastCheck | null }
  | { phase: "active" | "idle" | "unavailable" };

/// The Worker's last attempt to collect the operator's reply: when, and the
/// SDK's code for what came back. `error` (its prose) is the operator's only.
export interface SchedulerLastCheck {
  at: number;
  code: string;
  error?: string;
}

export interface SchedulerReissue {
  success?: boolean;
  phase?: string;
  requestedAt?: number | null;
  message?: string;
  error?: string;
  error_code?: string;
}

/// Operator-only: drop the Worker's pending request and have it DM a fresh one
/// now. For the request that is visibly never going to complete.
export async function reissueSchedulerProof(): Promise<SchedulerReissue> {
  try {
    return await callTool<SchedulerReissue>("scheduler_reissue", {}, { bestEffort: true });
  } catch (e) {
    return { success: false, error: String((e as Error)?.message ?? e) };
  }
}

export async function getSchedulerPending(): Promise<SchedulerPending | null> {
  try {
    return await callTool<SchedulerPending>("scheduler_pending", {}, { bestEffort: true });
  } catch {
    return null; // not the operator / proof lapsed / warming up → hide the card
  }
}

/// The scheduler's configuration + status (cadence, version, renewal window,
/// current authorization phase) plus the operator npub it acts for. Free +
/// proof-gated; global config, so any proven patron sees it. No challenge
/// phrase (that's getSchedulerPending, operator-only). Null on failure.
/** The server's derived resolve budget rings. Served, never mirrored: these used to be
 *  hand-copied literals here and drifted the moment the server retuned them. */
export interface ResolveBudgets {
  block_max_seconds: number;
  job_attempt_seconds: number;
  lease_seconds: number;
  runner_timeout_seconds: number;
  lead_seconds: number;
}

export interface SchedulerStatus {
  operator_npub?: string;
  version?: string;
  cadence?: string;
  resolve_budgets?: ResolveBudgets;
  // Renewal lead as a PERCENTAGE of whatever lifetime the operator granted —
  // not a fixed number of hours. How long an authorization lasts is a human's
  // choice at reply time, so a constant window silently refused to spend every
  // grant shorter than it.
  renewsAtRemainingPercent?: number;
  rerequestAfterHours?: number;
  mcpUrl?: string;
  verifyAt?: string | null;
  authorization?:
    | { phase: "pending"; reason: string; requestedAt: number; lastCheck?: SchedulerLastCheck | null }
    // `spendable` false means the Worker HOLDS a valid token but is inside its
    // renewal window, so the next tick re-requests rather than posting. Without
    // it, a Worker declining to spend a good token looked exactly like one that
    // had none.
    | { phase: "active"; expiresAt: number; grantedForMinutes: number | null; spendable: boolean }
    | { phase: "idle" };
  worker?: string; // "unavailable" when the Worker couldn't be reached
}

export async function getSchedulerStatus(): Promise<SchedulerStatus | null> {
  try {
    return await callTool<SchedulerStatus>("scheduler_status", {}, { bestEffort: true });
  } catch {
    return null;
  }
}

// Budgets are deployment configuration, not per-session state: they cannot change while
// this tab is open, so fetch once and share. Surfaces that only need a bound (the
// editor's time-budget input) should not each pay for a round trip.
let _budgetsPromise: Promise<ResolveBudgets | null> | null = null;

export function getResolveBudgets(): Promise<ResolveBudgets | null> {
  _budgetsPromise ??= getSchedulerStatus().then((s) => s?.resolve_budgets ?? null);
  return _budgetsPromise;
}

/// Poke the scheduler to run one tick now — claims a pending proof reply
/// (completing authorization) and fires due posts. Operator-only. Returns true
/// if the Worker accepted the poke (it runs in the background); re-read status a
/// few seconds later to see the phase flip.
export async function runSchedulerCheckNow(): Promise<boolean> {
  try {
    const r = await callTool<{ started?: boolean }>("scheduler_check_now", {}, { bestEffort: true });
    return !!r.started;
  } catch {
    return false;
  }
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

// ─── Post metrics / performance ──────────────────────────────────────────

export interface MetricsSnapshot {
  snapshot_id?: string;
  captured_at?: string;
  t_offset?: number;
  cadence_key?: string;
  impressions?: number | null;
  likes?: number | null;
  replies?: number | null;
  reposts?: number | null;
  quotes?: number | null;
  bookmarks?: number | null;
  url_link_clicks?: number | null;
  user_profile_clicks?: number | null;
  link_placement?: string | null;
  snippet_ids?: string[];
  voice_id?: string | null;
  tweet_id?: string;
}

export interface GetPostMetricsResult {
  success?: boolean;
  post_id?: string;
  snapshots?: MetricsSnapshot[];
  tweet_url?: string | null;
  note?: string;
  error?: string;
  error_code?: string;
}

export interface PerformanceSparkPoint {
  t_offset?: number;
  cadence_key?: string;
  impressions?: number | null;
  likes?: number | null;
  captured_at?: string;
}

export interface PerformancePost {
  post_id: string;
  tweet_id?: string;
  /** Operator-authored title when set. */
  title?: string | null;
  /** Opening words of the posted text (fallback identity). */
  excerpt?: string | null;
  /** When the post went out to X. */
  last_sent_at?: string | null;
  link_placement?: string | null;
  latest_impressions?: number | null;
  latest_likes?: number | null;
  latest_replies?: number | null;
  latest_reposts?: number | null;
  quotes?: number | null;
  bookmarks?: number | null;
  url_link_clicks?: number | null;
  user_profile_clicks?: number | null;
  /** Profile clicks ÷ impressions (Tier 1 free intent proxy). */
  profile_click_rate?: number | null;
  /** Bookmarks ÷ impressions. */
  bookmark_rate?: number | null;
  /** Replies ÷ impressions, isolated from blended engagement. */
  reply_rate?: number | null;
  /** Quotes ÷ reposts. */
  quote_to_repost_ratio?: number | null;
  escape_velocity?: number | null;
  breakout_ratio?: number | null;
  sparkline?: PerformanceSparkPoint[];
}

/** One cohort bucket: median value plus how many posts contributed. */
export interface CohortBucket {
  median: number;
  n: number;
}

export interface PostPerformanceResult {
  success?: boolean;
  npub?: string;
  follower_count?: number | null;
  posts?: PerformancePost[];
  cohorts?: {
    /** Median impressions + sample size by link placement. */
    link_placement?: Record<string, CohortBucket | number>;
    voice?: Record<string, number>;
    snippet?: Record<string, number>;
    /** Median impressions + sample size by UTC send hour (`"00"`…`"23"`). */
    time_of_day?: Record<string, CohortBucket | number>;
  };
  corpus?: {
    snapshot_count?: number;
    post_count?: number;
    rolling_median_t15?: number | null;
    /** Rolling median of final-reach impressions (t+28d when present, else latest). */
    rolling_median_final?: number | null;
    /** How many posts contributed a final-reach reading to the breakout baseline. */
    breakout_sample_size?: number;
    /** Minimum sample before breakout_ratio is computed (else suppressed). */
    breakout_min_sample?: number;
  };
  error?: string;
}

export async function getPostMetrics(postId: string): Promise<GetPostMetricsResult> {
  return callTool<GetPostMetricsResult>("get_post_metrics", { post_id: postId });
}

export async function getPostPerformance(): Promise<PostPerformanceResult> {
  return callTool<PostPerformanceResult>("post_performance", {});
}

export async function getPostPerformanceInfographic(): Promise<{
  success?: boolean;
  svg?: string;
  error?: string;
}> {
  return callTool("post_performance_infographic", {});
}
