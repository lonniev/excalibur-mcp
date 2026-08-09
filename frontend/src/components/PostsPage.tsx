import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Plus } from "lucide-react";
import {
  createPost, deletePost, getPost, getXConnection, listPosts, OAUTH_NEEDED_CODES,
  postTweet, updatePost,
  type PostSummary, type Recurrence, type SortDir, type XConnectionState,
} from "../lib/mcp";
import { uid } from "../lib/editorDoc";
import { formatDateTime, localDateFilterBounds } from "../lib/timezone";
import { useTimezone } from "../lib/useTimezone";
import TweetPreviewModal from "./TweetPreviewModal";
import { PageControls, SortHeader, TableShell } from "./PagedTable";
import TableFilter from "./TableFilter";
import QuoteScroller from "./QuoteScroller";
import SchedulerHealth from "./SchedulerHealth";
import SchedulerPendingCard from "./SchedulerPendingCard";
import RefreshButton from "./RefreshButton";

// The status toggle-chiclets. Each is an independent include filter: toggled ON
// means "show posts with this status", OFF means "exclude them" — together they
// form a select/reject chain. `sending` is the transient state the scheduler
// stamps when it claims a due post to fire it; it's a chiclet so a claimed (or
// stuck) post is never invisible. The "all" and "none" chiclets (rendered
// separately) are actions rather than filters: one selects every status, the
// other clears them so you can pick from scratch. Default is everything
// selected — equivalent to the old unfiltered view.
const POST_STATUSES = ["draft", "scheduled", "resolving", "resolved", "sending", "paused", "sent", "archived"] as const;
const DATE_FIELDS = [
  { value: "created", label: "Created" },
  { value: "updated", label: "Updated" },
  { value: "scheduled", label: "Scheduled" },
  { value: "sent", label: "Posted" },
];
const PAGE_SIZE = 25;

const statusStyle: Record<string, string> = {
  draft: "bg-stone-100 text-stone-600 dark:bg-zinc-800 dark:text-zinc-300",
  scheduled: "bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-400",
  // Building the body: a worker is resolving this post's dynamic blocks. The
  // slow phase — minutes, not milliseconds — so it pulses.
  resolving: "bg-violet-100 text-violet-700 dark:bg-violet-500/15 dark:text-violet-400 animate-pulse",
  // Built and waiting for its moment. Nothing is running; the text is final and
  // the next tick will send it.
  resolved: "bg-teal-100 text-teal-700 dark:bg-teal-500/15 dark:text-teal-400",
  // Transient: the scheduler has claimed this finished body and is posting it
  // right now. Milliseconds, so this is rarely seen.
  sending: "bg-sky-100 text-sky-700 dark:bg-sky-500/15 dark:text-sky-400 animate-pulse",
  // A "needs attention" stop-state: the scheduler paused this post after a
  // non-transient failure (e.g. a lapsed X subscription). Distinct from the
  // grey draft fallback so it reads as actionable, not idle.
  paused: "bg-rose-100 text-rose-700 dark:bg-rose-500/15 dark:text-rose-400",
  sent: "bg-green-100 text-green-700 dark:bg-green-500/15 dark:text-green-400",
  archived: "bg-stone-100 text-stone-400 dark:bg-zinc-800 dark:text-zinc-500",
};

// Pauses where the post MAY already be live on X. Resuming one of these is the
// one click in this UI that can publish a duplicate, so it gets the opposite
// advice from every other pause: check the timeline before acting, don't fix
// anything at the provider.
const UNCONFIRMED_SEND = ["x_post_outcome_unknown", "sending_orphaned_pre_split"];

// Friendly labels for a held-attempt reason recorded by the scheduler Worker.
// Anything unmapped (e.g. a raw x_api_error string) shows verbatim.
function attemptLabel(reason: string): string {
  // Two reason families carry a value in the string itself, and the difference
  // between them is the whole point — `_fallback_reason` says so: whether the
  // block ran out of ITS OWN time, which the author can fix by raising
  // runtimeLimit, or the provider failed, which is an outage and no edit helps.
  // Reported as one undifferentiated raw token they read as the same event.
  const timedOut = reason.match(/^resolve_timed_out_at_(\d+)s$/);
  if (timedOut) return `ran out of its own ${timedOut[1]}s budget — raise the block's time limit`;
  if (reason.startsWith("resolve_failed:")) {
    const kind = reason.slice("resolve_failed:".length);
    const known: Record<string, string> = {
      ConnectError: "couldn't reach the model provider",
      ReadError: "lost the connection to the model provider",
      RemoteProtocolError: "the model provider closed the connection early",
    };
    return known[kind] ?? `the model provider failed (${kind})`;
  }
  if (reason.startsWith("x_api_error")) {
    // The reason now carries X's status code and nothing else; X's own sentence
    // rides in `detail` and reaches the tooltip. So these labels name WHAT
    // happened and leave WHY to X.
    //
    // "X subscription/tier" used to be asserted for every 402 — a guess that
    // held only when a plan had actually lapsed. On 2026-07-31 a single post
    // 402'd while a 792-character sibling from the same account posted fine
    // thirty minutes earlier, so a lapsed plan was exactly what it was not.
    if (reason.includes("402")) return "X declined it (402)";
    if (reason.includes("429")) return "X rate limit";
    if (reason.includes("401") || reason.includes("403")) return "X refused the request";
    return "X error";
  }
  return (
    {
      insufficient_balance: "out of credits",
      insufficient_balance_resolve: "out of credits",
      // The operator's MODEL PROVIDER account, not the post owner's API sats —
      // the two must never read alike. "out of credits" above is the reader's
      // own balance and they top it up here; these are the operator's account
      // at OpenRouter and no action in this UI touches them. Unmapped, they
      // reached the badge as the raw shrug `resolve_failed:HTTPStatusError`,
      // which said only that something upstream broke and hid the single fact
      // that mattered: renders will keep falling back until someone funds the
      // provider. Cost a full evening of posts on 2026-08-06.
      operator_llm_unfunded: "the operator's model provider is out of credit — top it up",
      operator_llm_auth: "the model provider rejected the operator's API key",
      operator_llm_model_unknown: "the configured model no longer exists at the provider",
      upstream_rate_limited: "the model provider rate-limited us — retrying",
      oauth_token_expired: "X access expired",
      oauth_unavailable: "X not connected",
      oauth_not_yet_authorized: "X not connected",
      // The one the operator lived through for days. X retires a refresh token
      // the moment a renewal ARRIVES, so a renewal whose answer got lost leaves
      // us holding a spent token — the grant is dead, but of an accident, not
      // of age. Called "expired", it looked like a session aging out in hours,
      // and the only response it invited was to reconnect and wait for it again.
      oauth_refresh_token_lost: "X renewal was cut off — reconnect once",
      // No refresh token to spend: a scope problem wearing a clock's clothes.
      oauth_no_refresh_token: "X access can't renew itself",
      // Operator-side faults. These must never read as something the post's
      // owner can fix by reconnecting, because reconnecting cannot fix them.
      operator_app_credentials_rejected: "operator's X app was refused",
      oauth_refresh_request_malformed: "renewal request rejected — service bug",
      // Unknown, and honest about it. Retryable: the previous behaviour was to
      // call an unclassified failure an expiry, which spent a working grant on
      // a guess.
      oauth_refresh_failed_unclassified: "renewal failed — retrying",
      // X never answered the token refresh, so nobody knows whether the session
      // lapsed — and the three labels above all read as "go reconnect X". This
      // one must read as a retry, because that is what the next tick does.
      oauth_refresh_unavailable: "X didn't answer — retrying",
      // X refused the short-lived access token. The wheel has already retired
      // its cached expiry, so the next tick spends the refresh token and
      // renews. Same rule as above: this reads as a retry, never as reconnect.
      oauth_token_rejected: "renewing X access — retrying",
      // X took the request and never answered, so nobody knows whether a tweet
      // exists. This one PAUSES rather than holds — the whole point is that it
      // must NOT be retried automatically. Only a human looking at the timeline
      // can say whether it went out, so the label sends them there.
      x_post_outcome_unknown: "X didn't confirm — check your timeline",
      // Same hazard, found by the recovery sweep rather than by the publisher:
      // a post stranded mid-send before send-tracking existed, so whether it
      // reached X is simply unrecorded. Sends the owner to the timeline too.
      sending_orphaned_pre_split: "send unrecorded — check your timeline",
      // Gave up after repeated failures to fire. The real cause is in the
      // detail; this only says the post stopped trying, and that Resume is
      // what starts it again.
      firing_attempts_exhausted: "gave up retrying — resume when fixed",
      // The publisher refused to post because it could not durably record that
      // it was about to. Deliberate: posting without that record is how an
      // orphan later reads as "nothing sent" and goes out twice.
      x_call_mark_unavailable: "couldn't confirm send state — retrying",
      empty_text_cache: "empty content",
      pricing_unavailable: "pricing unavailable",
      // Situations where the service couldn't answer — NOT the owner's doing.
      // Each of these once arrived labelled as a dead X login or an empty
      // wallet, sending the owner to fix something that was never broken. The
      // wording has one job: make it obvious no action is wanted here.
      warming_up: "service warming up",
      vault_bootstrapping: "service warming up",
      secure_courier_unavailable: "service warming up",
      vault_unavailable: "balance unconfirmed — retrying",
      operator_credentials_missing: "operator setup pending",
      // …and these two will not clear on their own, so they must not read as a
      // wait. Naming the operator is the actionable part.
      persistence_quota_exceeded: "operator database over quota",
      persistence_misconfigured: "operator database needs repair",
    } as Record<string, string>
  )[reason] ?? reason;
}

// Material Design action glyphs (Apache-2.0), inlined as `currentColor` paths
// so each button's hover color flows straight through — one concept, one icon.
const ICONS = {
  // content_copy
  duplicate: "M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z",
  // play_arrow
  resume: "M8 5v14l11-7z",
  // event_busy (calendar with ✕ — "remove from schedule")
  toDraft: "M9.31 17l2.44-2.44L14.19 17l1.06-1.06-2.44-2.44 2.44-2.44L14.19 10l-2.44 2.44L9.31 10l-1.06 1.06 2.44 2.44-2.44 2.44L9.31 17zM19 3h-1V1h-2v2H8V1H6v2H5c-1.11 0-1.99.9-1.99 2L3 19c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 16H5V8h14v11z",
  // repeat
  repost: "M7 7h10v3l4-4-4-4v3H5v6h2V7zm10 10H7v-3l-4 4 4 4v-3h12v-6h-2v4z",
  // archive
  archive: "M20.54 5.23l-1.39-1.68C18.88 3.21 18.47 3 18 3H6c-.47 0-.88.21-1.16.55L3.46 5.23C3.17 5.57 3 6.02 3 6.5V19c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V6.5c0-.48-.17-.93-.46-1.27zM12 17.5L6.5 12H10v-2h4v2h3.5L12 17.5zM5.12 5l.81-1h12l.94 1H5.12z",
  // delete
  delete: "M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z",
  // visibility (peek at the posted tweet)
  visibility: "M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z",
};

/// One row-action icon button. Muted by default; `hover` supplies the accent on
/// hover. `busy` pulses the glyph and disables the click while in flight (the
/// old text affordance showed "…" — the pulse reads the same, without a layout
/// shift). Keeps a `title`/`aria-label` so the action name survives the icon.
function ActionIcon({
  path, title, onClick, hover, busy = false,
}: {
  path: string;
  title: string;
  onClick: (e: React.MouseEvent) => void;
  hover: string;
  busy?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={busy}
      title={title}
      aria-label={title}
      className={`p-1 rounded-sm text-stone-400 dark:text-zinc-500 transition-colors disabled:cursor-not-allowed ${hover}`}
    >
      <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" className={busy ? "animate-pulse" : ""} aria-hidden>
        <path d={path} />
      </svg>
    </button>
  );
}

/// The include/exclude control on a filter chiclet — a real checkbox glyph so the
/// toggle state reads at a glance, not by color alone: a filled+checked box when
/// the status is INCLUDED in the result set, an empty outlined box when EXCLUDED.
/// Decorative (the button carries the accessible state via aria-pressed).
function ChicletBox({ on }: { on: boolean }) {
  return (
    <span
      aria-hidden
      className={`inline-flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded-[3px] border transition-colors ${
        on
          ? "bg-amber-500 border-amber-500 text-white dark:bg-amber-400 dark:border-amber-400 dark:text-zinc-900"
          : "border-stone-400 dark:border-zinc-600"
      }`}
    >
      {on && (
        <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round">
          <path d="M20 6 9 17l-5-5" />
        </svg>
      )}
    </span>
  );
}

export default function PostsPage() {
  const nav = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  // When set (?template=<id>), the list is scoped to one template's published
  // occurrences — the "View published postings" view from the editor.
  const templateFilter = searchParams.get("template");
  const [posts, setPosts] = useState<PostSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  // The set of statuses to include. Starts fully selected (== the old "all" tab).
  const [selected, setSelected] = useState<Set<string>>(() => new Set(POST_STATUSES));
  const [sortCol, setSortCol] = useState("created");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [search, setSearch] = useState("");
  const [dateField, setDateField] = useState("created");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [, timeZone] = useTimezone();
  const [loading, setLoading] = useState(false);
  // True once the first fetch has completed — the search/date filter controls
  // only appear with the table after loading, not before it (they aren't needed
  // to load the first table).
  const [hasLoaded, setHasLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [reposting, setReposting] = useState<string | null>(null);
  const [resuming, setResuming] = useState<string | null>(null);
  const [returningToDraft, setReturningToDraft] = useState<string | null>(null);
  const [duplicating, setDuplicating] = useState<string | null>(null);
  const [preview, setPreview] = useState<{ url: string; text: string } | null>(null);
  // Whether X is connected RIGHT NOW. `last_attempt_reason` is a record of the
  // last attempt, not a live diagnosis — after a reconnect it still says the
  // account was expired, because that is what was true when it was written.
  // Rendering it as a live instruction told an owner with a working X account
  // to go reconnect it.
  const [xConn, setXConn] = useState<XConnectionState | null>(null);

  const refresh = useCallback(async () => {
    // An empty include-set matches nothing by definition — render the empty state
    // without troubling the backend (whose bare `status` means "all", not "none").
    if (selected.size === 0) {
      setPosts([]);
      setTotal(0);
      setHasLoaded(true);
      setError(null);
      return;
    }
    // Full set == unfiltered; a strict subset is sent comma-joined for `status IN`.
    const status =
      selected.size === POST_STATUSES.length
        ? undefined
        : POST_STATUSES.filter((s) => selected.has(s)).join(",");
    setLoading(true);
    setError(null);
    try {
      // #367 — wall YYYY-MM-DD → patron-local midnight ISO so the day edge is
      // the patron's, not UTC's. Backend accepts both bare dates and instants.
      const bounds = localDateFilterBounds(dateFrom, dateTo, timeZone);
      const r = await listPosts({
        status, sortCol, sortDir, page, pageSize: PAGE_SIZE,
        search,
        dateFrom: bounds.dateFrom,
        dateTo: bounds.dateTo,
        dateField,
        templateId: templateFilter ?? undefined,
      });
      if (r.error) setError(r.error);
      setPosts(r.posts ?? []);
      setTotal(r.total ?? 0);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setHasLoaded(true);
      setLoading(false);
    }
    // Best-effort and non-blocking: a row's OAuth affordance is suppressed only
    // on a definite "connected", so a failure here just leaves the old behaviour.
    void getXConnection().then(setXConn).catch(() => setXConn(null));
  }, [selected, sortCol, sortDir, page, search, dateFrom, dateTo, dateField, templateFilter, timeZone]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  function onSort(col: string, dir: SortDir) {
    setSortCol(col);
    setSortDir(dir);
    setPage(0);
  }

  // Toggle a single status in/out of the include-set.
  function toggleStatus(s: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
    setPage(0);
  }

  // "all" and "none" are actions, not filters, and each does exactly one thing.
  // "all" used to double as the way to clear — which meant that from a PARTIAL
  // selection there was no way to clear at all, since clicking it selected
  // everything instead. Two idempotent controls beat one with a hidden second
  // meaning.
  const allSelected = selected.size === POST_STATUSES.length;
  const noneSelected = selected.size === 0;
  function selectAll() {
    setSelected(new Set(POST_STATUSES));
    setPage(0);
  }
  function selectNone() {
    setSelected(new Set());
    setPage(0);
  }

  async function handleDelete(e: React.MouseEvent, id: string, hard: boolean) {
    e.stopPropagation();
    e.preventDefault();
    if (hard && !window.confirm("Permanently delete this post? This cannot be undone.")) return;
    setError(null);
    try {
      await deletePost(id, hard);
      await refresh();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function handleRepost(e: React.MouseEvent, id: string) {
    e.stopPropagation();
    e.preventDefault();
    setError(null);
    setNotice(null);
    setReposting(id);
    try {
      const row = await getPost(id);
      const text = (row.text_cache ?? "").trim();
      if (!text) { setError("Nothing to repost."); return; }
      const r = await postTweet(text);
      if (r.error || r.success === false) setError(r.message || r.error || "Repost failed.");
      else setNotice("Reposted to X.");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setReposting(null);
    }
  }

  // Resume a paused post: flip it back to `scheduled` so the next scheduler
  // tick picks it up. Its publish_at is in the past, so it fires on the very
  // next tick (and recurrence resumes from there). Use once the cause of the
  // pause (e.g. a lapsed X subscription) is fixed at the provider.
  async function handleResume(e: React.MouseEvent, id: string) {
    e.stopPropagation();
    e.preventDefault();
    setError(null);
    setNotice(null);
    setResuming(id);
    try {
      const r = await updatePost({ postId: id, patch: { status: "scheduled" }, clientReqId: uid() });
      if (r.error) setError(r.error);
      else {
        setNotice("Resumed — rescheduled. The next scheduler tick will post it.");
        await refresh();
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setResuming(null);
    }
  }

  // Return a post to Draft — the universal rescue for a post that left the table's
  // active views: a scheduled/paused one you want to pull back, or one the
  // scheduler claimed (`sending`) and couldn't finish. Draft is excluded from the
  // scheduler's due set, so this cleanly unschedules it for editing.
  async function handleReturnToDraft(e: React.MouseEvent, id: string) {
    e.stopPropagation();
    e.preventDefault();
    setError(null);
    setNotice(null);
    setReturningToDraft(id);
    try {
      const r = await updatePost({ postId: id, patch: { status: "draft" }, clientReqId: uid() });
      if (r.error) setError(r.error);
      else {
        setNotice("Returned to Draft — it won't post until you schedule it again.");
        await refresh();
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setReturningToDraft(null);
    }
  }

  // Duplicate a post: a deep copy of its content AND schedule (publish time,
  // recurrence cadence, cease date) into a fresh draft, then open it in the
  // editor. The copy lands as `draft`, so even with a publish time carried over
  // it never fires until the user reviews and schedules it — no double-posting
  // alongside the original. Works from any source status (draft, scheduled, …).
  async function handleDuplicate(e: React.MouseEvent, id: string) {
    e.stopPropagation();
    e.preventDefault();
    setError(null);
    setNotice(null);
    setDuplicating(id);
    try {
      const row = await getPost(id);
      const r = await createPost({
        doc: row.doc,
        textCache: row.text_cache ?? "",
        status: "draft",
        title: row.title || undefined,
        publishAt: row.publish_at ?? undefined,
        recurrence: row.recurrence ? (row.recurrence as Recurrence) : undefined,
        ceaseAt: row.cease_at ?? undefined,
        clientReqId: uid(),
      });
      if (r.error || !r.post_id) { setError(r.error || "Duplicate failed."); return; }
      nav(`/post/${r.post_id}`);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setDuplicating(null);
    }
  }

  return (
    <div className="mx-auto w-[90%] max-w-[1600px] px-4 py-6">
      {preview && (
        <TweetPreviewModal url={preview.url} text={preview.text} onClose={() => setPreview(null)} />
      )}
      <div className="flex items-center gap-3 mb-4">
        <h1 className="text-lg font-semibold">Posts</h1>
        <SchedulerHealth />
        <Link
          to="/new"
          className="ml-auto inline-flex items-center gap-1.5 bg-green-600 hover:bg-green-500 text-white text-sm px-4 py-2 rounded-lg transition-colors"
          aria-label="Compose"
        >
          <Plus className="h-6 w-6" aria-hidden />
          Compose
        </Link>
      </div>

      <div className="mb-4">
        <SchedulerPendingCard />
      </div>

      {templateFilter && (
        <div className="mb-4 flex items-center gap-2 rounded-lg border border-violet-200 bg-violet-50 px-3 py-2 text-sm text-violet-800 dark:border-violet-500/30 dark:bg-violet-500/10 dark:text-violet-300">
          <span>↻ Showing published postings from one recurring template.</span>
          <Link
            to={`/post/${templateFilter}`}
            className="underline underline-offset-2 hover:no-underline"
          >
            Open the template →
          </Link>
          <button
            onClick={() => { setSearchParams({}); setPage(0); }}
            className="ml-auto rounded-md px-2 py-0.5 text-violet-700 hover:bg-violet-100 dark:text-violet-300 dark:hover:bg-violet-500/20"
          >
            Clear ✕
          </button>
        </div>
      )}

      <div className="flex flex-wrap gap-1.5 mb-4 text-xs">
        <button
          onClick={selectAll}
          disabled={loading}
          aria-pressed={allSelected}
          title="Show every status"
          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg capitalize border transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
            allSelected
              ? "bg-amber-100 text-amber-800 border-amber-200 dark:bg-amber-500/15 dark:text-amber-400 dark:border-amber-500/30"
              : "text-stone-500 border-transparent hover:bg-stone-100 dark:text-zinc-400 dark:hover:bg-zinc-800"
          }`}
        >
          <ChicletBox on={allSelected} />
          all
        </button>
        <button
          onClick={selectNone}
          disabled={loading}
          aria-pressed={noneSelected}
          title="Clear every status, then pick the ones you want"
          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg capitalize border transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
            noneSelected
              ? "bg-amber-100 text-amber-800 border-amber-200 dark:bg-amber-500/15 dark:text-amber-400 dark:border-amber-500/30"
              : "text-stone-500 border-transparent hover:bg-stone-100 dark:text-zinc-400 dark:hover:bg-zinc-800"
          }`}
        >
          <ChicletBox on={noneSelected} />
          none
        </button>
        {POST_STATUSES.map((s) => {
          const on = selected.has(s);
          return (
            <button
              key={s}
              onClick={() => toggleStatus(s)}
              disabled={loading}
              aria-pressed={on}
              title={on ? `Showing ${s} posts — click to hide` : `Hiding ${s} posts — click to show`}
              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg capitalize border transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
                on
                  ? "bg-amber-100 text-amber-800 border-amber-200 dark:bg-amber-500/15 dark:text-amber-400 dark:border-amber-500/30"
                  : "text-stone-400 border-dashed border-stone-300 hover:bg-stone-100 dark:text-zinc-500 dark:border-zinc-700 dark:hover:bg-zinc-800"
              }`}
            >
              <ChicletBox on={on} />
              {s}
            </button>
          );
        })}
        <span className="ml-auto">
          <RefreshButton onClick={refresh} busy={loading} title="Refresh posts" />
        </span>
      </div>

      {hasLoaded && (
        <TableFilter
          search={search}
          onSearch={(t) => { setSearch(t); setPage(0); }}
          dateField={dateField}
          dateFieldOptions={DATE_FIELDS}
          onDateField={(v) => { setDateField(v); setPage(0); }}
          dateFrom={dateFrom}
          dateTo={dateTo}
          onDateFrom={(v) => { setDateFrom(v); setPage(0); }}
          onDateTo={(v) => { setDateTo(v); setPage(0); }}
          onClear={() => { setSearch(""); setDateFrom(""); setDateTo(""); setDateField("created"); setPage(0); }}
        />
      )}

      {error && (
        <div className="rounded-lg p-3 mb-3 text-xs bg-red-50 border border-red-200 text-red-700 dark:bg-red-500/10 dark:border-red-500/30 dark:text-red-400">
          {error}
        </div>
      )}
      {notice && (
        <div className="rounded-lg p-3 mb-3 text-xs bg-green-50 border border-green-200 text-green-700 dark:bg-green-500/10 dark:border-green-500/30 dark:text-green-400">
          {notice}
        </div>
      )}

      {loading ? (
        // Show the loading entertainment on ANY in-flight query — not just the
        // first load. A filter/tab switch keeps the prior posts in state, so
        // without this the stale table just sits there (no feedback) and the
        // human click-spams the tabs while the MCP cold-starts.
        <QuoteScroller heading="Loading your posts…" className="py-16" />
      ) : posts.length === 0 ? (
        <div className="text-center py-12">
          <p className="text-sm text-stone-400 dark:text-zinc-500 mb-3">
            {noneSelected
              ? "No status selected — pick one above, or choose all."
              : search || dateFrom || dateTo || !allSelected
                ? "No posts match this filter."
                : "No posts yet."}
          </p>
          <Link to="/new" className="text-sm text-amber-600 dark:text-amber-400 hover:underline">
            Compose a new post →
          </Link>
        </div>
      ) : (
        <>
          <TableShell>
            <thead className="border-b border-stone-200 dark:border-zinc-800">
              <tr>
                <SortHeader label="Status" col="status" activeCol={sortCol} dir={sortDir} onSort={onSort} />
                <SortHeader label="Post" activeCol={sortCol} dir={sortDir} onSort={onSort} />
                <SortHeader label="Scheduled" col="scheduled" activeCol={sortCol} dir={sortDir} onSort={onSort} />
                <SortHeader label="Edited" col="updated" activeCol={sortCol} dir={sortDir} onSort={onSort} />
                <SortHeader label="Posted" activeCol={sortCol} dir={sortDir} onSort={onSort} />
                <SortHeader label="" activeCol={sortCol} dir={sortDir} onSort={onSort} className="text-right" />
              </tr>
            </thead>
            <tbody>
              {posts.map((p) => {
              // The recorded reason is history, and X may have been reconnected
              // since. When it has been, an OAuth reason describes a cause that
              // is now fixed — so the row shows it as a past attempt rather than
              // a standing warning about an account that currently works.
              const oauthResolved =
                !!p.last_attempt_reason
                && OAUTH_NEEDED_CODES.has(p.last_attempt_reason)
                && xConn?.kind === "connected";
              return (
                <tr
                  key={p.post_id}
                  onClick={() => nav(`/post/${p.post_id}`)}
                  className="border-b border-stone-100 last:border-0 dark:border-zinc-900 hover:bg-stone-50 dark:hover:bg-zinc-900/60 cursor-pointer"
                >
                  <td className="px-3 py-2.5 align-top">
                    <span className={`text-xs px-2 py-0.5 rounded-full capitalize ${statusStyle[p.status] ?? statusStyle.draft}`}>
                      {p.status}
                    </span>
                    {/* A degraded send is still a send, so `status` reads "Sent"
                        in green and is RIGHT to. What it cannot say is that the
                        words that went out were the author's fallback rather
                        than the post they wrote. Until this badge existed the
                        only way to notice was to open the post and recognise
                        the fallback wording by eye — which is how four
                        flattened templates published their barista line on
                        schedule for days. */}
                    {(p.fell_back?.length ?? 0) > 0 && (
                      <span
                        className="mt-1 flex items-center gap-1 text-[11px] text-amber-600 dark:text-amber-400"
                        title={`This post went out with the author's FALLBACK text, not the post as written.\n\n${p.fell_back!
                          .map((f, i) => `Block ${i + 1}: ${attemptLabel(f.reason ?? "unreported")}${
                            f.budget_s ? ` (gave up within a ${f.budget_s}s budget)` : ""
                          }`)
                          .join("\n")}\n\nThe tweet is live; the content is the consolation copy. Open the post to see what was published.`}
                      >
                        ⚠ fell back to fallback text
                      </span>
                    )}
                    {/* Also on `resolved`/`resolving`: a post the recovery sweep
                        returned to the poster carries the reason it stalled, and
                        gating this on `scheduled` alone would hide exactly the
                        rows whose history the owner most needs. */}
                    {["scheduled", "resolved", "resolving"].includes(p.status)
                      && p.last_attempt_reason && (
                      <span
                        className={`mt-1 flex items-center gap-1 text-[11px] ${
                          oauthResolved
                            ? "text-stone-500 dark:text-zinc-400"
                            : "text-rose-600 dark:text-rose-400"
                        }`}
                        title={`Scheduler tried to post${p.last_attempt_at ? ` at ${fmt(p.last_attempt_at, timeZone)}` : ""} but held it back: ${p.last_attempt_reason}.${p.last_attempt_detail ? `\n\n${p.last_attempt_detail}` : ""}\n\n${oauthResolved ? "X has been reconnected since, so this cause is resolved. It will retry on the next tick." : "It will retry on the next tick."}`}
                      >
                        {oauthResolved
                          ? `↺ last attempt: ${attemptLabel(p.last_attempt_reason)}`
                          : `⚠ ${attemptLabel(p.last_attempt_reason)}`}
                      </span>
                    )}
                    {p.status === "paused" && p.last_attempt_reason && (
                      <span
                        className="mt-1 flex items-center gap-1 text-[11px] text-rose-600 dark:text-rose-400"
                        title={`Scheduler paused this post${p.last_attempt_at ? ` at ${fmt(p.last_attempt_at, timeZone)}` : ""}: ${p.last_attempt_reason}.${p.last_attempt_detail ? `\n\n${p.last_attempt_detail}` : ""}\n\n${UNCONFIRMED_SEND.includes(p.last_attempt_reason) ? "The publisher never confirmed, so this post MAY already be live on X. Check your timeline first — resuming a post that did go out publishes it twice." : "Fix the cause at the provider, then Resume to reschedule it."}`}
                      >
                        ⏸ {attemptLabel(p.last_attempt_reason)}
                      </span>
                    )}
                    {/* A post held because X genuinely needs (re)connecting is the
                        one case the owner can fix from here, so say so and offer
                        the door. Without this the row named the problem and left
                        the owner to guess that the cure lives under Profile.
                        Gated on OAUTH_NEEDED_CODES, which deliberately excludes
                        the self-healing codes — see its definition in lib/mcp.

                        Two further gates, because `last_attempt_reason` records
                        what was true at the LAST attempt and nothing rewrites it
                        afterwards:

                        • not while `sending` — a publisher is working this post
                          right now, so the previous attempt's reason is already
                          superseded and the row would read "Sending · Reconnect
                          X · working…", three states that cannot all be true.
                        • not when X is connected — after a reconnect the stale
                          reason still says the account expired, which sent an
                          owner with a working X account back to reconnect it
                          again. Only a definite `connected` suppresses the
                          button; `indeterminate` still offers it, since a warming
                          vault is not evidence the account is fine. */}
                    {p.last_attempt_reason
                      && OAUTH_NEEDED_CODES.has(p.last_attempt_reason)
                      && (p.status === "scheduled" || p.status === "paused")
                      && xConn?.kind !== "connected" && (
                      <button
                        type="button"
                        onClick={(e) => { e.stopPropagation(); nav("/profile"); }}
                        className="mt-1 inline-flex items-center gap-1 rounded-sm bg-amber-500/15 px-1.5 py-0.5 text-[11px] font-medium text-amber-700 transition-colors hover:bg-amber-500/25 dark:text-amber-400"
                        title="Reconnect your X account — this post reschedules itself once X accepts you again."
                      >
                        Reconnect X →
                      </button>
                    )}
                    {p.status === "sending" && (
                      <span
                        className="mt-1 flex items-center gap-1 text-[11px] text-sky-600 dark:text-sky-400"
                        title={`The scheduler claimed this post${p.last_attempt_at ? ` at ${fmt(p.last_attempt_at, timeZone)}` : ""} and is posting it. If it lingers here, use "to draft" to rescue it.`}
                      >
                        ⟳ working…
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2.5 align-top max-w-md">
                    {p.title ? (
                      <>
                        <p className="truncate font-medium text-stone-900 dark:text-zinc-100">{p.title}</p>
                        {p.excerpt && <p className="truncate text-xs text-stone-500 dark:text-zinc-400">{p.excerpt}</p>}
                      </>
                    ) : (
                      <p className="truncate text-stone-800 dark:text-zinc-200">{p.excerpt || "(empty draft)"}</p>
                    )}
                    {(p.is_recurring || p.has_dynamic || p.template_id) && (
                      <div className="mt-1 flex flex-wrap items-center gap-1.5">
                        {p.is_recurring && (
                          <span
                            className="inline-flex items-center gap-0.5 text-[11px] px-1.5 py-0.5 rounded-full bg-violet-100 text-violet-700 dark:bg-violet-500/15 dark:text-violet-300"
                            title="Recurring — this template reposts on its cadence, resolving fresh each time."
                          >
                            ↻ recurring
                          </span>
                        )}
                        {p.has_dynamic && (
                          <span
                            className="inline-flex items-center gap-0.5 text-[11px] px-1.5 py-0.5 rounded-full bg-amber-100 text-amber-700 dark:bg-amber-500/15 dark:text-amber-300"
                            title="Dynamic — carries a live prompt-driven block that resolves at post time (not frozen text)."
                          >
                            ⚡ dynamic
                          </span>
                        )}
                        {p.template_id && (
                          <Link
                            to={`/post/${p.template_id}`}
                            onClick={(e) => e.stopPropagation()}
                            className="inline-flex items-center gap-0.5 text-[11px] px-1.5 py-0.5 rounded-full bg-stone-100 text-stone-600 hover:underline dark:bg-zinc-800 dark:text-zinc-300"
                            title="This is a published record. Open the recurring template it fired from."
                          >
                            ↗ from series
                          </Link>
                        )}
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-2.5 align-top text-xs text-stone-400 dark:text-zinc-500 whitespace-nowrap">
                    {p.publish_at ? fmt(p.publish_at, timeZone) : "—"}
                  </td>
                  <td className="px-3 py-2.5 align-top text-xs text-stone-400 dark:text-zinc-500 whitespace-nowrap">
                    {p.updated_at ? fmt(p.updated_at, timeZone) : "—"}
                  </td>
                  <td className="px-3 py-2.5 align-top text-xs whitespace-nowrap">
                    {p.last_sent_at ? (
                      p.tweet_url ? (
                        <button
                          onClick={(e) => { e.stopPropagation(); e.preventDefault(); setPreview({ url: p.tweet_url!, text: p.excerpt || "" }); }}
                          className="inline-flex items-center gap-1 text-green-600 hover:underline dark:text-green-400"
                          title={`Peek at the posted tweet (${fmt(p.last_sent_at, timeZone)})`}
                        >
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" aria-hidden>
                            <path d={ICONS.visibility} />
                          </svg>
                          {fmt(p.last_sent_at, timeZone)}
                        </button>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-green-600 dark:text-green-400" title={`Posted to X at ${fmt(p.last_sent_at, timeZone)}`}>
                          ✓ {fmt(p.last_sent_at, timeZone)}
                        </span>
                      )
                    ) : (
                      <span className="text-stone-400 dark:text-zinc-500">—</span>
                    )}
                  </td>
                  <td className="px-3 py-2.5 align-top text-right whitespace-nowrap">
                    <span className="inline-flex items-center gap-1 justify-end">
                      <ActionIcon
                        path={ICONS.duplicate}
                        title="Duplicate — open an editable draft copy of this post (unscheduled)"
                        onClick={(e) => handleDuplicate(e, p.post_id)}
                        busy={duplicating === p.post_id}
                        hover="hover:text-amber-600 dark:hover:text-amber-400"
                      />
                      {p.status === "paused" && (
                        <ActionIcon
                          path={ICONS.resume}
                          title="Resume — reschedule this post so the next scheduler tick posts it"
                          onClick={(e) => handleResume(e, p.post_id)}
                          busy={resuming === p.post_id}
                          hover="hover:text-amber-600 dark:hover:text-amber-400"
                        />
                      )}
                      {(p.status === "sending" || p.status === "scheduled" || p.status === "paused") && (
                        <ActionIcon
                          path={ICONS.toDraft}
                          title="Return to Draft — unschedule this post so you can edit it (rescues a post stuck mid-send)"
                          onClick={(e) => handleReturnToDraft(e, p.post_id)}
                          busy={returningToDraft === p.post_id}
                          hover="hover:text-amber-600 dark:hover:text-amber-400"
                        />
                      )}
                      {p.status === "sent" && (
                        <ActionIcon
                          path={ICONS.repost}
                          title="Repost to X now"
                          onClick={(e) => handleRepost(e, p.post_id)}
                          busy={reposting === p.post_id}
                          hover="hover:text-green-600 dark:hover:text-green-400"
                        />
                      )}
                      {p.status !== "archived" && (
                        <ActionIcon
                          path={ICONS.archive}
                          title="Archive"
                          onClick={(e) => handleDelete(e, p.post_id, false)}
                          hover="hover:text-amber-600 dark:hover:text-amber-400"
                        />
                      )}
                      <ActionIcon
                        path={ICONS.delete}
                        title="Delete permanently"
                        onClick={(e) => handleDelete(e, p.post_id, true)}
                        hover="hover:text-red-500 dark:hover:text-red-400"
                      />
                    </span>
                  </td>
                </tr>
              );
              })}
            </tbody>
          </TableShell>
          <PageControls page={page} pageSize={PAGE_SIZE} total={total} onPage={setPage} />
        </>
      )}
    </div>
  );
}

function fmt(iso: string, timeZone: string): string {
  return formatDateTime(iso, timeZone);
}
