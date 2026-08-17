// Friendly labels for a held-attempt / fallback reason recorded by the scheduler
// Worker. Anything unmapped (e.g. a raw x_api_error string) shows verbatim.
//
// Shared so every surface that shows a reason — the Posts list, the Scheduler
// log — renders the SAME sentence. A reason code split across two hand-written
// maps is how one surface says "the operator's model provider is out of credit"
// while another shows the bare `operator_llm_unfunded` token beside it.
export function attemptLabel(reason: string): string {
  // Two reason families carry a value in the string itself, and the difference
  // between them is the whole point — whether the block ran out of ITS OWN time,
  // which the author can fix by raising runtimeLimit, or the provider failed,
  // which is an outage and no edit helps. Reported as one undifferentiated raw
  // token they read as the same event.
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
