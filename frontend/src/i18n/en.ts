/**
 * Every word eXcalibur's own pages say, in English: the bedrock the other
 * languages translate.
 *
 * Keys are "<area>.<file>.<name>" (areas: views, ui, lib). A `{{name}}` is
 * filled with a word or number; a `<name/>` or `<name>…</name>` is drawn as an
 * element. A translation keeps each one exactly as written and may move it.
 * "eXcalibur", X handles, post text and emoji stay as they are.
 */

export const en = {
  // ── ContentEditorPage: emoji picker group headings ──
  "ui.contentEditorPage.emoji.typographic": "Typographic",
  "ui.contentEditorPage.emoji.smileys": "Smileys",
  "ui.contentEditorPage.emoji.people": "Gestures & People",
  "ui.contentEditorPage.emoji.nature": "Nature",
  "ui.contentEditorPage.emoji.food": "Food & Drink",
  "ui.contentEditorPage.emoji.objects": "Activity & Objects",
  "ui.contentEditorPage.emoji.travel": "Travel & Places",
  "ui.contentEditorPage.emoji.symbols": "Symbols",
  "ui.contentEditorPage.emoji.money": "Money & Crypto",

  // ── ContentEditorPage: messages, hints and prompts ──
  "ui.contentEditorPage.snippetNotFound": "Snippet not found.",
  "ui.contentEditorPage.voiceSaveFailed": "Could not save Voice",
  "ui.contentEditorPage.flagSkippedOverlap": "Skipped part of the selection that overlapped an existing flag.",
  "ui.contentEditorPage.flagOverlaps": "That overlaps an existing flag.",
  "ui.contentEditorPage.flagEmptyBlock": "Nothing to flag — this block is empty.",
  "ui.contentEditorPage.flagOverlapsClear": "That overlaps an existing flag — clear it first.",
  "ui.contentEditorPage.refineUnavailable": "Refine is unavailable right now.",
  "ui.contentEditorPage.noSuggestions": "No suggestions returned.",
  "ui.contentEditorPage.regionUpdated": "Region updated.",
  "ui.contentEditorPage.regionUpdatedAcross": "Region updated across blocks.",
  "ui.contentEditorPage.snippetAddedDynamic": "Dynamic snippet added — its prompt runs at post time.",
  "ui.contentEditorPage.snippetAdded": "Snippet added as a block — drag it where you want.",
  "ui.contentEditorPage.nowDynamic": "Now a dynamic prompt — it runs at post time. Edit the prompt and fallback below, then Run to preview.",
  "ui.contentEditorPage.backToStatic": "Back to a static text block.",
  // {{token}} is the literal placeholder {{tweet_url}}, kept as is.
  "ui.contentEditorPage.nowNostr": "Nostr note — posts after the tweet lands. Use {{token}} to embed the live X link.",
  "ui.contentEditorPage.resolveFailed": "Couldn't resolve this prompt.",
  "ui.contentEditorPage.dividerAdded": "Divider added — X left-aligns text, so it sits at the line start.",
  "ui.contentEditorPage.draftRestored": "Restored your unsaved edits — Save when ready.",
  "ui.contentEditorPage.writeFirst": "Write something first.",
  "ui.contentEditorPage.setPublishTime": "Set a publish time.",
  "ui.contentEditorPage.savedReadyPast": "Saved — Ready; its time has passed, so it posts on the next scheduler run.",
  "ui.contentEditorPage.savedReady": "Saved — Ready.",
  "ui.contentEditorPage.savedHint": "Saved.",
  "ui.contentEditorPage.nameSnippetFirst": "Name your snippet first.",
  "ui.contentEditorPage.snippetSaveFailed": "Couldn't save the snippet.",
  "ui.contentEditorPage.saveAsSnippetPrompt": "Save as a new snippet named:",
  // The suggested name of a copy; {{name}} is the original's name or title.
  "ui.contentEditorPage.copyName": "{{name}} copy",
  "ui.contentEditorPage.defaultSnippetName": "Snippet",
  "ui.contentEditorPage.nameSnippetCopy": "Name your snippet copy.",
  "ui.contentEditorPage.copySaveFailed": "Couldn't save the copy.",
  "ui.contentEditorPage.saveAsPostPrompt": "Save as a new draft post titled:",
  "ui.contentEditorPage.untitled": "Untitled",
  "ui.contentEditorPage.deleteSnippetConfirm": "Delete this snippet?",
  "ui.contentEditorPage.discardAndMove": "Discard unsaved changes and move to the adjacent post?",
  "ui.contentEditorPage.dynamicNoFallback": "A dynamic block couldn't be resolved and has no fallback.",
  // {{why}} is a reason from the server, in English.
  "ui.contentEditorPage.scheduleFailed": "Couldn't schedule the post ({{why}}).",
  "ui.contentEditorPage.unknownError": "unknown error",
  "ui.contentEditorPage.deferredHint": "Ready — its blocks resolve in the background and it posts shortly.",
  "ui.contentEditorPage.nothingAfterResolve": "Nothing to post after resolving the dynamic blocks.",
  "ui.contentEditorPage.connectXFirst": "Connect your X account before posting.",
  "ui.contentEditorPage.postFailed": "Couldn't post to X.",
  "ui.contentEditorPage.relayRejected": "relay rejected",
  "ui.contentEditorPage.nostrDidntLand": "Posted to X; Nostr note didn't land ({{why}}).",
  "ui.contentEditorPage.recordSentFailed": "Posted to X, but couldn't record it as Sent ({{why}}). The tweet is live — try Save again to record it.",
  "ui.contentEditorPage.postedToX": "Posted to X.",
  "ui.contentEditorPage.openingSnippet": "Opening the snippet…",
  "ui.contentEditorPage.openingEditor": "Opening the editor…",

  // ── ContentEditorPage: rail tabs ──
  "ui.contentEditorPage.tabFlags": "Flags",
  "ui.contentEditorPage.tabFlagsCount": "Flags ({{n}})",
  "ui.contentEditorPage.tabVoice": "Voice",
  "ui.contentEditorPage.tabSnippets": "Snippets",
  "ui.contentEditorPage.tabSchedule": "Schedule",

  // ── ContentEditorPage: page ──
  // After the X handle on the tweet card: posted "now".
  "ui.contentEditorPage.now": "now",
  "ui.contentEditorPage.flagBlocks_one": "Flag {{count}} block",
  "ui.contentEditorPage.flagBlocks_other": "Flag {{count}} blocks",
  "ui.contentEditorPage.flagSelection": "Flag selection",
  // {{text}} is the start of the selected text.
  "ui.contentEditorPage.selectionQuote": "— \"{{text}}\"",
  "ui.contentEditorPage.cancelFlag": "Cancel — don't flag this",
  "ui.contentEditorPage.clearFlag": "Clear flag",
  "ui.contentEditorPage.backToSnippets": "Back to snippets",
  "ui.contentEditorPage.backToPosts": "Back to posts",
  "ui.contentEditorPage.headerSnippet": "eXcalibur Snippet",
  "ui.contentEditorPage.headerPosts": "eXcalibur Posts Manager",
  "ui.contentEditorPage.subSnippet": "reusable content",
  "ui.contentEditorPage.subPosts": "draft → refine → ready",
  "ui.contentEditorPage.prevPost": "Previous post (← arrow or swipe left)",
  "ui.contentEditorPage.nextPost": "Next post (→ arrow or swipe right)",
  // After the number of characters in the post.
  "ui.contentEditorPage.chars": "chars",
  "ui.contentEditorPage.saving": "Saving…",
  "ui.contentEditorPage.saveSnippet": "Save snippet",
  "ui.contentEditorPage.save": "Save",
  "ui.contentEditorPage.saveTitle": "Save your edits and the badge",
  "ui.contentEditorPage.postNowTitle": "Post to X now and mark this post sent",
  "ui.contentEditorPage.postNow": "Post now",
  "ui.contentEditorPage.saveAsTitleSnippet": "Save the current body as a new snippet",
  "ui.contentEditorPage.saveAsTitlePost": "Save the current body as a new draft post",
  "ui.contentEditorPage.saveAs": "Save as…",
  "ui.contentEditorPage.edit": "Edit",
  "ui.contentEditorPage.preview": "Preview",
  // {{when}} is a date and time, or the word "earlier".
  "ui.contentEditorPage.unsavedBanner": "You have unsaved edits from {{when}} that never finished saving.",
  "ui.contentEditorPage.earlier": "earlier",
  "ui.contentEditorPage.restore": "Restore",
  "ui.contentEditorPage.discard": "Discard",
  "ui.contentEditorPage.postedToXLabel": "Posted to X:",
  "ui.contentEditorPage.peekAt": "Peek at {{url}}",
  "ui.contentEditorPage.publishedRecord": "↻ This is a published record. To change future postings, edit the recurring template.",
  "ui.contentEditorPage.editTemplate": "Edit the template →",
  "ui.contentEditorPage.recurringFresh": "↻ This recurring post resolves fresh each time it fires.",
  "ui.contentEditorPage.viewPostings": "View published postings →",
  "ui.contentEditorPage.snippetName": "Snippet name",
  "ui.contentEditorPage.snippetNamePlaceholder": "My CTA Footer",
  "ui.contentEditorPage.titleLabel": "Title <muted>(optional)</muted>",
  "ui.contentEditorPage.titlePlaceholder": "Untitled — the list shows the first line",
  "ui.contentEditorPage.asOnX": "as it appears on X",
  "ui.contentEditorPage.editingStage": "editing stage",
  "ui.contentEditorPage.flagsReorder_one": "{{count}} flag · drag to reorder",
  "ui.contentEditorPage.flagsReorder_other": "{{count}} flags · drag to reorder",
  "ui.contentEditorPage.companionNotes": "companion Nostr notes · after the tweet lands",
  "ui.contentEditorPage.nostrNote": "nostr note",
  "ui.contentEditorPage.emptyNote": "(empty note)",
  "ui.contentEditorPage.addTextBlock": "Add text block",
  "ui.contentEditorPage.dividerTitle": "Insert a 20-char divider (────────────────────) as a block",
  "ui.contentEditorPage.divider": "Divider",
  "ui.contentEditorPage.insertSnippet": "Insert \"{{name}}\"",
  "ui.contentEditorPage.insertSnippetDynamic": "Insert \"{{name}}\" (dynamic prompt)",
  "ui.contentEditorPage.deleteSnippet": "Delete snippet",
  "ui.contentEditorPage.connectX": "Connect X →",

  // ── ContentEditorPage: a block ──
  "ui.contentEditorPage.resolvingUpTo": "resolving… (up to {{s}}s)",
  "ui.contentEditorPage.noPreviewYet": "(dynamic block — no preview yet)",
  // {{error}} is a reason from the server, in English.
  "ui.contentEditorPage.showingFallback": "Showing fallback — the dynamic prompt didn’t resolve: {{error}}",
  "ui.contentEditorPage.didntResolve": "The dynamic prompt didn’t resolve: {{error}}",
  "ui.contentEditorPage.dynamicHeader": "dynamic prompt · runs at post time",
  "ui.contentEditorPage.makeStaticNormalTitle": "Turn this back into a normal text block",
  "ui.contentEditorPage.makeStaticLower": "make static",
  "ui.contentEditorPage.promptPlaceholder": "Write the prompt to run, e.g. 'the current BTC price in USD, one short sentence'",
  "ui.contentEditorPage.fallbackPlaceholder": "Fallback text if it can't resolve (optional)",
  "ui.contentEditorPage.domainsPlaceholder": "Allowed web domains, comma-separated (blank = any)",
  "ui.contentEditorPage.maxFetchesTitle": "Max web lookups (search + fetch) for this prompt",
  // {{range}} is "60" or a range like "60–900".
  "ui.contentEditorPage.budgetTitle": "Time budget in seconds ({{range}}). Bounds runtime and may affect the fare.",
  // Short for seconds.
  "ui.contentEditorPage.sec": "sec",
  "ui.contentEditorPage.running": "Running…",
  "ui.contentEditorPage.run": "Run",
  "ui.contentEditorPage.previewHere": "preview the result here",
  "ui.contentEditorPage.makeStaticPlainTitle": "Turn this back into a plain text block",
  "ui.contentEditorPage.makeStatic": "Make static",
  "ui.contentEditorPage.deleteBlock": "Delete block",
  "ui.contentEditorPage.delete": "Delete",
  "ui.contentEditorPage.nostrHeader": "nostr note · posts after the tweet lands",
  // {{token}} is the literal placeholder {{tweet_url}}, kept as is.
  "ui.contentEditorPage.nostrPlaceholder": "Companion note text. Use {{token}} for the live X link.",
  "ui.contentEditorPage.insertTokenTitle": "Insert {{token}} at the cursor",
  "ui.contentEditorPage.neverEnters": "never enters the tweet",
  "ui.contentEditorPage.bold": "Bold (Unicode)",
  "ui.contentEditorPage.italic": "Italic (Unicode)",
  "ui.contentEditorPage.mono": "Monospace (Unicode)",
  "ui.contentEditorPage.insertEmoji": "Insert emoji or symbol",
  "ui.contentEditorPage.styleHint": "select text to style; ☺ inserts a symbol",
  "ui.contentEditorPage.dynamicEditing": "this is a dynamic prompt — it runs at post time",
  "ui.contentEditorPage.editingClears": "editing clears this block's flags",
  "ui.contentEditorPage.done": "Done",
  "ui.contentEditorPage.editText": "Edit text",
  "ui.contentEditorPage.makeDynamicTitle": "Make dynamic — turn this block's text into a prompt that runs at post time",
  "ui.contentEditorPage.dynamic": "Dynamic",
  "ui.contentEditorPage.makeNostrTitle": "Make Nostr — companion note that posts after the tweet lands",
  "ui.contentEditorPage.nostr": "Nostr",
  "ui.contentEditorPage.flagBlockTitle": "Flag this whole block for AI review",
  "ui.contentEditorPage.flag": "Flag",
  "ui.contentEditorPage.moveUp": "Move up",
  "ui.contentEditorPage.moveDown": "Move down",
  "ui.contentEditorPage.dragReorder": "Drag to reorder",

  // ── ContentEditorPage: Flags tab ──
  "ui.contentEditorPage.flagsEmpty": "Select any text in the tweet and tap <hl>Flag for AI</hl> to start a refinement.",
  "ui.contentEditorPage.swipeSelect": "swipe-select works on touch too",
  "ui.contentEditorPage.spansBlocks_one": "one region · spans {{count}} block",
  "ui.contentEditorPage.spansBlocks_other": "one region · spans {{count}} blocks",
  "ui.contentEditorPage.notePlaceholder": "What should change here? (optional)",
  "ui.contentEditorPage.refining": "Refining…",
  "ui.contentEditorPage.refine": "Refine",
  "ui.contentEditorPage.suggestions": "suggestions",
  "ui.contentEditorPage.useThis": "Use this",

  // ── ContentEditorPage: Snippets tab ──
  "ui.contentEditorPage.saveFocused": "Save the focused block",
  "ui.contentEditorPage.snippetPlaceholder": "My CTA Footer 26jun2026",
  // {{text}} is the start of the block's text.
  "ui.contentEditorPage.savesPreview": "Saves: \"{{text}}\"",
  "ui.contentEditorPage.clickBlockFirst": "Click into a block first, then save its text as a reusable snippet.",
  "ui.contentEditorPage.library": "Library",
  "ui.contentEditorPage.noSnippets": "No snippets yet — save common openings and footers here, then click to drop them into any post.",
  "ui.contentEditorPage.unfavorite": "Unfavorite",
  "ui.contentEditorPage.favoriteTitle": "Favorite — adds a one-click chiclet by Add text block",
  "ui.contentEditorPage.dynamicSnippetTitle": "Dynamic — its text is a prompt run at post time. Click to make static.",
  "ui.contentEditorPage.makeDynamicSnippetTitle": "Make dynamic — treat its text as a prompt run at post time",
  "ui.contentEditorPage.addAsDynamic": "Add as a dynamic block",
  "ui.contentEditorPage.addAsBlock": "Add as a block",
  "ui.contentEditorPage.insert": "+ Insert",

  // ── ContentEditorPage: Voice tab ──
  "ui.contentEditorPage.voiceProfile": "Voice profile",
  "ui.contentEditorPage.voicePlaceholder": "Paste a few sentences in your own voice…",
  "ui.contentEditorPage.voiceHelp": "Sent with every refinement so rewrites sound like you, not like a model.",
  "ui.contentEditorPage.bannedConstructions": "Banned constructions",
  "ui.contentEditorPage.saveChip": "Save chip",
  "ui.contentEditorPage.toggleConstraint": "Toggle constraint",
  "ui.contentEditorPage.remove": "Remove",
  "ui.contentEditorPage.addBanPlaceholder": "Add a construction to avoid…",
  "ui.contentEditorPage.add": "Add",
  "ui.contentEditorPage.bansHelp": "Active chips are passed as hard constraints. Tap a chip to disable it, the pencil to edit, the minus to remove.",
  "ui.contentEditorPage.saveVoice": "Save Voice",
  "ui.contentEditorPage.savedBadge": "Saved",
  "ui.contentEditorPage.unsavedChanges": "Unsaved changes",

  // ── ContentEditorPage: Schedule tab ──
  "ui.contentEditorPage.publishAt": "Publish at",
  // <zone/> is the time zone's name; <ready> and <postNow> are the labels of the badge and the button.
  "ui.contentEditorPage.scheduleHelp": "Times are in <zone/>. The scheduler sweeps on the hour and the half hour, so a post goes out at the next :00 or :30 after its publish time — once its badge says <ready>Ready</ready>. Need it out this instant? Use <postNow>Post now</postNow>.",
  "ui.contentEditorPage.republish": "Republish",
  "ui.contentEditorPage.freqNone": "Once, no repeat",
  "ui.contentEditorPage.freqDaily": "Daily",
  "ui.contentEditorPage.freqWeekdays": "Business Days (Mon–Fri)",
  "ui.contentEditorPage.freqWeekly": "Weekly",
  "ui.contentEditorPage.freqMonthly": "Monthly",
  // Before the number of days, weeks or months between repeats.
  "ui.contentEditorPage.every": "every",
  "ui.contentEditorPage.cease": "Cease republication",
  "ui.contentEditorPage.discardDraft": "Discard draft",
  "ui.contentEditorPage.archivePost": "Archive post",

  // ── ContentEditorPage: calendar preview ──
  "ui.contentEditorPage.setTimeToPreview": "Set a publish time to preview the schedule.",
  "ui.contentEditorPage.prevMonth": "Previous month",
  "ui.contentEditorPage.nextMonth": "Next month",
  // Calendar legend: the first posting day, the days it repeats, the day it stops.
  "ui.contentEditorPage.legendStart": "start",
  "ui.contentEditorPage.legendRepeats": "repeats",
  "ui.contentEditorPage.legendCease": "cease",

  // Posts list (PostsPage)
  "ui.postsPage.title": "Posts",
  "ui.postsPage.compose": "Compose",
  "ui.postsPage.composeNew": "Compose a new post",
  // Which date the date filter reads.
  "ui.postsPage.dateCreated": "Created",
  "ui.postsPage.dateUpdated": "Updated",
  "ui.postsPage.dateScheduled": "Scheduled",
  "ui.postsPage.datePosted": "Posted",
  "ui.postsPage.confirmDelete": "Permanently delete this post? This cannot be undone.",
  "ui.postsPage.nothingToRepost": "Nothing to repost.",
  "ui.postsPage.repostFailed": "Repost failed.",
  "ui.postsPage.reposted": "Reposted to X.",
  "ui.postsPage.duplicateFailed": "Duplicate failed.",
  "ui.postsPage.templateBanner": "Showing published postings from one recurring template.",
  "ui.postsPage.openTemplate": "Open the template",
  "ui.postsPage.clear": "Clear",
  // {{hour}} is a clock hour such as "9 AM"; {{zone}} is a time zone id such as America/New_York.
  "ui.postsPage.hourBanner": "Showing posts sent around <hour>{{hour}}</hour> <zone>({{zone}})</zone>.",
  "ui.postsPage.backToPerformance": "Back to Performance",
  // Status filter chip: select every status.
  "ui.postsPage.all": "all",
  "ui.postsPage.allTitle": "Show every status",
  // Status filter chip: clear every status.
  "ui.postsPage.none": "none",
  "ui.postsPage.noneTitle": "Clear every status, then pick the ones you want",
  // {{label}} is a post status such as Draft or Ready.
  "ui.postsPage.chicletShowing": "Showing {{label}} posts — click to hide",
  "ui.postsPage.chicletHiding": "Hiding {{label}} posts — click to show",
  "ui.postsPage.refresh": "Refresh posts",
  "ui.postsPage.searchPlaceholder": "Search content (regex)…",
  "ui.postsPage.searchTitle": "Case-insensitive regular expression matched against the content",
  "ui.postsPage.loading": "Loading your posts…",
  "ui.postsPage.emptyNoStatus": "No status selected — pick one above, or choose all.",
  "ui.postsPage.emptyFiltered": "No posts match this filter.",
  "ui.postsPage.emptyNone": "No posts yet.",
  "ui.postsPage.colStatus": "Status",
  "ui.postsPage.colPost": "Post",
  "ui.postsPage.colScheduled": "Scheduled",
  "ui.postsPage.colEdited": "Edited",
  "ui.postsPage.colPosted": "Posted",
  "ui.postsPage.unconfirmedCaution": "The publisher never confirmed, so this post MAY already be live on X. Check your timeline first — a post that did go out would publish twice.",
  // {{blocks}} is one line per block, each from fellBackBlock.
  "ui.postsPage.fellBackTitle": "This post went out with the author's FALLBACK text, not the post as written.\n\n{{blocks}}\n\nThe tweet is live; the content is the consolation copy. Open the post to see what was published.",
  "ui.postsPage.fellBackBlock": "Block {{n}}: {{reason}}",
  "ui.postsPage.fellBackBlockBudget": "Block {{n}}: {{reason}} (gave up within a {{budget}}s budget)",
  "ui.postsPage.fellBack": "fell back — {{reasons}}",
  // {{reason}} is a raw reason code from the scheduler.
  "ui.postsPage.held": "Scheduler tried to post but held it back: {{reason}}.",
  "ui.postsPage.heldAt": "Scheduler tried to post at {{at}} but held it back: {{reason}}.",
  "ui.postsPage.retry": "It will retry on the next tick.",
  "ui.postsPage.retryResolved": "X has been reconnected since, so this cause is resolved. It will retry on the next tick.",
  "ui.postsPage.lastAttempt": "last attempt: {{reason}}",
  "ui.postsPage.paused": "Scheduler paused this post: {{reason}}.",
  "ui.postsPage.pausedAt": "Scheduler paused this post at {{at}}: {{reason}}.",
  "ui.postsPage.pausedFix": "Fix the cause at the provider, then mark it Ready.",
  "ui.postsPage.reconnect": "Reconnect X",
  "ui.postsPage.reconnectTitle": "Reconnect your X account — this post reschedules itself once X accepts you again.",
  "ui.postsPage.sending": "The scheduler claimed this post and is posting it. If it lingers here, return it to Draft to rescue it.",
  "ui.postsPage.sendingAt": "The scheduler claimed this post at {{at}} and is posting it. If it lingers here, return it to Draft to rescue it.",
  "ui.postsPage.working": "working…",
  "ui.postsPage.emptyDraft": "(empty draft)",
  "ui.postsPage.recurring": "recurring",
  "ui.postsPage.recurringTitle": "Recurring — this template reposts on its cadence, resolving fresh each time.",
  "ui.postsPage.dynamic": "dynamic",
  "ui.postsPage.dynamicTitle": "Dynamic — carries a live prompt-driven block that resolves at post time (not frozen text).",
  "ui.postsPage.fromSeries": "from series",
  "ui.postsPage.fromSeriesTitle": "This is a published record. Open the recurring template it fired from.",
  "ui.postsPage.peekTitle": "Peek at the posted tweet ({{at}})",
  "ui.postsPage.postedAtTitle": "Posted to X at {{at}}",
  "ui.postsPage.duplicateTitle": "Duplicate — open an editable draft copy of this post (unscheduled)",
  "ui.postsPage.repostTitle": "Repost to X now",
  "ui.postsPage.archiveTitle": "Archive",
  "ui.postsPage.deleteTitle": "Delete permanently",
  // Performance page (PerformancePage)
  "ui.performancePage.tipPosts": "How many of your posts have at least one harvested metrics reading.",
  "ui.performancePage.tipSnapshots": "A snapshot is one reading of a post's metrics at a cadence step (t+15m, +1h, +6h, +24h, +72h, +7d, +28d). Whatever is not snapshotted inside that 28-day window is gone — X stops exposing the private metrics after ~30 days.",
  "ui.performancePage.tipMedianT15": "Your personal baseline: the rolling median of impressions in the first 15 minutes across your harvested posts. This is the denominator of escape velocity — why the number is on the page at all. Unit: impressions.",
  "ui.performancePage.tipFollowers": "Your current X follower count (best-effort from the account lookup). Context only — not used in escape velocity or breakout ratio, which both compare a post to your own rolling median.",
  "ui.performancePage.tipEscapeVelocity": "How this post's first 15 minutes compared to your own typical post: impressions at t+15m ÷ your rolling median t+15m. Above 1× means faster than your normal.",
  "ui.performancePage.tipBreakoutRatio": "How this post's final reach compared to your own typical post: impressions at the latest reading (preferring t+28d) ÷ your rolling median final impressions. Above 1× outpaced your baseline; below 1× under-reached. Empty until at least five posts have a final reading — a thinner sample is too noisy to trust.",
  "ui.performancePage.tipTrend": "Impressions at each snapshot for this post, oldest to newest (t+15m through +28d). The line shows the shape of the climb; the Impr. column carries the latest number.",
  "ui.performancePage.tipLinkPlacement": "Median impressions grouped by where the link sat — in the body, in the first reply, or no link at all. Only the groups your corpus actually contains appear, and the panel stays hidden until there are two of them, because one median compares to nothing. Sample size (n) is shown so a one-post group is not mistaken for a solid median.",
  "ui.performancePage.tipProfileClicks": "How many readers opened your profile from this post. Strongest free intent proxy on X: the post made someone want to find out who wrote it. The rate is profile clicks ÷ impressions.",
  "ui.performancePage.tipBookmarks": "Saves for later. X weights bookmarks heavily in ranking; bookmark rate (bookmarks ÷ impressions) separates evergreen reference posts from ephemeral ones.",
  "ui.performancePage.tipReplyRate": "Replies ÷ impressions, kept separate from the blended engagement mix. Author-reply chains carry heavy ranking weight, so this predicts next-post reach better than aggregates.",
  "ui.performancePage.tipQuoteToRepost": "Quotes ÷ reposts. Quotes recruit the quoter's out-of-network audience with commentary; plain reposts do neither to the same degree. High ratio means the post provoked response, not mere agreement.",
  "ui.performancePage.tipTimeOfDay": "Median impressions for posts sent in each hour, shown on a continuous 24-hour local-time axis. Gaps mean that hour has never been tried. Bars with n<3 are dimmed as provisional — a median of one post is that post wearing a statistical label.",
  "ui.performancePage.untitledPost": "Untitled post",
  "ui.performancePage.todAria": "Median impressions by local send hour across a full day. Click a bar to open posts sent in that hour.",
  // impr. = impressions; n = number of posts.
  "ui.performancePage.todBar": "{{hour}} · median {{median}} impr. · n={{n}} — open posts",
  "ui.performancePage.todBarProvisional": "{{hour}} · median {{median}} impr. · n={{n}} (provisional) — open posts",
  "ui.performancePage.todBarEmpty": "{{hour}} · no posts yet",
  "ui.performancePage.todBarOpen": "Open posts sent around {{hour}}",
  "ui.performancePage.todFooter": "Local time ({{zone}}). Bars with n<3 are provisional. Click a bar to open those posts.",
  "ui.performancePage.sortedDesc": "{{column}}, sorted descending",
  "ui.performancePage.sortedAsc": "{{column}}, sorted ascending",
  "ui.performancePage.sortBy": "Sort by {{column}}",
  "ui.performancePage.title": "Performance",
  "ui.performancePage.intro": "How your recent posts are travelling — early momentum versus your own baseline, final reach versus that same baseline, and where a link helped. Metrics are read at set intervals for 28 days after each send; after that X stops exposing them.",
  "ui.performancePage.refresh": "Refresh performance",
  "ui.performancePage.loading": "Loading performance…",
  "ui.performancePage.statPosts": "Posts",
  "ui.performancePage.statSnapshots": "Snapshots",
  // t+15m = 15 minutes after the post was sent.
  "ui.performancePage.statMedianT15": "Median t+15m",
  // Short for impressions.
  "ui.performancePage.unitImpr": "impr.",
  "ui.performancePage.statFollowers": "Followers",
  "ui.performancePage.colMedianImpressions": "Median impressions",
  "ui.performancePage.provisional": "provisional",
  "ui.performancePage.todTitle": "Time of day",
  "ui.performancePage.todIntro": "Median impressions by the local hour the post went out — continuous 24-hour axis so untried hours stay visible.",
  "ui.performancePage.reachTitle": "Posts by reach",
  "ui.performancePage.empty": "No harvested metrics yet. After a post is sent, snapshots land at t+15m, +1h, +6h, +24h, +72h, +7d, and +28d.",
  "ui.performancePage.backToPosts": "Back to posts",
  "ui.performancePage.colPost": "Post",
  "ui.performancePage.colTrend": "Trend",
  "ui.performancePage.breakoutThin": "Breakout ratio needs at least {{min}} posts with a final reading before the baseline is trustworthy — {{sample}} so far. Cells stay empty rather than guessing.",
  "ui.performancePage.mixTitle": "Format mix",
  "ui.performancePage.mixIntro": "How often each format goes out, and how far it travels. n is the posts behind each row.",
  "ui.performancePage.mixOnlyOne": "Every harvested post uses this format, so there is nothing to compare it with yet.",
  "ui.performancePage.colShare": "Share",
  "ui.performancePage.lastTitle": "Your last {{count}} posts",
  "ui.performancePage.lastIntro": "Views on each post, oldest to newest. The dashed line is your typical post.",
  "ui.performancePage.lastTypical": "typical {{value}}",
  "ui.performancePage.lastClipped": "Tallest bar cut off: best post {{value}} views.",
  "ui.performancePage.lastBar": "{{posted}} · {{views}} views. Open the post.",
  "ui.performancePage.tipLast": "Latest views on each of your newest posts. The dashed line is your typical post: the rolling median of final reach across your harvested posts.",
  "ui.performancePage.statViewsPerFollower": "Views / follower",
  "ui.performancePage.tipViewsPerFollower": "Your typical post's final reach ÷ your followers. Above 100% means your posts travel past your own followers.",
  "ui.performancePage.statEngagement": "Engagement",
  "ui.performancePage.tipEngagement": "Likes, replies, reposts and quotes ÷ views, pooled over all your harvested posts.",
  "ui.performancePage.followingRatio": "Following {{following}} · {{ratio}}:1",
  "ui.performancePage.followerGrowth": "{{delta}} in {{days}} days",
  "ui.performancePage.trendTitle": "Daily trend",
  "ui.performancePage.tipTrendDaily": "Followers and following are read once a day. Median views are the posts you sent each local day.",
  "ui.performancePage.trendFollowers": "Followers",
  "ui.performancePage.trendFollowing": "Following",
  "ui.performancePage.trendMedianViews": "Median views",
  "ui.performancePage.range30": "30 days",
  "ui.performancePage.range90": "90 days",
  "ui.performancePage.trendStarted": "Tracking started {{date}}. The line appears once 2 or more days are recorded.",
  "ui.performancePage.trendEmpty": "Nothing recorded in this range yet.",
  "ui.performancePage.trendPoint": "{{date}} · {{value}}",
  // Performance table columns (lib/performanceTable): short must stay a tight token, at most 8 characters
  "lib.performanceTable.postedShort": "Posted",
  "lib.performanceTable.postedFull": "Posted",
  "lib.performanceTable.impressionsShort": "Impr.",
  "lib.performanceTable.impressionsFull": "Impressions",
  "lib.performanceTable.escapeShort": "Escape",
  "lib.performanceTable.escapeFull": "Escape velocity",
  "lib.performanceTable.breakoutShort": "Breakout",
  "lib.performanceTable.breakoutFull": "Breakout ratio",
  "lib.performanceTable.clicksShort": "Clicks",
  "lib.performanceTable.clicksFull": "Link clicks",
  "lib.performanceTable.profileShort": "Profile",
  "lib.performanceTable.profileFull": "Profile clicks",
  "lib.performanceTable.bookmarksShort": "Saves",
  "lib.performanceTable.bookmarksFull": "Bookmarks",
  "lib.performanceTable.replyShort": "Reply",
  "lib.performanceTable.replyFull": "Reply rate",
  "lib.performanceTable.quoteShort": "Q/R",
  "lib.performanceTable.quoteFull": "Quote / repost ratio",
  // Where a post's link sat: no link.
  "lib.performanceTable.placementNone": "None",
  // The link sat in the post's body.
  "lib.performanceTable.placementBody": "Body",
  // The link sat in the first reply.
  "lib.performanceTable.placementFirstReply": "First reply",
  // Save errors (lib/postDraft)
  "lib.postDraft.notReached": "The save didn't reach the server — your edits are still here. Try again.",
  "lib.postDraft.blocked": "The save was blocked — nothing was changed. Your edits are still here.",
  "lib.postDraft.unconfirmed": "The save didn't confirm — your edits are still here. Try again.",
  // Why the scheduler held or fell back (lib/attemptLabel); lower-case, shown after a status badge
  "lib.attemptLabel.timedOut": "ran out of its own {{seconds}}s budget — raise the block's time limit",
  "lib.attemptLabel.connectError": "couldn't reach the model provider",
  "lib.attemptLabel.readError": "lost the connection to the model provider",
  "lib.attemptLabel.remoteProtocolError": "the model provider closed the connection early",
  // {{kind}} is an error class name; leave it as is.
  "lib.attemptLabel.providerFailed": "the model provider failed ({{kind}})",
  "lib.attemptLabel.x402": "X declined it (402)",
  "lib.attemptLabel.x429": "X rate limit",
  "lib.attemptLabel.xRefused": "X refused the request",
  "lib.attemptLabel.xError": "X error",
  "lib.attemptLabel.insufficientBalance": "out of credits",
  "lib.attemptLabel.insufficientBalanceResolve": "out of credits",
  "lib.attemptLabel.operatorLlmUnfunded": "the operator's model provider is out of credit — top it up",
  "lib.attemptLabel.operatorLlmAuth": "the model provider rejected the operator's API key",
  "lib.attemptLabel.operatorLlmModelUnknown": "the configured model no longer exists at the provider",
  "lib.attemptLabel.upstreamRateLimited": "the model provider rate-limited us — retrying",
  "lib.attemptLabel.oauthTokenExpired": "X access expired",
  "lib.attemptLabel.oauthUnavailable": "X not connected",
  "lib.attemptLabel.oauthNotYetAuthorized": "X not connected",
  "lib.attemptLabel.oauthRefreshTokenLost": "X renewal was cut off — reconnect once",
  "lib.attemptLabel.oauthNoRefreshToken": "X access can't renew itself",
  "lib.attemptLabel.operatorAppCredentialsRejected": "operator's X app was refused",
  "lib.attemptLabel.oauthRefreshRequestMalformed": "renewal request rejected — service bug",
  "lib.attemptLabel.oauthRefreshFailedUnclassified": "renewal failed — retrying",
  "lib.attemptLabel.oauthRefreshUnavailable": "X didn't answer — retrying",
  "lib.attemptLabel.oauthTokenRejected": "renewing X access — retrying",
  "lib.attemptLabel.xPostOutcomeUnknown": "X didn't confirm — check your timeline",
  "lib.attemptLabel.sendingOrphanedPreSplit": "send unrecorded — check your timeline",
  "lib.attemptLabel.firingAttemptsExhausted": "gave up retrying — resume when fixed",
  "lib.attemptLabel.xCallMarkUnavailable": "couldn't confirm send state — retrying",
  "lib.attemptLabel.emptyTextCache": "empty content",
  "lib.attemptLabel.pricingUnavailable": "pricing unavailable",
  "lib.attemptLabel.warmingUp": "service warming up",
  "lib.attemptLabel.vaultBootstrapping": "service warming up",
  "lib.attemptLabel.secureCourierUnavailable": "service warming up",
  "lib.attemptLabel.vaultUnavailable": "balance unconfirmed — retrying",
  "lib.attemptLabel.operatorCredentialsMissing": "operator setup pending",
  "lib.attemptLabel.persistenceQuotaExceeded": "operator database over quota",
  "lib.attemptLabel.persistenceMisconfigured": "operator database needs repair",

  // ── Leads page (src/components/ConversationsPage.tsx) ──
  "ui.conversationsPage.title": "Leads",
  "ui.conversationsPage.connectX": "Connect X →",
  // Date filter fields: when a lead was found, when its post was posted.
  "ui.conversationsPage.dateFound": "Found",
  "ui.conversationsPage.datePosted": "Posted",
  // Lead statuses, shown on the filter chips and in a lead's details.
  "ui.conversationsPage.status.new": "new",
  "ui.conversationsPage.status.seen": "seen",
  "ui.conversationsPage.status.engaged": "engaged",
  "ui.conversationsPage.status.dismissed": "dismissed",
  "ui.conversationsPage.actionSeen": "Seen",
  "ui.conversationsPage.actionEngaged": "Engaged — I replied by hand",
  "ui.conversationsPage.actionDismiss": "Dismiss",
  "ui.conversationsPage.connectFirst": "Connect your X account before searching.",
  "ui.conversationsPage.searchFailed": "Search failed.",
  // {{name}} is the saved query's name.
  "ui.conversationsPage.confirmDelete": "Delete \"{{name}}\"? Its leads are kept.",
  "ui.conversationsPage.confirmPurge": "Forget the leads \"{{name}}\" found that X no longer shows? Engaged leads are kept.",
  "ui.conversationsPage.purged": "{{n}} purged",
  // Shown when the selected saved query has no name.
  "ui.conversationsPage.queryFallback": "query",
  // {{label}} is the search text the patron typed.
  "ui.conversationsPage.runLabel": "“{{label}}”",
  "ui.conversationsPage.adhocPlaceholder": "One-off search, e.g. (\"MCP server\" OR \"MCP tool\") (monetize OR billing)",
  "ui.conversationsPage.adhocTitle": "Search X's last 7 days without saving the query",
  "ui.conversationsPage.run": "Run",
  "ui.conversationsPage.allLeads": "All leads",
  "ui.conversationsPage.searchPlaceholder": "Search text or @handle (regex)…",
  "ui.conversationsPage.searchTitle": "Case-insensitive regular expression matched against the post text or author handle",
  "ui.conversationsPage.clear": "Clear",
  "ui.conversationsPage.loading": "Loading your leads…",
  "ui.conversationsPage.notRunYet": "This query hasn't run yet.",
  "ui.conversationsPage.foundNoOne": "This search found no one.",
  "ui.conversationsPage.noMatch": "No leads match this filter.",
  // Table column headings.
  "ui.conversationsPage.colScore": "Score",
  "ui.conversationsPage.colPost": "Post",
  "ui.conversationsPage.colAuthor": "Author",
  "ui.conversationsPage.colReplies": "Replies",
  "ui.conversationsPage.colPosted": "Posted",
  "ui.conversationsPage.hasPhoto": "Has a photo",
  "ui.conversationsPage.foundByRun": "Found by this run",
  "ui.conversationsPage.replyAgain": "Reply again",
  "ui.conversationsPage.replyTitle": "Reply — posts to X as you, marks engaged",
  "ui.conversationsPage.noSignals": "no signals fired",
  "ui.conversationsPage.isReply": "a reply in the thread",
  "ui.conversationsPage.topOfThread": "top of the thread",
  // {{found}} and {{seen}} are dates and times.
  "ui.conversationsPage.foundSeen": "Found {{found}} · last seen {{seen}}",
  // <sources/> is the names of the saved queries that found the lead.
  "ui.conversationsPage.from": "From <sources/>",
  // {{when}} is a date and time.
  "ui.conversationsPage.replied": "Replied {{when}}",
  "ui.conversationsPage.openOnX": "Open on X",

  // ── Saved queries (src/components/ConversationQueriesPanel.tsx) ──
  "ui.conversationQueriesPanel.title": "Saved queries",
  "ui.conversationQueriesPanel.new": "New",
  "ui.conversationQueriesPanel.empty": "No saved queries yet — save one to re-run it and read only what's new.",
  // How many scoring weights the patron changed from the defaults.
  "ui.conversationQueriesPanel.tuned": "{{n}} tuned",
  "ui.conversationQueriesPanel.safeOn": "Safe defaults on",
  "ui.conversationQueriesPanel.safeOff": "Safe defaults off",
  "ui.conversationQueriesPanel.runAgain": "Search again — adds X posts newer than the last run",
  "ui.conversationQueriesPanel.edit": "Edit",
  "ui.conversationQueriesPanel.purge": "Purge leads X no longer shows (engaged leads are kept)",
  "ui.conversationQueriesPanel.delete": "Delete (its leads are kept)",

  // ── Reply box (src/components/ConversationReplyEditor.tsx) ──
  "ui.conversationReplyEditor.connectFirst": "Connect your X account before replying.",
  "ui.conversationReplyEditor.failed": "Couldn't post the reply.",
  "ui.conversationReplyEditor.handedOff": "X only lets us reply through the API where the author has mentioned you — so your words are waiting in X's composer. Press Post there, then confirm here.",
  "ui.conversationReplyEditor.openAgain": "Open X again",
  "ui.conversationReplyEditor.markEngaged": "Mark this lead engaged",
  "ui.conversationReplyEditor.iPosted": "I posted it",
  "ui.conversationReplyEditor.close": "Close",
  // <handle/> is the author's @handle.
  "ui.conversationReplyEditor.replyingTo": "Replying to <handle/>",
  "ui.conversationReplyEditor.placeholder": "Your reply, in your own words",
  "ui.conversationReplyEditor.postTitle": "Post the reply to X with your account (⌘↵)",
  "ui.conversationReplyEditor.post": "Post",

  // ── Saved query editor (src/components/ConversationQueryEditor.tsx) ──
  "ui.conversationQueryEditor.failed": "Couldn't save the query.",
  "ui.conversationQueryEditor.name": "Name",
  "ui.conversationQueryEditor.queryPlaceholder": "X search clause — your own nouns, e.g. (\"sound money\" OR mises) (recommend OR \"what should I read\")",
  // The X search operators stay as written.
  "ui.conversationQueryEditor.safeTitle": "Append -is:retweet lang:en",
  "ui.conversationQueryEditor.safe": "safe defaults",
  "ui.conversationQueryEditor.save": "Save",
  "ui.conversationQueryEditor.delete": "Delete saved query (its leads are kept)",
  "ui.conversationQueryEditor.close": "Close",
  "ui.conversationQueryEditor.scoring": "Scoring",
  "ui.conversationQueryEditor.tuned": "{{n}} tuned",
  // {{n}} is the default value.
  "ui.conversationQueryEditor.resetTo": "Reset to {{n}}",

  // ── Snippets page (src/components/SnippetsPage.tsx) ──
  "ui.snippetsPage.dateCreated": "Created",
  "ui.snippetsPage.dateUpdated": "Updated",
  "ui.snippetsPage.confirmDelete": "Delete this snippet? This cannot be undone.",
  "ui.snippetsPage.title": "Snippets",
  "ui.snippetsPage.new": "+ New snippet",
  "ui.snippetsPage.intro": "Reusable content for your posts — favorites appear as one-click chiclets in the editor.",
  "ui.snippetsPage.searchPlaceholder": "Search content (regex)…",
  "ui.snippetsPage.searchTitle": "Case-insensitive regular expression matched against the content",
  "ui.snippetsPage.clear": "Clear",
  "ui.snippetsPage.loading": "Loading your snippets…",
  "ui.snippetsPage.noMatch": "No snippets match this filter.",
  "ui.snippetsPage.empty": "No snippets yet.",
  "ui.snippetsPage.createFirst": "Create your first snippet →",
  // Table column headings.
  "ui.snippetsPage.colName": "Name",
  "ui.snippetsPage.colContent": "Content",
  "ui.snippetsPage.colEdited": "Edited",
  "ui.snippetsPage.unfavorite": "Unfavorite",
  "ui.snippetsPage.favorite": "Favorite — adds a one-click chiclet in the editor",
  "ui.snippetsPage.editTitle": "Edit",
  "ui.snippetsPage.edit": "edit",
  "ui.snippetsPage.deleteTitle": "Delete",
  "ui.snippetsPage.delete": "delete",

  // ── Leads presentation (src/lib/conversationsPresentation.ts) ──
  // A lead no saved query found: it came from a one-off search.
  "lib.conversationsPresentation.adHoc": "ad hoc",
  // Scoring signals and the weights that tune them.
  "lib.conversationsPresentation.signal.need": "Asks a question",
  "lib.conversationsPresentation.signal.thread": "Live thread",
  "lib.conversationsPresentation.signal.reachable": "Reachable author",
  "lib.conversationsPresentation.signal.spam": "Looks promotional",
  "lib.conversationsPresentation.signal.reply": "Is itself a reply",
  "lib.conversationsPresentation.signal.aged": "Older — score decayed",
  "lib.conversationsPresentation.weight.need": "Asks a question",
  "lib.conversationsPresentation.weight.needHint": "how do I, anyone know, looking for…",
  "lib.conversationsPresentation.weight.replies": "Live thread",
  "lib.conversationsPresentation.weight.repliesHint": "reply count at or above the threshold",
  "lib.conversationsPresentation.weight.repliesMin": "Thread threshold",
  "lib.conversationsPresentation.weight.repliesMinHint": "replies needed to count as live",
  "lib.conversationsPresentation.weight.band": "Reachable author",
  "lib.conversationsPresentation.weight.bandHint": "followers inside the band",
  "lib.conversationsPresentation.weight.followersMin": "Band from",
  "lib.conversationsPresentation.weight.followersMax": "Band to",
  "lib.conversationsPresentation.weight.followersHint": "followers",
  "lib.conversationsPresentation.weight.spam": "Looks promotional",
  "lib.conversationsPresentation.weight.spamHint": "cashtags, styled letters, airdrop…",
  "lib.conversationsPresentation.weight.reply": "Is a reply",
  "lib.conversationsPresentation.weight.replyHint": "not a top-level post",
  "lib.conversationsPresentation.weight.decayHours": "Fades over",
  "lib.conversationsPresentation.weight.decayHoursHint": "hours until positive signals reach 0",
  // {{label}} is a weight's name from the list above.
  "lib.conversationsPresentation.notWhole": "{{label}} must be a whole number",
  "lib.conversationsPresentation.outOfRange": "{{label}} must be between {{min}} and {{max}}",
  "lib.conversationsPresentation.bandInverted": "Band from must not exceed Band to",
  // When a saved query last ran.
  "lib.conversationsPresentation.never": "never",
  "lib.conversationsPresentation.justNow": "just now",
  "lib.conversationsPresentation.minAgo": "{{n}} min ago",
  "lib.conversationsPresentation.hAgo": "{{n}} h ago",
  "lib.conversationsPresentation.dAgo": "{{n}} d ago",
  // {{when}} is one of the times above; {{n}} is how many X posts the run read.
  "lib.conversationsPresentation.whenRead": "{{when}} · {{n}} read",
  // After a search: posts read, new leads, leads seen again.
  "lib.conversationsPresentation.runSummary": "{{read}} read · {{fresh}} new · {{seen}} refreshed",
  "lib.conversationsPresentation.rateLimited": " · X paused us",
  "lib.conversationsPresentation.maxPosts": " · more available",

  // ── lib/schedulerState: how long ago, and the status line's hover text ──
  "lib.schedulerState.ago.unknown": "an unknown time ago",
  // {{n}} is a number of seconds / minutes / hours / days.
  "lib.schedulerState.ago.seconds": "{{n}}s ago",
  "lib.schedulerState.ago.minutes": "{{n}} min ago",
  "lib.schedulerState.ago.hours": "{{n}} h ago",
  "lib.schedulerState.ago.days": "{{n}} d ago",
  // Shown for a post the scheduler paused because it could not tell whether X took it.
  "lib.schedulerState.recoveredDetail": "The publisher never confirmed. Check your X timeline before resuming.",
  // {{id}} is a short post id, {{reason}} a code such as insufficient_balance.
  "lib.schedulerState.stuckPaused": "{{id}} ({{reason}}, Paused)",
  "lib.schedulerState.stuckRetrying": "{{id}} ({{reason}}, Scheduled — retries next run)",
  // {{item}} is one of the two lines above; {{detail}} is why, in the words of whatever refused.
  "lib.schedulerState.stuckWithDetail": "{{item}} — {{detail}}",
  "lib.schedulerState.title.unknown": "Couldn't read scheduler status — your sign-in proof may have lapsed.",
  "lib.schedulerState.title.clickToRetry": "Click to retry.",
  "lib.schedulerState.title.unauthorized": "The scheduler is running, but it's waiting for the operator to approve it before it can post. Nothing goes out until then.",
  // {{ago}} is e.g. "12 min ago".
  "lib.schedulerState.title.cutoff": "A scheduler run started {{ago}} and never finished — it was cut short before it could post. The next run picks the work back up.",
  "lib.schedulerState.title.lastRan": "Scheduler last ran {{ago}}.",
  // {{list}} is the posts that didn't go out, separated by "; ".
  "lib.schedulerState.title.lastRanStuck": "Scheduler last ran {{ago}} · didn't post: {{list}}.",
  "lib.schedulerState.title.clickToRefresh": "Click to refresh.",
  "lib.schedulerState.title.neverRan": "The scheduler hasn't logged a run yet — it checks for due posts about every half hour.",

  // ── lib/schedulerCheck: whose approval the scheduler waits on, and its last look ──
  // {{op}} and {{viewer}} are a profile name or a shortened npub.
  "lib.schedulerCheck.waitingOn": "Waiting on the operator, {{op}}.",
  "lib.schedulerCheck.waitingOnSignedIn": "Waiting on the operator, {{op}} — you're signed in as {{viewer}}.",
  "lib.schedulerCheck.ago.justNow": "just now",
  "lib.schedulerCheck.ago.minutes": "{{n}} min ago",
  "lib.schedulerCheck.ago.hours": "{{n}} h ago",
  // {{ago}} is "just now" or "12 min ago"; {{words}} is one of the findings below.
  "lib.schedulerCheck.lastCheck": "Last check {{ago}}: {{words}}.",
  "lib.schedulerCheck.code.no_reply": "no reply yet",
  "lib.schedulerCheck.code.courier_not_found": "no matching reply on the relay yet",
  "lib.schedulerCheck.code.courier_relay_unreachable": "the relay the request went to did not answer",
  "lib.schedulerCheck.code.courier_nonce_mismatch": "this request was replaced by a newer one, so it can't complete",
  "lib.schedulerCheck.code.courier_no_pending_record": "the service has lost this request, so it can't complete",
  "lib.schedulerCheck.code.courier_token_expired": "this request expired, so it can't complete",
  "lib.schedulerCheck.code.courier_no_pinned_relay": "this request has no relay to read the reply from, so it can't complete",
  "lib.schedulerCheck.code.secure_courier_unavailable": "the service's courier was not ready",

  // ── SchedulerPage ──
  "ui.schedulerPage.title": "Scheduler",
  "ui.schedulerPage.refresh": "Refresh scheduler status",
  "ui.schedulerPage.intro": "A background worker checks for due posts on a schedule and posts them on each owner's behalf. It holds no keys — it renews a short-lived authorization from your npub, the same way you sign in.",
  // When an authorization renews: "now", or "in 3 days" / "in 5 h" / "in 20 min".
  "ui.schedulerPage.until.now": "now",
  "ui.schedulerPage.until.days": "in {{n}} days",
  "ui.schedulerPage.until.hours": "in {{n}} h",
  "ui.schedulerPage.until.minutes": "in {{n}} min",
  // A span of time: "47 min", "5 h", "3 d".
  "ui.schedulerPage.span.minutes": "{{n}} min",
  "ui.schedulerPage.span.hours": "{{n}} h",
  "ui.schedulerPage.span.days": "{{n}} d",
  "ui.schedulerPage.openPost": "Open this post",
  // What happened to one post, in the traffic log.
  "ui.schedulerPage.outcome.posted": "posted",
  "ui.schedulerPage.outcome.held": "held",
  "ui.schedulerPage.outcome.paused": "paused",
  "ui.schedulerPage.outcome.published": "published",
  // A "dynamic block" is a piece of a post filled in when it is sent; on failure the author's own text is used.
  "ui.schedulerPage.fellBack_one": "Posted, but a dynamic block fell back to the author's text:",
  "ui.schedulerPage.fellBack_other": "Posted, but {{count}} dynamic blocks fell back to the author's text:",
  // {{block}} is the block's name, {{reason}} why it failed, {{s}} a number of seconds.
  "ui.schedulerPage.fellBackLine": "block {{block}}: {{reason}}",
  "ui.schedulerPage.fellBackLineBudget": "block {{block}}: {{reason}} (budget {{s}}s)",
  // A "tick" is one scheduled run of the scheduler.
  "ui.schedulerPage.tick": "tick",
  "ui.schedulerPage.tickCutOff": "started, never finished",
  "ui.schedulerPage.tickPosted": "{{n}} posted",
  "ui.schedulerPage.tickResolving": "{{n}} resolving",
  "ui.schedulerPage.tickRecovered": "{{n}} recovered",
  "ui.schedulerPage.tickHandled": "{{n}} handled",
  "ui.schedulerPage.tickNothingDue": "nothing due",
  "ui.schedulerPage.nothingAhead": "nothing scheduled ahead",
  "ui.schedulerPage.ahead": "{{n}} ahead",
  // {{when}} is a span such as "47 min".
  "ui.schedulerPage.nextOf": "next of {{n}} in {{when}}",
  "ui.schedulerPage.skipped": "{{n}} skipped",
  "ui.schedulerPage.buildTitle": "The build that ran this tick",
  // {{when}} is e.g. "in 3 days"; {{span}} e.g. "30 d".
  "ui.schedulerPage.auth.authorized": "Authorized — renews {{when}}",
  "ui.schedulerPage.auth.authorizedGranted": "Authorized — renews {{when}} · granted {{span}}",
  "ui.schedulerPage.auth.dueRenewal": "Authorized but due for renewal — the next tick re-requests",
  "ui.schedulerPage.auth.dueRenewalGranted": "Authorized but due for renewal — the next tick re-requests · granted {{span}}",
  "ui.schedulerPage.auth.pending": "Awaiting your approval (requested {{ago}})",
  "ui.schedulerPage.auth.idle": "Idle — no authorization needed right now",
  "ui.schedulerPage.card.status": "Status",
  "ui.schedulerPage.row.npubAuthorization": "npub authorization",
  "ui.schedulerPage.row.lastTick": "Last tick",
  "ui.schedulerPage.row.runsOn": "Runs on",
  "ui.schedulerPage.row.worker": "Worker",
  "ui.schedulerPage.workerUnreachable": "unreachable right now",
  "ui.schedulerPage.card.configuration": "Configuration",
  "ui.schedulerPage.row.actsFor": "Acts for (operator)",
  "ui.schedulerPage.row.cadence": "Cadence",
  "ui.schedulerPage.row.npubRenewal": "npub renewal",
  // {{pct}} is a percentage number.
  "ui.schedulerPage.npubRenewal": "re-requests this worker's npub authorization once {{pct}}% of the granted lifetime is left — a share, not a fixed number of hours, because you choose that lifetime when you approve (not your X connection)",
  "ui.schedulerPage.row.npubRenudge": "npub re-nudge",
  // {{h}} is a number of hours.
  "ui.schedulerPage.npubRenudge": "resends the npub-approval DM if unanswered for {{h}} h",
  "ui.schedulerPage.row.workerVersion": "Worker version",
  "ui.schedulerPage.row.verifyVenue": "Verify venue",
  "ui.schedulerPage.card.trafficLog": "Traffic log",
  "ui.schedulerPage.loading": "Loading…",
  "ui.schedulerPage.noTicks": "No ticks recorded yet — the scheduler logs a run each time it checks for due posts.",
  "ui.schedulerPage.col.when": "When",
  "ui.schedulerPage.col.event": "Event",
  "ui.schedulerPage.col.detail": "Detail",

  // ── SchedulerPendingCard ──
  "ui.schedulerPendingCard.reissued": "A fresh request is on its way. Approve the newest DM in Pricing Studio — the one whose phrase matches the one above — then check now.",
  // {{error}} is the reason, from the server or the line below.
  "ui.schedulerPendingCard.reissueFailed": "No fresh request was sent: {{error}}",
  "ui.schedulerPendingCard.noAnswer": "the scheduler didn't answer",
  "ui.schedulerPendingCard.stillWaiting": "Still waiting — give the reply a moment to land, then check again.",
  "ui.schedulerPendingCard.headingOperator": "Your scheduler is waiting for your OK",
  "ui.schedulerPendingCard.headingPatron": "Scheduled posts are paused until the operator approves",
  "ui.schedulerPendingCard.phrase": "Confirmation phrase",
  // {{ago}} is e.g. "12 min ago". <b> marks the app's name.
  "ui.schedulerPendingCard.helpOperator": "Requested {{ago}}. Approve in <b>Pricing Studio</b> — reply to the proof DM whose phrase matches this one; a reply to any older DM does not count. If you can't find a DM with this exact phrase, don't approve it — send a fresh request instead.",
  "ui.schedulerPendingCard.helpPatron": "Requested {{ago}}. Nothing goes out until the operator replies — only they can approve it. If you know they already have, check now and the scheduler picks it up instead of waiting for the next run.",
  "ui.schedulerPendingCard.deadOperator": "A fresh request goes out on the next check — or send one now.",
  "ui.schedulerPendingCard.deadPatron": "A fresh request goes out on the next check.",
  "ui.schedulerPendingCard.checking": "Checking…",
  "ui.schedulerPendingCard.checkApproved": "I've approved — check now",
  "ui.schedulerPendingCard.checkNow": "Check now",
  "ui.schedulerPendingCard.reissue": "Send a fresh request",

  // ── SchedulerStatusLine ──
  "ui.schedulerStatusLine.label.loading": "Scheduler…",
  "ui.schedulerStatusLine.label.healthy": "Scheduler healthy",
  "ui.schedulerStatusLine.label.cutoff": "Scheduler cut off",
  "ui.schedulerStatusLine.label.quiet": "Scheduler quiet",
  "ui.schedulerStatusLine.label.stalled": "Scheduler stalled",
  "ui.schedulerStatusLine.label.unauthorized": "Scheduler awaiting approval",
  "ui.schedulerStatusLine.label.unknown": "Scheduler status unknown",
  // Badges. "Resolving", "Scheduled", "Paused" are post statuses with their own Posts filters.
  // {{ids}} are short post ids.
  "ui.schedulerStatusLine.resolvingTitle": "A worker is building the body of {{ids}} right now. Filter Posts by Resolving to see it.",
  "ui.schedulerStatusLine.resolving": "{{n}} Resolving",
  // {{list}} is "id (reason)" entries separated by "; ".
  "ui.schedulerStatusLine.heldTitle": "Held on the last run, still Scheduled and due to retry: {{list}}. Filter Posts by Scheduled — each one carries the same ⚠ marker.",
  "ui.schedulerStatusLine.held": "Retrying {{n}}",
  "ui.schedulerStatusLine.soonTitle_one": "{{count}} post queued ahead, as of the last tick. Filter Posts by Scheduled to see them.",
  "ui.schedulerStatusLine.soonTitle_other": "{{count}} posts queued ahead, as of the last tick. Filter Posts by Scheduled to see them.",
  "ui.schedulerStatusLine.soon": "{{n}} Soon",
  "ui.schedulerStatusLine.pausedTitle": "Stopped until you resume them: {{list}}. Filter Posts by Paused.",
  "ui.schedulerStatusLine.paused": "{{n}} Paused",

  // App.tsx
  "ui.app.welcome": "An AI-assisted content management system for your X posts. Drafts, schedule and snippets live with your key, not a login.",
  "ui.app.postsManager": "Posts Manager",
  // {{version}} is the site's version number, e.g. 3.7.2.
  "ui.app.footerVersion": "eXcalibur Posts Manager v{{version}}",
  "ui.app.footerMonetized": "Monetized with <tollbooth>Tollbooth DPYC™</tollbooth> · Apache-2.0 · Patent Pending (US Prov. 64/045,999)",

  // Nav.tsx
  "ui.calendarPage.title": "Calendar",
  "ui.calendarPage.intro": "When your posts go out, by day, in {{zone}}. A paused post shows the days it would post if you resumed it.",
  "ui.calendarPage.refresh": "Refresh calendar",
  "ui.calendarPage.kind.sent": "Sent",
  "ui.calendarPage.kind.coming": "Coming",
  "ui.calendarPage.kind.paused": "Paused",
  "ui.calendarPage.count.sent_one": "{{count}} sent",
  "ui.calendarPage.count.sent_other": "{{count}} sent",
  "ui.calendarPage.count.coming_one": "{{count}} coming",
  "ui.calendarPage.count.coming_other": "{{count}} coming",
  "ui.calendarPage.count.paused_one": "{{count}} paused",
  "ui.calendarPage.count.paused_other": "{{count}} paused",
  "ui.nav.posts": "Posts",
  "ui.nav.snippets": "Snippets",
  "ui.nav.compose": "Compose",
  "ui.nav.performance": "Performance",
  // Conversations worth replying to.
  "ui.nav.leads": "Leads",
  "ui.nav.calendar": "Calendar",
  "ui.nav.scheduler": "Scheduler",
  "ui.nav.wallet": "Wallet",
  "ui.nav.profileTheme": "Profile & theme",
  "ui.nav.creditBalance": "Credit balance",
  "ui.nav.balanceUnknown": "— sats",
  // {{sats}} is the balance, already formatted.
  "ui.nav.balance": "{{sats}} sats",

  // Hero.tsx
  "ui.hero.postsManager": "Posts Manager",
  "ui.hero.tagline": "A Content Management System for X",
  "ui.hero.headline": "An AI-assisted Content Management System for your X posts.",
  "ui.hero.intro": "Stay in the zone. Let your agentic assistant post thoughts or marketing copy straight to X through <mcp>eXcalibur MCP</mcp> — the monetized MCP for X posting — or route a draft into eXcalibur Posts Manager for editorial fine-tuning first.",
  "ui.hero.more": "Draft in a block editor, refine flagged passages with AI, schedule and repost, and keep a reusable snippet library. Sign in with a Nostr key and pay per use in Bitcoin Lightning — your posts, schedule, and snippets live with your npub, not a login.",
  "ui.hero.editorTitle": "Block editor",
  "ui.hero.editorBody": "X-aware Unicode formatting, dividers, and an emoji picker — what you see is what posts.",
  "ui.hero.refineTitle": "Refine a passage",
  "ui.hero.refineBody": "Flag a region and the server rewrites it. The AI key stays vaulted — it never reaches your browser.",
  "ui.hero.scheduleTitle": "Schedule & reuse",
  "ui.hero.scheduleBody": "Queue posts, repost a sent one, and one-click your favorite snippets into any draft.",
  "ui.hero.poweredBy": "Powered by <tollbooth>Tollbooth DPYC™</tollbooth> — operator-controlled dynamic pricing at the MCP layer.",

  // ProfilePage.tsx
  "ui.profilePage.language": "Language",
  "ui.profilePage.tzHeading": "Display timezone",
  "ui.profilePage.tzIntro": "All times on Posts, Performance, Scheduler, and Wallet use this zone. Storage stays UTC; only display and filter edges convert. Saved on this device.",
  "ui.profilePage.tzLabel": "Zone",
  // {{zone}} is a time zone name, e.g. America/New_York.
  "ui.profilePage.tzAuto": "Auto (browser) — {{zone}}",
  "ui.profilePage.tzResolving": "Currently resolving to {{zone}}.",
  "ui.profilePage.tzUsing": "Using {{zone}}. Historical posts keep the offset that applied when they were sent.",
  "ui.profilePage.themeIntro": "eXcalibur defaults to dark. Your choice is saved on this device.",
  "ui.profilePage.themeDark": "Dark",
  "ui.profilePage.themeLight": "Light",
  "ui.profilePage.themeSystem": "System",
  // Under "Dark": it is the theme eXcalibur starts in.
  "ui.profilePage.themeDefault": "Default",
  // Under "System": follow the device's light/dark setting.
  "ui.profilePage.themeMatchOs": "Match OS",
  "ui.profilePage.buildIntro": "eXcalibur and Tollbooth-DPYC<sup>™</sup> ship as open source under the Apache License 2.0 — anyone can read the code, fork it, run their own operator. The <i>services</i> on top are private commerce: each operator sets their own tolls; patrons pre-fund a Lightning balance and pay per call. The protocol is shared; the businesses on it are not.",

  // ReadinessBadge.tsx (tooltips on the post-state badge)
  "ui.readinessBadge.flipReady": "Mark Ready — the scheduler posts it at its publish time",
  "ui.readinessBadge.flipDraft": "Return to Draft — it won't post until you mark it Ready again",
  // {{label}} is the badge's word (Draft, Ready…); {{action}} is one of the two lines above.
  "ui.readinessBadge.flipAria": "{{label}} — {{action}}",

  // lib/readiness.ts — a post's state as its badge says it
  "lib.readiness.badge.draft": "Draft",
  // A post queued for the scheduler.
  "lib.readiness.badge.scheduled": "Ready",
  // The post's dynamic blocks are being built.
  "lib.readiness.badge.resolving": "Resolving",
  // Built, waiting for its time.
  "lib.readiness.badge.resolved": "Resolved",
  "lib.readiness.badge.sending": "Sending",
  "lib.readiness.badge.paused": "Paused",
  "lib.readiness.badge.sent": "Sent",
  "lib.readiness.badge.archived": "Archived",
  "lib.readiness.archiveLive": "This post is still scheduled to go out. Archive it anyway?",
  "lib.readiness.archive": "Archive this post?",

  // lib/fundingStatus.ts — eXcalibur's rows on the account-health panels
  "lib.fundingStatus.xAccount": "X account",
  // {{reason}} is a short code from the server, e.g. warming_up.
  "lib.fundingStatus.unverifiedReason": "Couldn't verify connection ({{reason}}).",
  "lib.fundingStatus.unverified": "Couldn't verify connection — service may be waking up.",
  "lib.fundingStatus.notConnected": "Not connected — authorize X before posting.",
  "lib.fundingStatus.expired": "Access token expired — reconnect to keep posting.",
  // {{duration}} is a span of time, e.g. "2 hours".
  "lib.fundingStatus.renewsIn": "Connected — access renews in about {{duration}}.",
  "lib.fundingStatus.connected": "Connected.",
  // The service that routes requests to an AI model.
  "lib.fundingStatus.modelRouter": "Model router",
  // llm_api_key is the credential's name; keep it as is.
  "lib.fundingStatus.llmConfigured": "llm_api_key is configured. Credit balance lives on the provider dashboard — nothing here can read it yet.",
  "lib.fundingStatus.llmMissing": "llm_api_key not delivered — refine and dynamic blocks will fail until the key is couriered (posting still works).",
  "lib.fundingStatus.llmUnknown": "Couldn't determine llm_api_key state from onboarding.",

  // lib/xConnectPresentation.ts — the X account card; {{handle}} is an X handle like @name
  "lib.xConnectPresentation.linkedExpiredAs": "Linked · {{handle}} — token expired",
  "lib.xConnectPresentation.linkedExpired": "Linked — token expired",
  "lib.xConnectPresentation.connectedAs": "Connected · {{handle}}",
  "lib.xConnectPresentation.connected": "Connected",
  "lib.xConnectPresentation.canPostAs": "eXcalibur can post to your X account as {{handle}}.",
  "lib.xConnectPresentation.canPost": "eXcalibur can post to your X account.",
  // {{duration}} is one of the short spans below.
  "lib.xConnectPresentation.renews": "Access renews in about {{duration}}.",
  // Short spans of time: days, hours, minutes.
  "lib.xConnectPresentation.days": "{{n}}d",
  "lib.xConnectPresentation.hours": "{{n}}h",
  "lib.xConnectPresentation.minutes": "{{n}}m",

  // FundingStatusPanels.tsx — account health on the Profile page
  "ui.fundingStatusPanels.stateOk": "ok",
  "ui.fundingStatusPanels.stateWarning": "warning",
  "ui.fundingStatusPanels.stateBlocked": "blocked",
  // {{checked}} is when the row was read, e.g. "2 min ago".
  "ui.fundingStatusPanels.checked": "checked {{checked}}",
  "ui.fundingStatusPanels.patronIntro": "Connection, sign-in proof, and credit expiry — checked live, never sticky.",
  "ui.fundingStatusPanels.operatorIntro": "Upstream things only you can fix — model router, credentials, Authority tax balance, Neon, durable jobs. No prices.",

  // XConnectPanel.tsx — linking the patron's X account
  "ui.xConnectPanel.title": "X account",
  "ui.xConnectPanel.startFailed": "Couldn't start the X authorization.",
  // Names the button ui.xConnectPanel.openAuthorization.
  "ui.xConnectPanel.popupBlocked": "Popup blocked — use the “Open X authorization” button below.",
  "ui.xConnectPanel.connectedNote": "X account connected.",
  "ui.xConnectPanel.checkFailed": "Couldn't check authorization status.",
  "ui.xConnectPanel.stillWaiting": "Still waiting — finish authorizing in the X tab, then check again.",
  "ui.xConnectPanel.checking": "Checking connection…",
  "ui.xConnectPanel.indeterminate": "Couldn't read your X connection status — the service may be waking up. This doesn't mean you're disconnected; if you connected before, you still are.",
  "ui.xConnectPanel.checkAgain": "Check again",
  "ui.xConnectPanel.setUpTitle": "Only if you've never linked an X account",
  "ui.xConnectPanel.setUp": "Set up X",
  "ui.xConnectPanel.disconnected": "Connect your X account so eXcalibur can post on your behalf. You'll authorize on X in a new tab; the callback returns through the Tollbooth OAuth2 collector — eXcalibur never sees your X password.",
  "ui.xConnectPanel.connect": "Connect X",
  "ui.xConnectPanel.authorizing": "Authorize eXcalibur on X, then come back and verify. If the popup didn't open, use the button below — it opens X in a new tab.",
  "ui.xConnectPanel.openAuthorization": "Open X authorization",
  "ui.xConnectPanel.verify": "I've authorized — verify",
  "ui.xConnectPanel.cancel": "Cancel",
  "ui.xConnectPanel.reconnectToPost": "Reconnect to keep posting",
  "ui.xConnectPanel.reconnect": "Reconnect",

  // lib/quotes.ts — quotations shown while a page loads; the author's name follows each, untranslated
  // David Ogilvy
  "lib.quotes.q1": "The consumer isn't a moron; she is your wife.",
  // David Ogilvy
  "lib.quotes.q2": "On the average, five times as many people read the headline as read the body copy.",
  // David Ogilvy
  "lib.quotes.q3": "Tell the truth, but make the truth fascinating.",
  // David Ogilvy
  "lib.quotes.q4": "The more informative your advertising, the more persuasive it will be.",
  // Bill Bernbach
  "lib.quotes.q5": "The most powerful element in advertising is the truth.",
  // Bill Bernbach
  "lib.quotes.q6": "In advertising, not to be different is virtually suicidal.",
  // John E. Kennedy
  "lib.quotes.q7": "Advertising is salesmanship in print.",
  // Claude C. Hopkins
  "lib.quotes.q8": "The time to stop talking is when the other person nods his head affirmatively but says nothing.",
  // William Howard Taft
  "lib.quotes.q9": "Don't write so that you can be understood, write so that you can't be misunderstood.",
  // John Caples
  "lib.quotes.q10": "When you have written your headline, you have spent eighty cents out of your dollar.",
  // Leo Burnett
  "lib.quotes.q11": "Make it simple. Make it memorable. Make it inviting to look at.",
  // Shirley Polykoff
  "lib.quotes.q12": "Copy is a direct conversation with the consumer.",
  // George Gribbin
  "lib.quotes.q13": "A copywriter should have an understanding of people, an insight into them, a sympathy toward them.",
  // David Ogilvy
  "lib.quotes.q14": "The headline is the ticket on the meat. Use it to flag down readers who are prospects.",
  // William Strunk Jr.
  "lib.quotes.q15": "Omit needless words.",
  // Mark Twain
  "lib.quotes.q16": "I didn't have time to write a short letter, so I wrote a long one instead.",
  // Nathaniel Hawthorne
  "lib.quotes.q17": "Easy reading is damn hard writing.",
  // Albert Einstein
  "lib.quotes.q18": "If you can't explain it simply, you don't understand it well enough.",

  // TweetPreviewModal.tsx
  "ui.tweetPreviewModal.title": "Posted to X",
  "ui.tweetPreviewModal.close": "Close",
  "ui.tweetPreviewModal.view": "View on X",
  "ui.tweetPreviewModal.open": "Open on X",

  // lib/mcp.ts — fallbacks when the server sends no message of its own
  "lib.mcp.resolveFailed": "The resolve failed — your fare was refunded.",
  "lib.mcp.resolveExpired": "The resolve claim expired — try again.",
  "lib.mcp.resolveTimedOut": "Timed out waiting for the dynamic block to resolve.",
  "lib.mcp.purgeFailed": "Purge failed.",
};

/** A key as written in the catalog, plural suffix and all. */
export type EnglishKey = keyof typeof en;
type StripPlural<K> = K extends `${infer Base}_${"zero" | "one" | "two" | "few" | "many" | "other"}` ? Base : K;
/** A key as code asks for it: `x` stands for `x_one` / `x_other`, read with `{ count }`. */
export type MessageKey = StripPlural<EnglishKey>;
export type Messages = Record<EnglishKey, string>;
type PluralBase = EnglishKey extends infer K ? (K extends `${infer Base}_other` ? Base : never) : never;
/** One language's words: English's keys, plus the plural forms that language has beyond English's two. */
export type Translation = Partial<Messages> & Partial<Record<`${PluralBase}_${"zero" | "two" | "few" | "many"}`, string>>;

export default en as Messages;
