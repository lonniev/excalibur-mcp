
eXcalibur Posts Manager is a single-page web app (the CMS) backed by eXcalibur
MCP, a Model Context Protocol server. Humans use the web UI; AI agents can call
the same MCP tools directly. The operator holds the X API credentials in an
encrypted vault; patrons pay per published post rather than supplying their own
keys.

## What is on this site

- **Composer** — a block editor for X posts. Each block is a line/paragraph
  you can reorder; X has no rich text, so "bold/italic/monospace" render as
  Unicode Mathematical Alphanumeric Symbols, dividers as box-drawing rules,
  and an emoji/symbol picker inserts glyphs at the cursor. What you see is
  what posts.
- **Refine** — flag a region of a draft and the server rewrites it against
  your voice profile and banned constructions. The operator's model-router
  key stays vaulted and never reaches the browser; the AI cost is metered as
  a Lightning fare.
- **Posts** — drafts, scheduled, sent, and archived. Repost a sent post in
  one click.
- **Snippet library** — save reusable openings, footers, and CTAs under your
  npub (Neon-backed, follows you across devices); star favorites to get
  one-click chiclets in the editor.
- **Wallet** — pre-fund and check your satoshi balance; preview any tool's
  price before committing.
- **Profile** — display name, avatar, and Nostr relays stored in your Nostr
  kind-0 metadata; theme selection (dark by default); build, license, patent,
  and version transparency.

## Tools

- Posting: `excalibur_post_tweet`, `excalibur_post_tweet_image`.
- Stored posts: `excalibur_create_post`, `excalibur_get_post`,
  `excalibur_list_posts`, `excalibur_update_post`, `excalibur_delete_post`.
- Snippet library (free, proof-gated, owner-scoped): `excalibur_list_snippets`,
  `excalibur_save_snippet`, `excalibur_delete_snippet`.
- Server-side AI refine (metered): `excalibur_refine_post_region`.
