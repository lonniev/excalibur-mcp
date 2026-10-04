-- eXcalibur MCP — canonical schema (documentation only).
--
-- This file is the authoritative DDL reference for eXcalibur's single domain
-- table. It is NOT executed by any migration runner. Schema is created lazily
-- at runtime via db/neon.py::_ensure_domain_schema, which uses the wheel's
-- NeonVault.vault._t() schema-prefix helper to keep each operator's tables in
-- its own Postgres role/schema.
--
-- Keep this file in lock-step with db/neon.py::_ensure_domain_schema.

-- Stored posts: the editable Doc (blocks + flags + voice + bans + schedule)
-- lives in `doc` as the single source of truth; `text_cache` is the FE-composed
-- text (blocks joined "\n\n") so the scheduler and list excerpts never have to
-- deserialize `doc`.
--
-- `doc` is AUTHORED state: it changes only when a human edits the post. The
-- publishing path must never write it. What a given firing built goes in
-- `render` — see the column comment below.
CREATE TABLE IF NOT EXISTS posts (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    npub          TEXT        NOT NULL,        -- owner; access-control key
    status        TEXT        NOT NULL DEFAULT 'draft',  -- draft|scheduled|sent|archived
    title         TEXT,                        -- optional human label; falls back to first body line
    doc           JSONB       NOT NULL,        -- authored Doc (source of truth; human edits only)
    render        JSONB,                       -- THIS firing's resolved doc; cleared each recurrence
    x_call_at     TIMESTAMPTZ,                 -- a request MAY have reached X; absence ≠ "nothing sent"
    text_cache    TEXT,                        -- composed text (scheduler + excerpts)
    publish_at    TIMESTAMPTZ,                 -- first/next intended publish
    recurrence    JSONB,                       -- {"freq": "...", "interval": n} | null
    cease_at      TIMESTAMPTZ,                 -- stop republishing after; null = open
    last_sent_at  TIMESTAMPTZ,                 -- set by scheduler on each post_tweet
    tweet_url     TEXT,                        -- the live X URL of the last successful fire
    last_attempt_at     TIMESTAMPTZ,           -- when a fire was last tried
    last_attempt_reason TEXT,                  -- why it didn't post (machine code)
    last_attempt_detail TEXT,                  -- ...in the words of whatever refused
    template_id   UUID,                        -- sent occurrence → its recurring template's id
    client_req_id TEXT,                        -- idempotency: create dedup + last-applied update id
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS posts_owner_idx ON posts (npub, status);

CREATE INDEX IF NOT EXISTS posts_due_idx ON posts (status, publish_at)
    WHERE status = 'scheduled';

-- Reverse link: list every sent occurrence fired from a recurring template.
CREATE INDEX IF NOT EXISTS posts_template_idx ON posts (npub, template_id)
    WHERE template_id IS NOT NULL;

-- Append-only X post metrics (non_public / organic). Available only ~30 days
-- after authorship under user-context OAuth — the harvest store is the durable
-- time-series. Never upsert.
CREATE TABLE IF NOT EXISTS post_metrics_snapshot (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    post_id              UUID NOT NULL,
    tweet_id             TEXT NOT NULL,
    npub                 TEXT NOT NULL,
    captured_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    t_offset             INT NOT NULL DEFAULT 0,
    impressions          INT,
    likes                INT,
    replies              INT,
    reposts              INT,
    quotes               INT,
    bookmarks            INT,
    url_link_clicks      INT,
    user_profile_clicks  INT,
    link_placement       TEXT,
    snippet_ids          JSONB NOT NULL DEFAULT '[]',
    voice_id             TEXT,
    cadence_key          TEXT,
    raw                  JSONB
);

CREATE INDEX IF NOT EXISTS post_metrics_owner_post_idx
    ON post_metrics_snapshot (npub, post_id, captured_at);

CREATE INDEX IF NOT EXISTS post_metrics_tweet_idx
    ON post_metrics_snapshot (tweet_id, captured_at);

-- Decaying-cadence harvest queue with dead-letter (status='dead').
CREATE TABLE IF NOT EXISTS metrics_harvest_job (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    post_id         UUID NOT NULL,
    tweet_id        TEXT NOT NULL,
    npub            TEXT NOT NULL,
    cadence_key     TEXT NOT NULL,
    due_at          TIMESTAMPTZ NOT NULL,
    sent_at         TIMESTAMPTZ NOT NULL,
    link_placement  TEXT,
    snippet_ids     JSONB NOT NULL DEFAULT '[]',
    voice_id        TEXT,
    status          TEXT NOT NULL DEFAULT 'pending',
    attempts        INT NOT NULL DEFAULT 0,
    last_attempt_at TIMESTAMPTZ,
    last_error      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS metrics_harvest_post_cadence_uniq
    ON metrics_harvest_job (post_id, cadence_key);

CREATE INDEX IF NOT EXISTS metrics_harvest_due_idx
    ON metrics_harvest_job (due_at)
    WHERE status IN ('pending', 'harvesting');

-- Conversation leads: a patron's saved X search selectors (no domain vocabulary
-- lives server-side) and the scored questioners each run found.
CREATE TABLE IF NOT EXISTS conversation_queries (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    npub                TEXT NOT NULL,
    name                TEXT NOT NULL,
    query               TEXT NOT NULL,
    weights             JSONB NOT NULL DEFAULT '{}',
    safe_defaults       BOOLEAN NOT NULL DEFAULT TRUE,
    since_id            TEXT,
    last_run_at         TIMESTAMPTZ,
    last_run_posts_read INT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS conversation_queries_owner_idx
    ON conversation_queries (npub, updated_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS conversation_queries_name_uniq
    ON conversation_queries (npub, lower(name));

-- One row per (patron, X conversation). `status` is the patron's and a re-run
-- never touches it.
CREATE TABLE IF NOT EXISTS conversations (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    npub             TEXT NOT NULL,
    query_id         UUID,
    query_text       TEXT NOT NULL,
    conversation_id  TEXT NOT NULL,
    tweet_id         TEXT NOT NULL,
    author_id        TEXT NOT NULL,
    author_username  TEXT NOT NULL,
    author_followers INT,
    author_location  TEXT,
    text             TEXT NOT NULL,
    posted_at        TIMESTAMPTZ,
    reply_count      INT NOT NULL DEFAULT 0,
    like_count       INT NOT NULL DEFAULT 0,
    is_reply         BOOLEAN NOT NULL DEFAULT FALSE,
    has_media        BOOLEAN NOT NULL DEFAULT FALSE,
    score            SMALLINT NOT NULL DEFAULT 0,
    signals          JSONB NOT NULL DEFAULT '[]',
    status           TEXT NOT NULL DEFAULT 'new',
    found_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status_at        TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS conversations_owner_conv_uniq
    ON conversations (npub, conversation_id);

CREATE INDEX IF NOT EXISTS conversations_owner_score_idx
    ON conversations (npub, status, score DESC);

CREATE INDEX IF NOT EXISTS conversations_owner_query_idx
    ON conversations (npub, query_id);
