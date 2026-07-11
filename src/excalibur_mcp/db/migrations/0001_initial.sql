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
CREATE TABLE IF NOT EXISTS posts (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    npub          TEXT        NOT NULL,        -- owner; access-control key
    status        TEXT        NOT NULL DEFAULT 'draft',  -- draft|scheduled|sent|archived
    title         TEXT,                        -- optional human label; falls back to first body line
    doc           JSONB       NOT NULL,        -- editable Doc (source of truth)
    text_cache    TEXT,                        -- composed text (scheduler + excerpts)
    publish_at    TIMESTAMPTZ,                 -- first/next intended publish
    recurrence    JSONB,                       -- {"freq": "...", "interval": n} | null
    cease_at      TIMESTAMPTZ,                 -- stop republishing after; null = open
    last_sent_at  TIMESTAMPTZ,                 -- set by scheduler on each post_tweet
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
