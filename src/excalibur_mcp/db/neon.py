"""eXcalibur domain persistence on top of the wheel's NeonVault.

Mechanism modeled on ``optionality-mcp/db/neon.py`` (the canonical DPYC
pattern), but the **schema is eXcalibur's own** — a single purpose-built
``posts`` table (the posts-persistence contract), not a port of any other
operator's tables.

- The wheel's ``vault._t(...)`` schema-prefixes every table into the
  operator's own Postgres role/schema, so a bare ``posts`` cannot collide
  across operators — no extra name prefix is needed.
- ``_ensure_domain_schema(vault)`` runs idempotent ``CREATE TABLE IF NOT
  EXISTS`` on first vault use. This matches every DPYC operator — there is no
  separate migration runner. The canonical DDL is also kept (documentation
  only) at ``db/migrations/0001_initial.sql`` in lock-step with this file.
- ``execute()``/``fetch()``/``fetchrow()`` are thin wrappers that auto-rewrite
  bare domain table names to their schema-qualified form before dispatching to
  the vault.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

_vault: Any = None
_schema_done: bool = False

# Bare domain table names. The wheel's vault._t() schema-prefixes each into the
# operator's own role/schema, so the logical name stays the contract's ``posts``.
_DOMAIN_TABLES: tuple[str, ...] = ("posts",)


async def _get_vault() -> Any:
    """Obtain the operator's NeonVault, lazy-initializing schema on first use."""
    global _vault, _schema_done
    if _vault is None:
        # Imported lazily to avoid a circular import at module load
        # (server imports the runtime; the runtime owns the vault).
        from excalibur_mcp.server import runtime

        _vault = await runtime.vault()
        logger.info(
            "Vault obtained, schema_prefix=%s",
            getattr(_vault, "_schema_prefix", ""),
        )
    if not _schema_done:
        _schema_done = True
        try:
            await _ensure_domain_schema(_vault)
            logger.info("eXcalibur domain schema ensured")
        except Exception as e:
            logger.error("Domain schema init failed: %s", e)
            _schema_done = False
    return _vault


def _qualify(query: str) -> str:
    """Rewrite bare domain table names with their schema-qualified form."""
    if not _vault:
        return query
    t = _vault._t
    q = query
    for bare in _DOMAIN_TABLES:
        q = re.sub(rf"(?<![.\w]){bare}(?=[\s(,;)]|$)", t(bare), q)
    return q


async def _ensure_domain_schema(vault: Any) -> None:
    """Create eXcalibur's ``posts`` table idempotently (purpose-built)."""
    t = vault._t
    stmts = [
        f"CREATE TABLE IF NOT EXISTS {t('posts')} ("
        "id UUID PRIMARY KEY DEFAULT gen_random_uuid(), "
        "npub TEXT NOT NULL, "
        "status TEXT NOT NULL DEFAULT 'draft', "  # draft|scheduled|sent|archived
        "doc JSONB NOT NULL, "
        "text_cache TEXT, "
        "publish_at TIMESTAMPTZ, "
        "recurrence JSONB, "
        "cease_at TIMESTAMPTZ, "
        "last_sent_at TIMESTAMPTZ, "
        "client_req_id TEXT, "
        "created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), "
        "updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())",

        f"CREATE INDEX IF NOT EXISTS posts_owner_idx ON {t('posts')} (npub, status)",

        f"CREATE INDEX IF NOT EXISTS posts_due_idx ON {t('posts')} (status, publish_at) "
        "WHERE status = 'scheduled'",
    ]
    for stmt in stmts:
        try:
            await vault._execute(stmt)
        except Exception as e:
            logger.error("Schema DDL failed: %s\nSQL: %s", e, stmt[:200])


async def execute(query: str, *args: Any) -> dict[str, Any]:
    v = await _get_vault()
    q = _qualify(query)
    logger.debug("execute: %s | args=%s", q[:150], list(args)[:3])
    return await v._execute(q, list(args))


async def fetch(query: str, *args: Any) -> list[dict[str, Any]]:
    result = await execute(query, *args)
    return result.get("rows", [])


async def fetchrow(query: str, *args: Any) -> dict[str, Any] | None:
    rows = await fetch(query, *args)
    return rows[0] if rows else None
