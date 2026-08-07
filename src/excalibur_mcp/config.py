"""eXcalibur-mcp settings loaded from environment variables.

With nsec-only bootstrap, Settings contains only the operator's Nostr
identity and tuning parameters.  All secrets (BTCPay, X/Twitter API keys)
are delivered via Secure Courier credential templates.
"""

from __future__ import annotations

import math
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """eXcalibur MCP server settings.

    Only one env var is required to boot: TOLLBOOTH_NOSTR_OPERATOR_NSEC.
    Everything else has sensible defaults or is delivered via Secure Courier.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Nostr identity (one env var to boot) ─────────────────────────
    tollbooth_nostr_operator_nsec: str | None = None
    tollbooth_nostr_relays: str | None = None

    # ── Tuning (defaults are fine) ───────────────────────────────────
    seed_balance_sats: int = 0
    dpyc_registry_cache_ttl_seconds: int = 300

    # Public URL of the scheduled-post cron Worker (scheduler-worker). The
    # operator-gated `scheduler_pending` tool reads the Worker's owner-private
    # pending state from here, authenticating AS the operator (no shared secret).
    scheduler_worker_url: str = "https://excalibur-scheduler.lonniev.workers.dev"

    # ── Constraint Engine (opt-in) ───────────────────────────────────
    constraints_enabled: bool = False
    constraints_config: str | None = None

    # ── Resolve budget rings ─────────────────────────────────────────
    #
    # Building a post's body runs as NESTED RINGS. One block's LLM budget sits
    # inside a single job attempt, which sits inside the claim lease, which sits
    # inside the detached runner's own timeout.
    #
    #     block budget  <  job attempt  <  claim lease  <  runner timeout
    #
    # Invert any adjacent pair and the failure is specific. A lease shorter than
    # the attempt it guards declares a live resolve orphaned and hands it to a
    # second worker. A runner timeout inside the lease kills a job the scheduler
    # still believes it owns, so nothing is retried until the lease lapses.
    #
    # These were once four independent literals in three files (plus two more
    # hand-copied into the frontend), each defended by a comment quoting the
    # others. Raising one meant finding all six. So only the INNERMOST is
    # authored here; the rest are computed from it, and `gt=1.0` on the safety
    # factor makes an inversion unrepresentable rather than merely tested for.
    #
    # Change `resolve_block_budget_max_s` and every ring follows.
    resolve_block_budget_max_s: int = Field(default=1800, ge=60)
    resolve_ring_safety: float = Field(default=1.15, gt=1.0)

    # Mirrors the crontab in scheduler-worker/wrangler.toml. Python cannot read a
    # Cloudflare trigger, so this is the one duplicated number left; it feeds the
    # resolve lead, which is meaningless if it is shorter than the gap between ticks.
    scheduler_cadence_s: int = Field(default=30 * 60, ge=60)

    @property
    def resolve_job_attempt_s(self) -> int:
        """Ceiling on ONE resolve attempt: the largest block, plus room to persist it."""
        return math.ceil(self.resolve_block_budget_max_s * self.resolve_ring_safety)

    @property
    def resolve_lease_s(self) -> int:
        """How long a claimed resolve is safe from another tick. Outlasts the attempt."""
        return math.ceil(self.resolve_job_attempt_s * self.resolve_ring_safety)

    @property
    def resolve_runner_timeout_s(self) -> int:
        """The detached runner's own ceiling — outermost, so the runner is never what
        kills work the scheduler still believes is in flight."""
        return math.ceil(self.resolve_lease_s * self.resolve_ring_safety)

    @property
    def resolve_lead_s(self) -> int:
        """How far ahead of ``publish_at`` to start building a body.

        One tick, or one full-budget block, whichever is longer. Leading by less than a
        tick means no tick is positioned to pick the post up in time; leading by less
        than the block's own budget guarantees the post is late by the difference.
        """
        return max(self.scheduler_cadence_s, self.resolve_block_budget_max_s)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings, read from the environment once.

    Lives here rather than in ``server.py`` so the scheduler, the persistence layer and
    ``modal_app.py`` can read the budget rings without importing the server (which
    imports them, and would close the cycle).
    """
    return Settings()
