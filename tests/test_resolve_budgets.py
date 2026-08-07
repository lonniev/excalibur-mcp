"""The resolve budget rings must nest, at every ceiling an operator might choose.

Five durations used to be authored independently in three Python files and two
frontend modules, each comment quoting the others' values. Raising one meant finding
all five, and getting it wrong is not cosmetic:

* a **lease inside the job attempt** declares a still-running resolve orphaned and
  hands it to a second worker — two workers, one post, two fares;
* a **runner timeout inside the lease** kills work the scheduler still believes it
  owns, so nothing retries until the lease lapses;
* a **lead shorter than a full-budget block** guarantees the post is late by the
  difference, every time.

So the rings are computed from one authored number. These tests pin the *ordering*,
never the values — a test asserting `lease == 2381` would have to be edited by the same
person making the same mistake it exists to catch.
"""

from __future__ import annotations

import pytest

from excalibur_mcp.config import Settings

# Deliberately spans the old hardcoded ceiling (900), the new default (1800) and well
# past it. A derivation can be wrong in a way that happens to hold at one value —
# `job = block + 60` nests fine at 900 and inverts nowhere, but stops leaving room as
# the block grows. Several ceilings catch that; one does not.
CEILINGS = [60, 300, 900, 1800, 3600, 86_400]


@pytest.mark.parametrize("ceiling", CEILINGS)
def test_rings_strictly_nest(ceiling: int):
    """block budget < job attempt < claim lease < runner timeout, with no ties.

    Strict, not `<=`: equal bounds race. A lease that expires exactly when the attempt
    ends leaves the reclaim and the completion to be ordered by chance.
    """
    s = Settings(resolve_block_budget_max_s=ceiling)
    assert s.resolve_block_budget_max_s < s.resolve_job_attempt_s
    assert s.resolve_job_attempt_s < s.resolve_lease_s
    assert s.resolve_lease_s < s.resolve_runner_timeout_s


@pytest.mark.parametrize("ceiling", CEILINGS)
def test_lead_covers_a_full_budget_block_and_a_whole_tick(ceiling: int):
    """Starting late is the one failure the rings cannot repair after the fact."""
    s = Settings(resolve_block_budget_max_s=ceiling)
    assert s.resolve_lead_s >= s.resolve_block_budget_max_s
    assert s.resolve_lead_s >= s.scheduler_cadence_s


def test_one_number_moves_every_ring():
    """The whole point of the refactor: retune the ceiling, touch nothing else."""
    small, large = Settings(resolve_block_budget_max_s=900), Settings(
        resolve_block_budget_max_s=3600)
    assert large.resolve_job_attempt_s > small.resolve_job_attempt_s
    assert large.resolve_lease_s > small.resolve_lease_s
    assert large.resolve_runner_timeout_s > small.resolve_runner_timeout_s


def test_an_inverting_safety_factor_is_unrepresentable():
    """The invariant is enforced by the type, so it cannot be violated at all rather
    than merely being detected here. A factor of 1.0 makes every ring equal; below it
    they invert — both are rejected at construction."""
    for bad in (1.0, 0.9, 0.0, -2.0):
        with pytest.raises(ValueError):
            Settings(resolve_ring_safety=bad)


def test_a_sub_minute_ceiling_is_rejected():
    """No LLM call with web lookups completes in seconds, so a tiny ceiling is a
    typo. Refusing it at construction beats every block silently falling back."""
    with pytest.raises(ValueError):
        Settings(resolve_block_budget_max_s=5)


def test_scheduler_and_persistence_read_the_derived_rings():
    """The modules must consume the rings, not re-author them. Without this the
    settings could be perfect while `scheduler.py` kept its own literal."""
    from excalibur_mcp import scheduler
    from excalibur_mcp.config import get_settings
    from excalibur_mcp.db import posts as posts_db

    s = get_settings()
    assert scheduler.RESOLVE_MAX_RUNTIME_S == s.resolve_job_attempt_s
    assert scheduler.RESOLVE_LEAD_SECONDS == s.resolve_lead_s
    assert str(s.resolve_lease_s) in posts_db._RESOLVE_LEASE
