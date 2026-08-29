"""Tests for the resolve_dynamic_block background job runner.

The slow resolve runs as a wheel async job; the runner loads the operator's
vaulted Anthropic key (never stored in the job params) and calls the shared
resolve_block core, raising on failure so the wheel refunds the start fare.
"""

from unittest.mock import AsyncMock, patch

import pytest

from excalibur_mcp import server


@pytest.mark.asyncio
async def test_runner_loads_key_and_resolves():
    with patch.object(server.runtime, "_load_vault_creds",
                      AsyncMock(return_value=({"llm_api_key": "k"}, ""))), \
         patch("excalibur_mcp.resolve.resolve_block", AsyncMock(return_value="the copy")) as rb:
        out = await server._resolve_dynamic_runner(
            npub="np", prompt="p", context="c", voice="v",
            bans=["delve"], allowed_domains=["a.com"], max_fetches=9,
        )
    assert out == {"text": "the copy"}
    kw = rb.await_args.kwargs
    assert kw["api_key"] == "k"          # key loaded server-side, not from params
    assert kw["prompt"] == "p"
    assert kw["allowed_domains"] == ["a.com"]
    assert kw["max_fetches"] == 9


@pytest.mark.asyncio
async def test_runner_raises_without_key():
    # No key → raise, so the wheel marks the job errored and refunds the fare.
    with patch.object(server.runtime, "_load_vault_creds", AsyncMock(return_value=({}, ""))):
        with pytest.raises(RuntimeError):
            await server._resolve_dynamic_runner(prompt="p")


@pytest.mark.asyncio
async def test_runner_distinguishes_unreadable_vault_from_missing_key():
    """This runner is what Modal executes, and the container rediscovers its
    vault over Nostr on every cold start — so an unreadable vault is its most
    likely failure, not a missing key. It must say which. Observed live
    2026-08-29: every bootstrap relay was unreachable and the scheduler
    reported `no_operator_llm_key` for a key that was vaulted all along.
    """
    with patch.object(server.runtime, "_load_vault_creds",
                      AsyncMock(return_value=({}, "vault_bootstrapping"))):
        with pytest.raises(RuntimeError) as exc:
            await server._resolve_dynamic_runner(prompt="p")

    assert "vault_bootstrapping" in str(exc.value)
    assert "not configured" not in str(exc.value), (
        "an unreadable vault must never be reported as an unconfigured operator"
    )


def test_runner_is_registered():
    # Registered at import so a fresh container can resume an orphaned job.
    assert "resolve_dynamic_block" in server.runtime._job_runners


# --- failures become curated, frontend-facing situations (not raw errors) -----

import httpx  # noqa: E402
from tollbooth import AsyncJobSituation  # noqa: E402


def _provider_resp(status, message):
    req = httpx.Request("POST", "https://openrouter.ai/api/v1/messages")
    return httpx.Response(status, json={"error": {"message": message}}, request=req)


@pytest.mark.asyncio
async def test_runner_maps_billing_400_to_unfunded_situation():
    resp = _provider_resp(400, "Your credit balance is too low to access the Anthropic API.")
    err = httpx.HTTPStatusError("400", request=resp.request, response=resp)
    with patch.object(server.runtime, "_load_vault_creds",
                      AsyncMock(return_value=({"llm_api_key": "k"}, ""))), \
         patch("excalibur_mcp.resolve.resolve_block", AsyncMock(side_effect=err)):
        with pytest.raises(AsyncJobSituation) as ei:
            await server._resolve_dynamic_runner(prompt="p")
    assert ei.value.error_code == "operator_llm_unfunded"
    assert ei.value.transient is False
    # the raw provider wording does not become the patron message
    assert "credit balance" not in ei.value.message.lower()


@pytest.mark.asyncio
async def test_runner_maps_router_402_to_unfunded_situation():
    """The regression this whole route exists to prevent.

    A model router reports an empty account as a 402 reading "Insufficient
    credits" — sharing no wording with the lab's 400. Matching only the lab, as
    this did before the wheel took over the reading, curated an exhausted account
    as a generic transient blip: the operator was never told to feed it, and
    patrons were told to retry forever.
    """
    resp = _provider_resp(402, "Insufficient credits. Add more using https://openrouter.ai/credits")
    err = httpx.HTTPStatusError("402", request=resp.request, response=resp)
    with patch.object(server.runtime, "_load_vault_creds",
                      AsyncMock(return_value=({"llm_api_key": "k"}, ""))), \
         patch("excalibur_mcp.resolve.resolve_block", AsyncMock(side_effect=err)):
        with pytest.raises(AsyncJobSituation) as ei:
            await server._resolve_dynamic_runner(prompt="p")
    assert ei.value.error_code == "operator_llm_unfunded"
    assert ei.value.transient is False


# ---------------------------------------------------------------------------
# Upstream classification
# ---------------------------------------------------------------------------
#
# These asserted through `_resolve_shape_result`, the DETACHED path's mirror of
# the runner's error handling — deleted with the closure apparatus in
# tollbooth-dpyc 0.82.0. The classification itself never lived there: it is
# `_resolve_failure_situation`, which the runner calls directly. So the tests
# now assert the classifier, and cover the same statuses without a second code
# path to keep in step.


def test_router_402_is_unfunded_and_permanent():
    sit = server._resolve_failure_situation(402, "Insufficient credits")
    assert sit.error_code == "operator_llm_unfunded" and sit.transient is False


def test_retired_model_slug_is_permanent():
    """A marketplace renaming a model under a running deployment. Retrying can
    never clear it, so the patron must not be told to keep trying."""
    sit = server._resolve_failure_situation(400, "x-ai/grok-9 is not a valid model ID")
    assert sit.error_code == "operator_llm_model_unknown" and sit.transient is False


def test_billing_400_is_unfunded_not_a_bad_request():
    sit = server._resolve_failure_situation(400, "Insufficient credits")
    assert sit.error_code == "operator_llm_unfunded" and sit.transient is False


def test_429_is_transient_so_the_patron_is_told_to_retry():
    sit = server._resolve_failure_situation(429, "overloaded")
    assert sit.error_code == "upstream_rate_limited" and sit.transient is True


def test_an_empty_2xx_is_its_own_situation():
    assert server._empty_result_situation().error_code == "dynamic_block_empty"
