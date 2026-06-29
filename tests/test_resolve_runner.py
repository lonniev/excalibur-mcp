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
    with patch.object(server.runtime, "load_credentials",
                      AsyncMock(return_value={"anthropic_api_key": "k"})), \
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
    with patch.object(server.runtime, "load_credentials", AsyncMock(return_value={})):
        with pytest.raises(RuntimeError):
            await server._resolve_dynamic_runner(prompt="p")


def test_runner_is_registered():
    # Registered at import so a fresh container can resume an orphaned job.
    assert "resolve_dynamic_block" in server.runtime._job_runners


# --- failures become curated, frontend-facing situations (not raw errors) -----

import httpx  # noqa: E402
from tollbooth import AsyncJobSituation  # noqa: E402


def _anthropic_resp(status, message):
    req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    return httpx.Response(status, json={"error": {"message": message}}, request=req)


@pytest.mark.asyncio
async def test_runner_maps_billing_400_to_unfunded_situation():
    resp = _anthropic_resp(400, "Your credit balance is too low to access the Anthropic API.")
    err = httpx.HTTPStatusError("400", request=resp.request, response=resp)
    with patch.object(server.runtime, "load_credentials",
                      AsyncMock(return_value={"anthropic_api_key": "k"})), \
         patch("excalibur_mcp.resolve.resolve_block", AsyncMock(side_effect=err)):
        with pytest.raises(AsyncJobSituation) as ei:
            await server._resolve_dynamic_runner(prompt="p")
    assert ei.value.error_code == "operator_llm_unfunded"
    assert ei.value.transient is False
    # the raw Anthropic wording does not become the patron message
    assert "credit balance" not in ei.value.message.lower()


@pytest.mark.asyncio
async def test_runner_maps_empty_output_to_situation():
    with patch.object(server.runtime, "load_credentials",
                      AsyncMock(return_value={"anthropic_api_key": "k"})), \
         patch("excalibur_mcp.resolve.resolve_block", AsyncMock(side_effect=ValueError("no text"))):
        with pytest.raises(AsyncJobSituation) as ei:
            await server._resolve_dynamic_runner(prompt="p")
    assert ei.value.error_code == "dynamic_block_empty"


def test_shape_result_2xx_extracts_text():
    raw = {"status": 200, "json": {"content": [{"type": "text", "text": "<post>hi there</post>"}]}}
    assert server._resolve_shape_result(raw) == {"text": "hi there"}


def test_shape_result_billing_400_to_unfunded_situation():
    raw = {"status": 400, "json": {"error": {
        "message": "Your credit balance is too low. Please purchase credits.",
        "request_id": "req_SECRET"}}}
    with pytest.raises(AsyncJobSituation) as ei:
        server._resolve_shape_result(raw)
    assert ei.value.error_code == "operator_llm_unfunded"
    assert "req_SECRET" not in ei.value.message  # raw body never in patron copy


def test_shape_result_429_is_transient_rate_limit():
    raw = {"status": 429, "json": {"error": {"message": "overloaded"}}}
    with pytest.raises(AsyncJobSituation) as ei:
        server._resolve_shape_result(raw)
    assert ei.value.error_code == "upstream_rate_limited"
    assert ei.value.transient is True


def test_shape_result_empty_2xx_to_empty_situation():
    raw = {"status": 200, "json": {"content": []}}
    with pytest.raises(AsyncJobSituation) as ei:
        server._resolve_shape_result(raw)
    assert ei.value.error_code == "dynamic_block_empty"
