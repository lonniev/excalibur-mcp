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
