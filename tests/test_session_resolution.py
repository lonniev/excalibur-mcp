"""Tests for the refactored excalibur _prepare_x_client + _x_api_error_to_response.

Drops the long-lived in-memory bearer cache and routes every paid call
through runtime.restore_oauth_session, returning a structured error
dict on every non-success situation. Situation→error_code mapping is
1:1 — token_expired and no_credentials get distinct codes so a calling
agent knows whether to phrase a 'reconnect' or 'first connect' to the
patron.
"""

from unittest.mock import AsyncMock, patch

import pytest


VALID_NPUB = "npub1l94pd4qu4eszrl6ek032ftcnsu3tt9a7xvq2zp7eaxeklp6mrpzssmq8pf"


@pytest.mark.asyncio
async def test_missing_npub_returns_npub_missing():
    """Distinct from invalid-format — caller didn't pass npub at all."""
    import excalibur_mcp.server as srv

    rollback = AsyncMock()
    with patch.object(srv.runtime, "rollback_debit", rollback):
        result = await srv._prepare_x_client("post_tweet", "")

    assert isinstance(result, dict)
    assert result["error_code"] == "npub_missing"
    rollback.assert_awaited_once()


@pytest.mark.asyncio
async def test_malformed_npub_returns_npub_invalid():
    import excalibur_mcp.server as srv

    rollback = AsyncMock()
    with patch.object(srv.runtime, "rollback_debit", rollback):
        result = await srv._prepare_x_client("post_tweet", "not-an-npub")

    assert isinstance(result, dict)
    assert result["error_code"] == "npub_invalid"


@pytest.mark.asyncio
async def test_token_expired_returns_oauth_token_expired():
    """Refresh token aged out → caller gets a structured dict, not a raise."""
    import excalibur_mcp.server as srv

    with (
        patch.object(
            srv.runtime, "restore_oauth_session",
            new=AsyncMock(return_value=(None, "token_expired")),
        ),
        patch.object(srv.runtime, "rollback_debit", new=AsyncMock()),
    ):
        result = await srv._prepare_x_client("post_tweet", VALID_NPUB)

    assert isinstance(result, dict)
    assert result["error_code"] == "oauth_token_expired"
    assert any("excalibur_begin_oauth" in step for step in result["next_steps"])


@pytest.mark.asyncio
async def test_no_credentials_returns_oauth_not_yet_authorized():
    """Distinct from token_expired — first-time vs returning patron."""
    import excalibur_mcp.server as srv

    with (
        patch.object(
            srv.runtime, "restore_oauth_session",
            new=AsyncMock(return_value=(None, "no_credentials")),
        ),
        patch.object(srv.runtime, "rollback_debit", new=AsyncMock()),
    ):
        result = await srv._prepare_x_client("post_tweet", VALID_NPUB)

    assert result["error_code"] == "oauth_not_yet_authorized"
    assert any("excalibur_begin_oauth" in step for step in result["next_steps"])


@pytest.mark.asyncio
async def test_vault_bootstrapping_returns_warming_up():
    import excalibur_mcp.server as srv

    with (
        patch.object(
            srv.runtime, "restore_oauth_session",
            new=AsyncMock(return_value=(None, "vault_bootstrapping")),
        ),
        patch.object(srv.runtime, "rollback_debit", new=AsyncMock()),
    ):
        result = await srv._prepare_x_client("post_tweet", VALID_NPUB)

    assert result["error_code"] == "warming_up"


@pytest.mark.asyncio
async def test_empty_access_token_treated_as_no_credentials():
    """Vault returned creds with no access_token — same first-time recovery."""
    import excalibur_mcp.server as srv

    with (
        patch.object(
            srv.runtime, "restore_oauth_session",
            new=AsyncMock(return_value=({"access_token": ""}, "")),
        ),
        patch.object(srv.runtime, "rollback_debit", new=AsyncMock()),
    ):
        result = await srv._prepare_x_client("post_tweet", VALID_NPUB)

    assert result["error_code"] == "oauth_not_yet_authorized"


@pytest.mark.asyncio
async def test_success_returns_xclient_tuple():
    """Happy path: builds an XClient bound to the freshly resolved bearer."""
    import excalibur_mcp.server as srv
    from excalibur_mcp.x_client import XClient

    creds = {"access_token": "fresh-bearer-tok"}
    with patch.object(
        srv.runtime, "restore_oauth_session",
        new=AsyncMock(return_value=(creds, "")),
    ):
        result = await srv._prepare_x_client("post_tweet", VALID_NPUB)

    assert isinstance(result, tuple)
    client, situation = result
    assert isinstance(client, XClient)
    assert situation == ""


def test_x_api_error_401_routes_to_oauth_token_expired():
    """A 401/403 from X (token rejected upstream) maps to oauth_token_expired —
    the patron's session existed but the upstream now rejects it."""
    import excalibur_mcp.server as srv
    from excalibur_mcp.x_client import XAPIError

    exc = XAPIError(401, "Unauthorized", raw={"title": "Unauthorized"})
    result = srv._x_api_error_to_response(exc)

    assert result["error_code"] == "oauth_token_expired"
    assert any("excalibur_begin_oauth" in step for step in result["next_steps"])
    # Upstream context preserved for debugging
    assert result["status_code"] == 401


def test_x_api_error_500_passes_through_without_oauth_recipe():
    """Non-auth upstream errors don't get the begin_oauth recipe."""
    import excalibur_mcp.server as srv
    from excalibur_mcp.x_client import XAPIError

    exc = XAPIError(500, "Internal Server Error", raw={})
    result = srv._x_api_error_to_response(exc)

    assert result["status_code"] == 500
    # No misleading begin_oauth recipe attached
    assert "next_steps" not in result or not any(
        "begin_oauth" in s for s in result.get("next_steps", [])
    )
