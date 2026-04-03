"""eXcalibur-mcp — FastMCP server for posting formatted content to X (Twitter).

Tollbooth-monetized, DPYC-native. Standard DPYC tools (check_balance,
purchase_credits, Secure Courier, Oracle, pricing) are provided by
``register_standard_tools`` from the tollbooth-dpyc wheel. Only
domain-specific X/Twitter tools are defined here.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastmcp import FastMCP
from pydantic import Field
from tollbooth.constants import ToolTier
from tollbooth.credential_templates import CredentialTemplate, FieldSpec
from tollbooth.runtime import OperatorRuntime, register_standard_tools
from tollbooth.slug_tools import make_slug_tool

from excalibur_mcp import __version__

logger = logging.getLogger(__name__)

mcp = FastMCP(
    "eXcalibur",
    instructions=(
        "eXcalibur MCP — AI agent access to X (Twitter) posting, "
        "monetized via DPYC Tollbooth Lightning micropayments.\n\n"
        "## Getting Started\n\n"
        "1. Call `session_status` to check your current session.\n"
        "2. If no active session, follow the Secure Courier onboarding flow:\n"
        "   - Get your **patron npub** from the dpyc-oracle's how_to_join() tool — "
        "this is the npub you registered as a DPYC Citizen, your identity for credit operations\n"
        "   - Call `request_credential_channel(recipient_npub=<patron_npub>)` to receive a welcome DM\n"
        "   - Reply via your Nostr client with your X API credentials in JSON\n"
        "   - Call `receive_credentials(sender_npub=<patron_npub>)` to vault your credentials\n\n"
        "## Credits Model\n\n"
        "Tool calls cost api_sats per call. Auth and balance tools are always free. "
        "Use `check_balance` to see your balance. Top up via `purchase_credits`."
    ),
)
tool = make_slug_tool(mcp, "excalibur")

# Structured onboarding guidance — included in error responses so Claude
# can self-guide a first-time user through Secure Courier registration
# without the user needing to explain the process.
_ONBOARDING_NEXT_STEPS = {
    "action": "oauth2_authorization",
    "step_1": "Ask the user for their **patron npub** (npub1...).",
    "step_2": "Call begin_oauth(npub=<npub>) to get an authorization URL.",
    "step_3": "Tell the user to open the URL in their browser and authorize the app on X.",
    "step_4": "Call check_oauth_status(npub=<npub>) to complete the token exchange.",
}

# Service name for Neon vault patron session persistence
PATRON_CREDENTIAL_SERVICE = "excalibur"

# ---------------------------------------------------------------------------
# Tool cost table (domain tools only — standard tool costs are in the runtime)
# ---------------------------------------------------------------------------

TOOL_COSTS: dict[str, int] = {
    # Domain-specific free
    "begin_oauth": ToolTier.FREE,
    "check_oauth_status": ToolTier.FREE,
    # Domain-specific paid
    "post_tweet": ToolTier.WRITE,  # 5 api_sats (text only)
    "post_tweet_image": ToolTier.HEAVY,  # 10 api_sats (with image upload)
}

# ---------------------------------------------------------------------------
# Settings singleton
# ---------------------------------------------------------------------------

_settings = None


def get_settings():
    """Get or create the Settings singleton."""
    global _settings
    if _settings is not None:
        return _settings
    from excalibur_mcp.config import Settings

    _settings = Settings()
    return _settings


# ---------------------------------------------------------------------------
# OperatorRuntime — replaces all DPYC boilerplate
# ---------------------------------------------------------------------------

runtime = OperatorRuntime(
    service_name="eXcalibur",
    tool_costs=TOOL_COSTS,
    operator_credential_template=CredentialTemplate(
        service="excalibur-operator",
        version=3,
        fields={
            "btcpay_host": FieldSpec(
                required=True, sensitive=True,
                description="The URL of your BTCPay Server instance.",
            ),
            "btcpay_api_key": FieldSpec(
                required=True, sensitive=True,
                description="Your BTCPay Server API key.",
            ),
            "btcpay_store_id": FieldSpec(
                required=True, sensitive=True,
                description="Your BTCPay Store ID.",
            ),
            "client_id": FieldSpec(
                required=True, sensitive=True,
                description="X OAuth2 Client ID (from X Developer Portal).",
            ),
            "client_secret": FieldSpec(
                required=True, sensitive=True,
                description="X OAuth2 Client Secret (from X Developer Portal).",
            ),
        },
        description="BTCPay Lightning payment + X OAuth2 app credentials",
    ),
    # No patron_credential_template — patron tokens come from OAuth2 browser flow
    operator_credential_greeting=(
        "Hi \u2014 I\u2019m eXcalibur, a Tollbooth MCP service for posting formatted "
        "content to X. You (the operator) need to provide BTCPay and X OAuth2 credentials."
    ),
)

# ---------------------------------------------------------------------------
# Register all standard DPYC tools from the wheel
# ---------------------------------------------------------------------------

register_standard_tools(
    mcp,
    "excalibur",
    runtime,
    service_name="excalibur-mcp",
    service_version=__version__,
)


# ---------------------------------------------------------------------------
# Horizon auth helpers
# ---------------------------------------------------------------------------




# ---------------------------------------------------------------------------
# Credential vault singleton
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# SVG-to-PNG conversion
# ---------------------------------------------------------------------------


def _svg_to_png(svg_markup: str) -> bytes:
    """Convert SVG markup to PNG bytes via PyMuPDF."""
    import pymupdf

    doc = pymupdf.open(stream=svg_markup.encode("utf-8"), filetype="svg")
    page = doc[0]
    pix = page.get_pixmap()
    return pix.tobytes("png")


# ---------------------------------------------------------------------------
# Credential resolution: session -> env vars
# ---------------------------------------------------------------------------

# Patron-facing guidance for each lifecycle state.
_SESSION_GUIDANCE: dict[str, dict[str, str]] = {
    "vault_bootstrapping": {
        "status": "TRANSIENT — vault syncing",
        "message": "Credential vault is syncing after restart. Retry in a moment.",
        "action": "Retry in 10-15 seconds.",
    },
    "no_credentials": {
        "status": "ABSENT — not authorized",
        "message": "No X authorization found for this npub.",
        "action": "Call begin_oauth(npub) to start the X OAuth2 authorization flow.",
    },
    "token_expired": {
        "status": "EXPIRED — token needs refresh",
        "message": "X access token expired and refresh failed.",
        "action": "Call begin_oauth(npub) to re-authorize.",
    },
    "credentials_rejected": {
        "status": "REJECTED — X API refused the token",
        "message": "X rejected the access token. It may have been revoked.",
        "action": "Call begin_oauth(npub) to re-authorize.",
    },
}



async def _ensure_session(user_id: str, npub: str = "") -> str | None:
    """Restore OAuth2 Bearer token from vault on cold start.

    Checks expiration and auto-refreshes if needed. Returns lifecycle
    situation string on failure, or None on success.
    """
    import json
    import time

    from excalibur_mcp.vault import get_session, set_bearer_session

    if get_session(user_id) is not None:
        return None
    if not npub:
        return None
    try:
        creds = await runtime.load_patron_session(npub, service=PATRON_CREDENTIAL_SERVICE)
        if not creds:
            return "no_credentials"

        access_token = creds.get("access_token")
        if not access_token:
            return "no_credentials"

        # Check expiration and auto-refresh
        expires_at = float(creds.get("expires_at", 0))
        if time.time() > expires_at:
            refresh_token = creds.get("refresh_token", "")
            if not refresh_token:
                return "token_expired"
            # Load operator app creds for refresh
            op_creds = await runtime.load_credentials(["client_id", "client_secret"])
            client_id = op_creds.get("client_id", "")
            client_secret = op_creds.get("client_secret", "")
            if not client_id or not client_secret:
                return "token_expired"
            try:
                from excalibur_mcp.oauth_flow import refresh_access_token
                new_token = await refresh_access_token(client_id, client_secret, refresh_token)
                # Persist refreshed token
                await runtime.store_patron_session(npub, {
                    "access_token": new_token["access_token"],
                    "refresh_token": new_token.get("refresh_token", refresh_token),
                    "expires_at": str(new_token["expires_at"]),
                    "token_type": "Bearer",
                }, service=PATRON_CREDENTIAL_SERVICE)
                access_token = new_token["access_token"]
                logger.info("Refreshed X OAuth2 token for %s", npub[:20])
            except Exception as exc:
                logger.warning("Token refresh failed for %s: %s", npub[:20], exc)
                return "token_expired"

        set_bearer_session(user_id, access_token, npub=npub)
        logger.info("Restored excalibur OAuth2 session for %s from vault.", npub[:20])
        return None
    except Exception as exc:
        logger.warning("Vault session restore failed (%s): %s", type(exc).__name__, exc)
        return "vault_bootstrapping"


def _get_x_credentials():
    """Get X API Bearer token from the in-memory session."""
    from excalibur_mcp.vault import get_session
    from excalibur_mcp.x_client import XCredentials

    user_id = OperatorRuntime.get_current_user_id()
    if user_id:
        session = get_session(user_id)
        if session and session.bearer_token:
            return XCredentials(bearer_token=session.bearer_token)

    raise ValueError(_SESSION_GUIDANCE["no_credentials"]["message"])


# ---------------------------------------------------------------------------
# MCP Tools — Free (OAuth2 flow)
# ---------------------------------------------------------------------------


@tool
async def begin_oauth(npub: str = "") -> dict[str, Any]:
    """Start the X OAuth2 authorization flow.

    Returns an authorization URL. Open it in a browser to authorize
    this app to post on your behalf. Then call check_oauth_status.

    Free — no credits required.

    Args:
        npub: Required. Your Nostr public key (npub1...).
    """
    from tollbooth.runtime import resolve_npub
    try:
        npub = resolve_npub(npub)
    except ValueError as e:
        return {"success": False, "error": str(e)}

    # Load operator OAuth2 app credentials
    op_creds = await runtime.load_credentials(["client_id", "client_secret"])
    client_id = op_creds.get("client_id", "")
    if not client_id:
        return {"success": False, "error": "Operator X OAuth2 client_id not configured."}

    # Resolve redirect URI from the OAuth2 collector in the registry
    try:
        from tollbooth.registry import resolve_service_by_name
        svc = await resolve_service_by_name("tollbooth-oauth2-callback")
        redirect_uri = svc["url"].rstrip("/") + "/callback"
    except Exception as e:
        return {"success": False, "error": f"Failed to resolve OAuth2 callback: {e}"}

    from excalibur_mcp.oauth_flow import begin_oauth_flow
    authorize_url, verifier = begin_oauth_flow(npub, client_id, redirect_uri)

    # Store verifier in vault (survives across Horizon SSE connections)
    await runtime.store_patron_session(npub, {
        "pkce_verifier": verifier,
        "redirect_uri": redirect_uri,
    }, service=PATRON_CREDENTIAL_SERVICE)

    return {
        "success": True,
        "status": "pending",
        "authorize_url": authorize_url,
        "message": (
            "Open this URL in your browser to authorize with X. "
            "After authorizing, call check_oauth_status to complete."
        ),
    }


@tool
async def check_oauth_status(npub: str = "") -> dict[str, Any]:
    """Check if the X OAuth2 authorization completed.

    Polls the OAuth2 collector for the authorization code, exchanges
    it for tokens, and stores them in the vault.

    Free — no credits required.

    Args:
        npub: Required. Your Nostr public key (npub1...).
    """
    import json

    from tollbooth.runtime import resolve_npub
    try:
        npub = resolve_npub(npub)
    except ValueError as e:
        return {"success": False, "error": str(e)}

    # Load PKCE verifier and redirect_uri from vault (stored by begin_oauth)
    pending = await runtime.load_patron_session(npub, service=PATRON_CREDENTIAL_SERVICE)
    verifier = (pending or {}).get("pkce_verifier")
    if not verifier:
        return {
            "success": False,
            "error": "No pending OAuth flow for this npub. Call begin_oauth first.",
        }
    stored_redirect_uri = (pending or {}).get("redirect_uri", "")

    # Load operator OAuth2 app credentials
    op_creds = await runtime.load_credentials(["client_id", "client_secret"])
    client_id = op_creds.get("client_id", "")
    client_secret = op_creds.get("client_secret", "")
    if not client_id or not client_secret:
        return {"success": False, "error": "Operator OAuth2 credentials not configured."}

    # Resolve collector URL
    try:
        from tollbooth.registry import resolve_service_by_name
        settings = get_settings()
        svc = await resolve_service_by_name(
            "tollbooth-oauth2-collector",
            cache_ttl_seconds=settings.dpyc_registry_cache_ttl_seconds,
        )
        collector_url = svc["url"].rstrip("/")
    except Exception as e:
        return {"success": False, "error": f"Failed to resolve OAuth2 collector: {e}"}

    # Use stored redirect_uri (must match what was used in begin_oauth)
    redirect_uri = stored_redirect_uri
    if not redirect_uri:
        try:
            callback_svc = await resolve_service_by_name("tollbooth-oauth2-callback")
            redirect_uri = callback_svc["url"].rstrip("/") + "/callback"
        except Exception as e:
            return {"success": False, "error": f"Failed to resolve callback: {e}"}

    # Retrieve auth code from collector
    from tollbooth.oauth2_collector import retrieve_code_from_collector
    code = await retrieve_code_from_collector(collector_url, npub)
    if code is None:
        return {
            "status": "pending",
            "message": "Waiting for browser authorization. Open the URL from begin_oauth.",
        }

    # Exchange code for tokens
    try:
        from excalibur_mcp.oauth_flow import exchange_code_for_token
        token = await exchange_code_for_token(
            code, client_id, client_secret, redirect_uri, verifier,
        )
    except Exception as e:
        return {"success": False, "error": f"Token exchange failed: {e}"}

    # Store tokens in vault (replaces the temporary pkce_verifier entry)
    await runtime.store_patron_session(npub, {
        "access_token": token["access_token"],
        "refresh_token": token.get("refresh_token", ""),
        "expires_at": str(token.get("expires_at", 0)),
        "token_type": "Bearer",
    }, service=PATRON_CREDENTIAL_SERVICE)

    # Activate in-memory session
    user_id = OperatorRuntime.get_current_user_id()
    if user_id:
        from excalibur_mcp.vault import set_bearer_session
        set_bearer_session(user_id, token["access_token"], npub=npub)

    return {
        "success": True,
        "status": "completed",
        "message": "X authorization successful. You can now use post_tweet.",
    }



# ---------------------------------------------------------------------------
# MCP Tools — Paid (domain-specific)
# ---------------------------------------------------------------------------


@tool
async def post_tweet(
    text: str,
    image_url: str | None = None,
    banner_svg: str | None = None,
    npub: Annotated[str, Field(description="Required. Your Nostr public key (npub1...) for credit billing.")] = "",
) -> dict:
    """Post a tweet with markdown formatting converted to Unicode rich text. Requires npub for credit billing.

    Accepts standard markdown inline formatting and converts it to Unicode
    Mathematical Alphanumeric Symbols that render as styled text on X:

        **bold**          -> bold
        *italic*          -> italic
        ***bold italic*** -> bold italic
        `monospace`       -> monospace

    Args:
        text: Tweet content with optional markdown formatting.
        image_url: Optional URL of an image to attach to the tweet.
        banner_svg: Optional self-contained SVG markup string, converted
                   to PNG and attached as a native Twitter media image.
        npub: Your DPYC patron Nostr public key (npub1...) for credit attribution.
    """
    cost_key = "post_tweet_image" if (image_url or banner_svg) else "post_tweet"

    # Credit gating via runtime
    err = await runtime.debit_or_error(cost_key, npub)
    if err is not None:
        return err

    from excalibur_mcp.formatter import markdown_to_unicode
    from excalibur_mcp.x_client import XAPIError, XClient

    converted = markdown_to_unicode(text)

    # --- Banner processing: SVG -> PNG -> Twitter media attachment ---
    banner_png: bytes | None = None
    if banner_svg:
        try:
            banner_png = _svg_to_png(banner_svg)
        except Exception as exc:
            await runtime.rollback_debit(cost_key, npub)
            return {"error": f"Banner render failed: {exc}"}

    # Restore session from Neon vault on cold start
    user_id = OperatorRuntime.get_current_user_id()
    restore_situation: str | None = None
    if user_id:
        restore_situation = await _ensure_session(user_id, npub)
        if restore_situation:
            logger.info("Session restore for %s: %s", npub[:20], restore_situation)

    try:
        creds = _get_x_credentials()
    except ValueError as exc:
        await runtime.rollback_debit(cost_key, npub)
        state = restore_situation or "no_credentials"
        guidance = _SESSION_GUIDANCE.get(state, {
            "status": f"ERROR — {state}",
            "message": str(exc),
            "action": "Check the credential state and retry.",
        })
        result: dict[str, Any] = {
            "credential_state": state,
            **guidance,
        }
        # Include onboarding steps only when credentials are actually
        # absent or incomplete — not for transient situations.
        if state in ("no_credentials", "token_expired"):
            result["next_steps"] = _ONBOARDING_NEXT_STEPS
        return result

    client = XClient(creds)

    try:
        if image_url:
            result = await client.post_tweet_with_image(converted, image_url)
        elif banner_png:
            media_id = await client.upload_media(banner_png, "image/png")
            result = await client.post_tweet(converted, media_ids=[media_id])
        else:
            result = await client.post_tweet(converted)
    except XAPIError as exc:
        await runtime.rollback_debit(cost_key, npub)
        result: dict[str, Any] = {
            "error": str(exc),
            "status_code": exc.status_code,
            "detail": exc.detail,
        }
        # 401/403 from X means credentials are revoked or invalid
        if exc.status_code in (401, 403):
            result["credential_state"] = "credentials_rejected"
            result.update(_SESSION_GUIDANCE["credentials_rejected"])
        return result

    runtime.fire_and_forget_demand_increment(cost_key)
    return await runtime.inject_low_balance_warning(result, npub)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Entry point for the eXcalibur MCP server."""
    from tollbooth import validate_operator_tools

    missing = validate_operator_tools(mcp, "excalibur")
    if missing:
        import sys

        print(f"\u26a0 Missing base-catalog tools: {', '.join(missing)}", file=sys.stderr)
    mcp.run()


if __name__ == "__main__":
    main()
