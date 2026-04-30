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
from tollbooth.credential_templates import CredentialTemplate, FieldSpec
from tollbooth.credential_validators import validate_btcpay_creds, validate_required
from tollbooth.oauth_config import OAuthProviderConfig
from tollbooth.runtime import OperatorRuntime, register_standard_tools
from tollbooth.slug_tools import make_slug_tool
from tollbooth.tool_identity import STANDARD_IDENTITIES, ToolIdentity, capability_uuid

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

_DOMAIN_TOOLS = [
    # OAuth tools are now standard (from wheel via OAuthProviderConfig)
    ToolIdentity(capability="post_tweet", category="write", intent="Post a text tweet to X/Twitter"),
    ToolIdentity(capability="post_tweet_image", category="heavy", intent="Post a tweet with image to X/Twitter"),
]

TOOL_REGISTRY: dict[str, ToolIdentity] = {ti.tool_id: ti for ti in _DOMAIN_TOOLS}

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
    tool_registry={**STANDARD_IDENTITIES, **TOOL_REGISTRY},
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
    oauth_provider=OAuthProviderConfig(
        authorize_url="https://x.com/i/oauth2/authorize",
        token_url="https://api.x.com/2/oauth2/token",
        scopes="tweet.read tweet.write users.read offline.access",
        pkce=True,
        refresh_enabled=True,
        service_name="excalibur",
    ),
    operator_credential_greeting=(
        "Hi \u2014 I\u2019m eXcalibur, a Tollbooth MCP service for posting formatted "
        "content to X. You (the operator) need to provide BTCPay and X OAuth2 credentials."
    ),
    credential_validator=lambda creds: (
        validate_btcpay_creds(creds)
        + [e for e in [validate_required(creds.get("client_id", ""), "client_id")] if e]
        + [e for e in [validate_required(creds.get("client_secret", ""), "client_secret")] if e]
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



async def _ensure_session(session_key: str, npub: str = "") -> str | None:
    """Restore OAuth2 Bearer token from vault on cold start.

    Delegates token loading and refresh to the wheel's generic
    ``restore_oauth_session``. Returns lifecycle situation string
    on failure, or None on success.
    """
    from excalibur_mcp.vault import get_session, set_bearer_session

    if get_session(session_key) is not None:
        return None
    if not npub:
        return None

    creds, situation = await runtime.restore_oauth_session(npub)
    if creds is None:
        return situation

    access_token = creds.get("access_token", "")
    if not access_token:
        return "no_credentials"

    set_bearer_session(session_key, access_token)
    logger.info("Restored excalibur OAuth2 session for %s from vault.", npub[:20])
    return None


def _get_x_credentials(npub: str):
    """Get X API Bearer token from the in-memory session, keyed by npub."""
    from excalibur_mcp.vault import get_session
    from excalibur_mcp.x_client import XCredentials

    session = get_session(npub)
    if session and session.bearer_token:
        return XCredentials(bearer_token=session.bearer_token)

    raise ValueError(_SESSION_GUIDANCE["no_credentials"]["message"])


# ---------------------------------------------------------------------------
# MCP Tools — Paid (domain-specific)
# OAuth tools (begin_oauth, check_oauth_status) are now standard
# wheel tools, registered via OAuthProviderConfig.
# ---------------------------------------------------------------------------


async def _prepare_x_client(
    cost_key: str, npub: str,
) -> tuple[Any, str | None] | dict:
    """Shared setup for X posting tools: session restore, credential check.

    Billing and proof are handled by the ``@paid_tool`` decorator —
    do NOT call ``debit_or_deny`` here (double-gating bug).

    Returns (XClient, restore_situation) on success, or an error dict.
    """
    from excalibur_mcp.x_client import XClient

    restore_situation = await _ensure_session(npub, npub)
    if restore_situation:
        logger.info("Session restore for %s: %s", npub[:20], restore_situation)

    try:
        creds = _get_x_credentials(npub)
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
        if state in ("no_credentials", "token_expired"):
            result["next_steps"] = _ONBOARDING_NEXT_STEPS
        return result

    return (XClient(creds), restore_situation)


@tool
@runtime.paid_tool(capability_uuid("post_tweet"), catch_errors=True)
async def post_tweet(
    text: str,
    npub: Annotated[str, Field(description="Required. Your Nostr public key (npub1...) for credit billing.")] = "", proof: str = "",
) -> dict:
    """Post a text tweet with markdown formatting converted to Unicode rich text.

    Accepts standard markdown inline formatting and converts it to Unicode
    Mathematical Alphanumeric Symbols that render as styled text on X:

        **bold**          -> bold
        *italic*          -> italic
        ***bold italic*** -> bold italic
        `monospace`       -> monospace

    Args:
        text: Tweet content with optional markdown formatting.
        npub: Your DPYC patron Nostr public key (npub1...) for credit attribution.
    """
    from excalibur_mcp.formatter import markdown_to_unicode
    from excalibur_mcp.x_client import XAPIError

    converted = markdown_to_unicode(text)

    client_or_err = await _prepare_x_client(capability_uuid("post_tweet"), npub)
    if isinstance(client_or_err, dict):
        return client_or_err
    client, _ = client_or_err

    try:
        result = await client.post_tweet(converted)
    except XAPIError as exc:
        result: dict[str, Any] = {
            "error": str(exc),
            "status_code": exc.status_code,
            "detail": exc.detail,
        }
        if exc.status_code in (401, 403):
            result["credential_state"] = "credentials_rejected"
            result.update(_SESSION_GUIDANCE["credentials_rejected"])
        return result

    return result


@tool
@runtime.paid_tool(capability_uuid("post_tweet_image"), catch_errors=True)
async def post_tweet_image(
    text: str,
    image_url: str = "",
    banner_svg: str = "",
    npub: Annotated[str, Field(description="Required. Your Nostr public key (npub1...) for credit billing.")] = "", proof: str = "",
) -> dict:
    """Post a tweet with a hero banner image to X/Twitter.

    Provide either an image_url (fetched and attached) or banner_svg
    (rendered to PNG and attached). Text supports the same markdown
    formatting as post_tweet.

    Args:
        text: Tweet content with optional markdown formatting.
        image_url: URL of an image to attach to the tweet.
        banner_svg: Self-contained SVG markup string, converted to PNG.
        npub: Your DPYC patron Nostr public key (npub1...) for credit attribution.
    """
    if not image_url and not banner_svg:
        return {"error": "Either image_url or banner_svg is required."}

    from excalibur_mcp.formatter import markdown_to_unicode
    from excalibur_mcp.x_client import XAPIError

    converted = markdown_to_unicode(text)

    client_or_err = await _prepare_x_client(capability_uuid("post_tweet_image"), npub)
    if isinstance(client_or_err, dict):
        return client_or_err
    client, _ = client_or_err

    banner_png: bytes | None = None
    if banner_svg:
        try:
            banner_png = _svg_to_png(banner_svg)
        except Exception as exc:
            return {"error": f"Banner render failed: {exc}"}

    try:
        if image_url:
            result = await client.post_tweet_with_image(converted, image_url)
        elif banner_png:
            media_id = await client.upload_media(banner_png, "image/png")
            result = await client.post_tweet(converted, media_ids=[media_id])
        else:
            result = {"error": "No image provided."}
    except XAPIError as exc:
        result: dict[str, Any] = {
            "error": str(exc),
            "status_code": exc.status_code,
            "detail": exc.detail,
        }
        if exc.status_code in (401, 403):
            result["credential_state"] = "credentials_rejected"
            result.update(_SESSION_GUIDANCE["credentials_rejected"])
        return result

    return result


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
