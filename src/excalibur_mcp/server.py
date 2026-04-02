"""eXcalibur-mcp — FastMCP server for posting formatted content to X (Twitter).

Tollbooth-monetized, DPYC-native. Standard DPYC tools (check_balance,
purchase_credits, Secure Courier, Oracle, pricing) are provided by
``register_standard_tools`` from the tollbooth-dpyc wheel. Only
domain-specific X/Twitter tools are defined here.
"""

from __future__ import annotations

import logging
import os
from typing import Annotated, Any

from pydantic import Field

from fastmcp import FastMCP
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
    "action": "secure_courier_onboarding",
    "step_1": "Ask the user for their **patron npub** (the npub they registered as a DPYC Citizen). They can get one from the dpyc-oracle's how_to_join() tool.",
    "step_2": "Call request_credential_channel(recipient_npub=<npub>) to send a welcome DM to the user's Nostr client.",
    "step_3": "Tell the user to open their Nostr client (Primal, Damus, etc.) and reply to the welcome DM with their X API credentials in the JSON format shown. Credentials must NEVER appear in this chat.",
    "step_4": "Once the user confirms they replied, call receive_credentials(sender_npub=<npub>) to vault the credentials for future sessions.",
}

# Default vault directory (operator can override via EXCALIBUR_VAULT_DIR)
_DEFAULT_VAULT_DIR = os.path.join(os.path.expanduser("~"), ".excalibur", "vault")

# Service name for Neon vault patron session persistence
PATRON_CREDENTIAL_SERVICE = "excalibur"

# ---------------------------------------------------------------------------
# Tool cost table (domain tools only — standard tool costs are in the runtime)
# ---------------------------------------------------------------------------

TOOL_COSTS: dict[str, int] = {
    # Domain-specific free
    "register_credentials": ToolTier.FREE,
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
        version=1,
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
        },
        description="BTCPay Lightning payment credentials",
    ),
    patron_credential_template=CredentialTemplate(
        service="excalibur",
        version=3,
        fields={
            "access_token": FieldSpec(
                required=True,
                sensitive=True,
                description=(
                    "Your X/Twitter OAuth 1.0a Access Token. Found in the "
                    "X Developer Portal under your app's Keys and Tokens."
                ),
            ),
            "access_token_secret": FieldSpec(
                required=True,
                sensitive=True,
                description=(
                    "Your X/Twitter OAuth 1.0a Access Token Secret. Found "
                    "alongside the Access Token in the Developer Portal."
                ),
            ),
        },
        description="X/Twitter posting credentials",
    ),
    operator_credential_greeting=(
        "Hi \u2014 I\u2019m eXcalibur, a Tollbooth MCP service for posting formatted "
        "content to X. You (the operator) need to provide BTCPay credentials."
    ),
    patron_credential_greeting=(
        "Hi \u2014 I\u2019m eXcalibur, a Tollbooth MCP service for posting formatted "
        "content to X. You (or your AI agent) requested a credential channel."
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

_vault_instance = None


def _get_vault():
    """Get or create the FileVault singleton."""
    global _vault_instance
    if _vault_instance is not None:
        return _vault_instance
    from excalibur_mcp.vault import FileVault

    settings = get_settings()
    vault_dir = settings.excalibur_vault_dir or os.environ.get(
        "EXCALIBUR_VAULT_DIR", _DEFAULT_VAULT_DIR
    )
    _vault_instance = FileVault(vault_dir)
    return _vault_instance


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
        "message": (
            "The credential vault is syncing after a server restart. "
            "This usually takes 10-15 seconds."
        ),
        "action": "Retry in a moment. No re-authentication needed.",
    },
    "no_credentials": {
        "status": "ABSENT — no credentials stored",
        "message": (
            "No X API credentials are stored in the vault for this npub. "
            "Either credentials were never delivered, or they were stored "
            "under a different identity."
        ),
        "action": (
            "Deliver X API credentials via Secure Courier "
            "(request_patron_credentials → Nostr DM → receive_patron_credentials), "
            "or call register_credentials directly."
        ),
    },
    "credentials_incomplete": {
        "status": "INCOMPLETE — missing required fields",
        "message": (
            "X API credentials were found in the vault but some required "
            "fields are missing (x_api_key, x_api_secret, x_access_token, "
            "x_access_token_secret)."
        ),
        "action": "Re-deliver complete credentials via Secure Courier or register_credentials.",
    },
    "session_expired": {
        "status": "TRANSIENT — session timed out",
        "message": (
            "The in-memory session expired but vault credentials exist. "
            "Automatic restoration was attempted."
        ),
        "action": "Retry your request. Restoration completes transparently.",
    },
    "credentials_rejected": {
        "status": "REJECTED — X API refused the credentials",
        "message": (
            "X API credentials were found and loaded, but X rejected them. "
            "They may have been revoked or changed in the X Developer Portal."
        ),
        "action": "Deliver fresh X API credentials via Secure Courier or register_credentials.",
    },
}


async def _ensure_session(user_id: str, npub: str = "") -> str | None:
    """Restore credentials from Neon vault into in-memory session on cold start.

    Returns the lifecycle situation string if restoration was attempted but
    failed, or ``None`` on success / nothing to do.
    """
    from excalibur_mcp.vault import get_session, set_session

    if get_session(user_id) is not None:
        return None
    if not npub:
        return None
    try:
        creds = await runtime.load_patron_session(npub, service=PATRON_CREDENTIAL_SERVICE)
        if not creds:
            return "no_credentials"

        # Patron vault stores access_token + access_token_secret (per-patron).
        # The app-level api_key + api_secret come from env vars (shared by all patrons).
        # Also accept the legacy x_-prefixed field names from register_credentials.
        access_token = creds.get("x_access_token") or creds.get("access_token")
        access_token_secret = creds.get("x_access_token_secret") or creds.get("access_token_secret")

        if not access_token or not access_token_secret:
            logger.warning("Vault credentials for %s missing access_token fields", npub[:20])
            return "credentials_incomplete"

        # App-level keys: from vault (register_credentials path) or env vars
        api_key = creds.get("x_api_key") or os.environ.get("X_API_KEY", "")
        api_secret = creds.get("x_api_secret") or os.environ.get("X_API_SECRET", "")

        if not api_key or not api_secret:
            logger.warning("No X API app keys — set X_API_KEY and X_API_SECRET env vars")
            return "credentials_incomplete"

        set_session(
            user_id,
            api_key,
            api_secret,
            access_token,
            access_token_secret,
            npub=npub,
        )
        logger.info("Restored excalibur session for %s from vault.", npub[:20])
        return None
    except Exception as exc:
        logger.warning("Vault session restore failed (%s): %s", type(exc).__name__, exc)
        return "vault_bootstrapping"


def _get_x_credentials():
    """Get X API credentials: per-user session first, env vars as fallback.

    Raises ``ValueError`` with lifecycle-aware guidance when credentials
    cannot be resolved.
    """
    from excalibur_mcp.vault import get_session
    from excalibur_mcp.x_client import XCredentials

    user_id = OperatorRuntime.get_current_user_id()
    if user_id:
        session = get_session(user_id)
        if session:
            return XCredentials(
                api_key=session.x_api_key,
                api_secret=session.x_api_secret,
                access_token=session.x_access_token,
                access_token_secret=session.x_access_token_secret,
            )

    # Env-var fallback (operator-level credentials)
    try:
        return XCredentials.from_env()
    except KeyError:
        raise ValueError(_SESSION_GUIDANCE["no_credentials"])



# ---------------------------------------------------------------------------
# MCP Tools — Free (domain-specific)
# ---------------------------------------------------------------------------



@tool
async def register_credentials(
    x_api_key: str,
    x_api_secret: str,
    x_access_token: str,
    x_access_token_secret: str,
    passphrase: str,
    npub: str,
) -> dict[str, Any]:
    """Register your X API credentials for multi-tenant access.

    First-time setup: encrypts your X API OAuth credentials with your
    passphrase and stores the encrypted blob in the operator's credential
    vault. The passphrase is never stored — you will need it each session
    to activate access.

    Args:
        x_api_key: Your X API consumer key
        x_api_secret: Your X API consumer secret
        x_access_token: Your X API access token
        x_access_token_secret: Your X API access token secret
        passphrase: A passphrase to encrypt your credentials (remember this!)
        npub: Your **patron** Nostr public key in bech32 format (npub1...)
    """
    from excalibur_mcp.vault import encrypt_credentials, set_session

    if not npub.startswith("npub1") or len(npub) < 60:
        return {
            "success": False,
            "error": (
                "Invalid npub format. Must start with 'npub1' and be at least 60 characters. "
                "Get your npub from the dpyc-oracle's how_to_join() tool."
            ),
        }

    try:
        user_id = OperatorRuntime.require_user_id()
    except ValueError as e:
        return {"success": False, "error": str(e)}

    try:
        vault = _get_vault()
    except Exception as e:
        return {"success": False, "error": f"Vault not available: {e}"}

    blob = encrypt_credentials(
        x_api_key, x_api_secret, x_access_token, x_access_token_secret,
        passphrase, npub=npub,
    )
    await vault.store(user_id, blob)

    set_session(
        user_id, x_api_key, x_api_secret, x_access_token, x_access_token_secret, npub=npub
    )

    # Persist to Neon vault for cross-restart survival
    await runtime.store_patron_session(npub, {
        "x_api_key": x_api_key,
        "x_api_secret": x_api_secret,
        "x_access_token": x_access_token,
        "x_access_token_secret": x_access_token_secret,
    }, service=PATRON_CREDENTIAL_SERVICE)

    return {
        "success": True,
        "message": "Credentials registered and session activated.",
        "userId": user_id,
        "dpyc_npub": npub,
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
    restore_detail: str | None = None
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
        if state in ("no_credentials", "credentials_incomplete"):
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
