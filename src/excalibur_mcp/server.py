"""eXcalibur-mcp — FastMCP server for posting formatted content to X (Twitter).

Tollbooth-monetized, DPYC-native. Standard DPYC tools (check_balance,
purchase_credits, Secure Courier, Oracle, pricing) are provided by
``register_standard_tools`` from the tollbooth-dpyc wheel. Only
domain-specific X/Twitter tools are defined here.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from fastmcp import FastMCP
from tollbooth.constants import ToolTier
from tollbooth.credential_templates import CredentialTemplate, FieldSpec
from tollbooth.runtime import OperatorRuntime, register_standard_tools, resolve_npub
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

# ---------------------------------------------------------------------------
# Tool cost table (domain tools only — standard tool costs are in the runtime)
# ---------------------------------------------------------------------------

TOOL_COSTS: dict[str, int] = {
    # Domain-specific free
    "health": ToolTier.FREE,
    "register_credentials": ToolTier.FREE,
    "activate_session": ToolTier.FREE,
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


def _get_current_user_id() -> str | None:
    """Extract FastMCP Cloud user ID from request headers.

    Returns None in STDIO mode (local dev) or when no auth headers present.
    """
    try:
        from fastmcp.server.dependencies import get_http_headers

        headers = get_http_headers(include_all=True)
        return headers.get("fastmcp-cloud-user")
    except Exception:
        return None


def _require_user_id() -> str:
    """Extract user ID or raise ValueError."""
    user_id = _get_current_user_id()
    if not user_id:
        raise ValueError(
            "Multi-tenant credentials require FastMCP Cloud (Horizon). "
            "In STDIO mode, set X_API_KEY etc. as environment variables."
        )
    return user_id


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


def _get_x_credentials():
    """Get X API credentials: per-user session first, env vars as fallback."""
    from excalibur_mcp.vault import get_session
    from excalibur_mcp.x_client import XCredentials

    user_id = _get_current_user_id()
    if user_id:
        session = get_session(user_id)
        if session:
            return XCredentials(
                api_key=session.x_api_key,
                api_secret=session.x_api_secret,
                access_token=session.x_access_token,
                access_token_secret=session.x_access_token_secret,
            )

    return XCredentials.from_env()


# ---------------------------------------------------------------------------
# Low-balance warning helper (uses runtime)
# ---------------------------------------------------------------------------


async def _with_warning(result: dict[str, Any], npub: str = "") -> dict[str, Any]:
    """Attach a low-balance warning to a paid tool result if balance is low."""
    try:
        from tollbooth.tools.credits import compute_low_balance_warning

        user_id = resolve_npub(npub)
        cache = await runtime.ledger_cache()
        ledger = await cache.get(user_id)
        settings = get_settings()
        warning = compute_low_balance_warning(ledger, settings.seed_balance_sats)
        if warning:
            result = dict(result)
            result["low_balance_warning"] = warning
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# MCP Tools — Free (domain-specific)
# ---------------------------------------------------------------------------


@tool
async def health() -> dict:
    """Health check — returns service version and status. Free, no credits consumed."""
    import importlib.metadata as _meta

    versions: dict[str, str] = {"excalibur_mcp": __version__}
    try:
        versions["tollbooth_dpyc"] = _meta.version("tollbooth-dpyc")
    except _meta.PackageNotFoundError:
        versions["tollbooth_dpyc"] = "unknown"

    return {
        "service": "excalibur-mcp",
        "version": __version__,
        "versions": versions,
        "status": "ok",
    }


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
        user_id = _require_user_id()
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

    return {
        "success": True,
        "message": "Credentials registered and session activated.",
        "userId": user_id,
        "dpyc_npub": npub,
    }


@tool
async def activate_session(passphrase: str) -> dict[str, Any]:
    """Activate your personal X API session by decrypting stored credentials.

    Call this at the start of each session. Provide the same passphrase you
    used during register_credentials.

    Args:
        passphrase: The passphrase you used when registering credentials
    """
    from excalibur_mcp.vault import (
        CredentialNotFoundError,
        DecryptionError,
        VaultNotConfiguredError,
        decrypt_credentials,
        set_session,
    )

    try:
        user_id = _require_user_id()
        vault = _get_vault()
        blob = await vault.fetch(user_id)
        creds = decrypt_credentials(blob, passphrase)
    except (ValueError, VaultNotConfiguredError, CredentialNotFoundError, DecryptionError) as e:
        result: dict[str, Any] = {"success": False, "error": str(e)}
        if isinstance(e, CredentialNotFoundError):
            result["next_steps"] = _ONBOARDING_NEXT_STEPS
            result["hint"] = (
                "If you already completed the Secure Courier flow, you may not "
                "have included a passphrase. Re-run receive_credentials(sender_npub=<npub>, "
                "passphrase=<passphrase>) to store credentials in the passphrase vault."
            )
        return result

    npub = creds.get("npub")
    set_session(
        user_id,
        creds["x_api_key"],
        creds["x_api_secret"],
        creds["x_access_token"],
        creds["x_access_token_secret"],
        npub=npub,
    )

    result: dict[str, Any] = {
        "success": True,
        "message": "Session activated. post_tweet now uses your personal credentials.",
    }
    if npub:
        result["dpyc_npub"] = npub
    else:
        result["dpyc_warning"] = (
            "Your vault credentials were registered before npub was required. "
            "Credit operations will not work until you re-register with an npub."
        )
    return result


# ---------------------------------------------------------------------------
# MCP Tools — Paid (domain-specific)
# ---------------------------------------------------------------------------


@tool
async def post_tweet(
    text: str,
    image_url: str | None = None,
    banner_svg: str | None = None,
    npub: str = "",
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

    try:
        creds = _get_x_credentials()
    except KeyError as exc:
        await runtime.rollback_debit(cost_key, npub)
        return {
            "error": f"Missing X API credential: {exc}. "
            "Set X_API_KEY, X_API_SECRET, X_ACCESS_TOKEN, X_ACCESS_TOKEN_SECRET "
            "or call register_credentials to store your personal credentials."
        }

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
        return {
            "error": str(exc),
            "status_code": exc.status_code,
            "detail": exc.detail,
        }

    return await _with_warning(result, npub=npub)


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
