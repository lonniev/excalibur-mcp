"""eXcalibur-mcp — FastMCP server for posting formatted content to X (Twitter).

Tollbooth-monetized, DPYC-native. Standard DPYC tools (check_balance,
purchase_credits, Secure Courier, Oracle, pricing) are provided by
``register_standard_tools`` from the tollbooth-dpyc wheel. Only
domain-specific X/Twitter tools are defined here.
"""

from __future__ import annotations

import json
import logging
from typing import Annotated, Any

from fastmcp import FastMCP
from pydantic import Field
from tollbooth.credential_templates import CredentialTemplate, FieldSpec
from tollbooth.credential_validators import validate_btcpay_creds, validate_required
from tollbooth.oauth_config import OAuthProviderConfig
from tollbooth.runtime import OperatorRuntime, register_standard_tools
from tollbooth.tool_identity import STANDARD_IDENTITIES, ToolIdentity, capability_uuid
from tollbooth.upstream_payment import upstream_payment_situation

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
        "   - Call `request_credential_channel(recipient_npub=<patron_npub>)` to receive a welcome DM "
        "(the response includes a session phrase / poison)\n"
        "   - Reply via your Nostr client with your X API credentials in JSON\n"
        "   - Call `receive_credentials(sender_npub=<patron_npub>, service=<service>, poison=<session phrase>)` "
        "to vault your credentials — all three are required\n\n"
        "## Credits Model\n\n"
        "Tool calls cost api_sats per call. Auth and balance tools are always free. "
        "Use `check_balance` to see your balance. Top up via `purchase_credits`."
    ),
)
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

# Frozen UUIDs — declared once at tool birth and never changed.
POST_TWEET_UUID       = "11f169f5-9cd8-5d30-85ab-d4485e6c6965"
POST_TWEET_IMAGE_UUID = "d10365f0-9a03-5b6c-8c6d-1457c139f31b"


_DOMAIN_TOOLS = [
    # OAuth tools are now standard (from wheel via OAuthProviderConfig)
    ToolIdentity(tool_id=POST_TWEET_UUID, capability="post_tweet", category="write", intent="Post a text tweet to X/Twitter"),
    ToolIdentity(tool_id=POST_TWEET_IMAGE_UUID, capability="post_tweet_image", category="heavy", intent="Post a tweet with image to X/Twitter"),
    # Stored-post CRUD — reads cheap, writes pricier, create highest. These are
    # seed prices; the operator tunes them in the tollbooth-pricing-studio model.
    ToolIdentity(tool_id=capability_uuid("get_post"), capability="get_post", category="read",
                 intent="Read a stored post by id", pricing_hint_type="flat", pricing_hint_value=1),
    ToolIdentity(tool_id=capability_uuid("list_posts"), capability="list_posts", category="read",
                 intent="List this patron's stored posts (paginated)", pricing_hint_type="flat", pricing_hint_value=1),
    ToolIdentity(tool_id=capability_uuid("update_post"), capability="update_post", category="write",
                 intent="Patch a stored post (doc/schedule)", pricing_hint_type="flat", pricing_hint_value=3),
    ToolIdentity(tool_id=capability_uuid("delete_post"), capability="delete_post", category="write",
                 intent="Archive or delete a stored post", pricing_hint_type="flat", pricing_hint_value=3),
    ToolIdentity(tool_id=capability_uuid("create_post"), capability="create_post", category="write",
                 intent="Store a new draft/scheduled post", pricing_hint_type="flat", pricing_hint_value=5),
    # Server-side "Refine with Claude": the editor sends a flagged region +
    # context; the MCP calls Anthropic with the operator's vaulted key (never
    # exposed to the browser) and returns suggestions. Paid — the AI cost is a
    # metered tollbooth fare (refunded on no-key / upstream failure).
    ToolIdentity(tool_id=capability_uuid("refine_post_region"), capability="refine_post_region",
                 category="heavy", intent="Refine a flagged post region with Claude (server-side, metered)",
                 pricing_hint_type="flat", pricing_hint_value=25),
    # Resolve a *dynamic* post block: its text is a runnable prompt that Claude
    # executes (with web search) at post time / preview, weaving a fresh answer
    # into the surrounding tweet. Same posture as refine — operator's vaulted key,
    # metered as a paid fare, refunded on no-key / upstream failure. The scheduler
    # bills the owner for this per fire when a due post carries dynamic blocks.
    ToolIdentity(tool_id=capability_uuid("resolve_dynamic_block"), capability="resolve_dynamic_block",
                 category="heavy", intent="Resolve a dynamic post block's prompt with Claude (server-side, metered)",
                 pricing_hint_type="flat", pricing_hint_value=25),
    # Snippet library — reusable openings/footers/CTAs the patron saves once and
    # drops into the editor (favorites become one-click chiclets). Free: managing
    # your own snippets carries no fare, but every call is proof-gated and
    # npub-scoped, so a patron only ever touches their own.
    ToolIdentity(tool_id=capability_uuid("list_snippets"), capability="list_snippets",
                 category="free", intent="List this patron's saved post snippets"),
    ToolIdentity(tool_id=capability_uuid("get_snippet"), capability="get_snippet",
                 category="free", intent="Read one of this patron's saved snippets"),
    # Reads the connected X account's handle/name for personalization (the editor
    # tweet-card preview). Free + proof-gated to the npub owner.
    ToolIdentity(tool_id=capability_uuid("get_x_profile"), capability="get_x_profile",
                 category="free", intent="Read your connected X account handle"),
    ToolIdentity(tool_id=capability_uuid("save_snippet"), capability="save_snippet",
                 category="free", intent="Create or update a saved post snippet"),
    ToolIdentity(tool_id=capability_uuid("delete_snippet"), capability="delete_snippet",
                 category="free", intent="Delete a saved post snippet"),
    # Writing Voice — the patron's per-npub voice profile + "banned construction"
    # chips the editor feeds to refine_post_region. A singleton per npub (one
    # Voice, upserted). Priceable (read/write), proof-gated, owner-scoped — they
    # carry no pricing hint, so they begin unpriced (TBD) and the operator sets a
    # price (or 0/free) in Pricing Studio like any new tool.
    ToolIdentity(tool_id=capability_uuid("get_voice"), capability="get_voice",
                 category="read", intent="Read this patron's saved writing Voice"),
    ToolIdentity(tool_id=capability_uuid("save_voice"), capability="save_voice",
                 category="write", intent="Save this patron's writing Voice (profile + banned constructions)"),
    # Operator-only cron entrypoint — fires due scheduled posts. `restricted`
    # gates it to the operator npub (verified by proof) and bills nothing for
    # the trigger itself; each fired post bills its own owner for post_tweet.
    ToolIdentity(tool_id=capability_uuid("process_scheduled_posts"), capability="process_scheduled_posts",
                 category="restricted", intent="Operator: publish all due scheduled posts"),
    # Read the scheduler-tick audit ring (powers the FE debug log's view of what
    # the cron Worker is doing). `free` + proof-gated: the OPERATOR sees every
    # tick in full; any other proven patron sees the global heartbeat plus only
    # the per-post outcomes for THEIR OWN posts (owner-scoped server-side).
    ToolIdentity(tool_id=capability_uuid("get_scheduler_log"), capability="get_scheduler_log",
                 category="free", intent="Read recent scheduler-tick outcomes for your posts"),
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
            "anthropic_api_key": FieldSpec(
                required=False, sensitive=True,
                description="Anthropic API key for the editor's FE-direct 'Refine with Claude'. Optional — posting works without it.",
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

tool = register_standard_tools(
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
# Credential resolution: vault → live XClient on every call
#
# No long-lived in-memory cache: every paid call routes through
# runtime.restore_oauth_session, which loads from vault, refreshes
# via the upstream provider if expired, and persists rotated tokens
# back. This eliminates the prior bug where in-memory bearer cache
# could go stale across process restarts.
# ---------------------------------------------------------------------------


async def _resolve_x_client(npub: str) -> tuple[Any | None, dict | None]:
    """Resolve a fresh X bearer for ``npub`` and build an XClient.

    Pure resolution — **no billing, no rollback**. Returns ``(XClient, None)``
    on success, or ``(None, situation_dict)`` on any non-success state. Both the
    patron path (``_prepare_x_client``) and the scheduler share this; each owns
    its own billing semantics.
    """
    from excalibur_mcp.x_client import XClient, XCredentials

    err = runtime.npub_validation_error(npub)
    if err is not None:
        return None, err

    creds, situation = await runtime.restore_oauth_session(npub)
    if creds is None:
        return None, runtime.oauth_situation_response(situation)

    access_token = creds.get("access_token", "")
    if not access_token:
        return None, runtime.oauth_situation_response("no_credentials")

    return XClient(XCredentials(bearer_token=access_token)), None


async def _prepare_x_client(
    cost_key: str, npub: str,
) -> tuple[Any, str] | dict:
    """Resolve a fresh X bearer for this patron and build an XClient.

    Returns ``(XClient, "")`` on success, or a structured error dict
    (``{"success": False, "error_code": ..., "next_steps": [...]}``)
    on any non-success situation.  Billing and proof are handled by
    the ``@paid_tool`` decorator — on a non-success situation we refund
    the decorator's debit (the call did no upstream work).
    """
    client, situation = await _resolve_x_client(npub)
    if client is None:
        await runtime.rollback_debit(cost_key, npub)
        return situation  # structured situation dict
    return (client, "")


def _x_api_error_to_response(exc: Any) -> dict[str, Any]:
    """Map an X API error to a structured response.

    A 401/403 from X means the access token was rejected upstream
    even though our records considered it fresh — the patron must
    re-authorize.  Routes to ``oauth_refresh_needed`` for symmetry
    with the SDK helper's standard situations.

    A 402 means the patron's own X developer subscription / access tier
    has lapsed or doesn't cover the request — a billing matter at X, not a
    re-authorization. Routes to the SDK's generic upstream-subscription
    situation (``upstream_subscription_required``) with renewal advice.
    """
    base: dict[str, Any] = {
        "success": False,
        "error": str(exc),
        "status_code": getattr(exc, "status_code", None),
        "detail": getattr(exc, "detail", None),
    }
    status = getattr(exc, "status_code", 0)
    if status in (401, 403):
        base.update(runtime.oauth_situation_response("token_expired"))
        # Preserve the upstream detail alongside the structured guidance
        base["status_code"] = exc.status_code
        base["detail"] = getattr(exc, "detail", None)
    elif status == 402:
        base.update(
            upstream_payment_situation(
                service="X (Twitter) API",
                renew_url="https://developer.x.com/en/portal/dashboard",
                audience="patron",
                detail=getattr(exc, "detail", None),
            )
        )
    return base


# ---------------------------------------------------------------------------
# MCP Tools — Paid (domain-specific)
# OAuth tools (begin_oauth, check_oauth_status) are now standard
# wheel tools, registered via OAuthProviderConfig.
# ---------------------------------------------------------------------------


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
        return _x_api_error_to_response(exc)

    return result


@tool
@runtime.paid_tool(capability_uuid("get_x_profile"), catch_errors=True)
async def get_x_profile(
    npub: Annotated[str, Field(description="Required. Your Nostr public key (npub1...).")] = "",
    proof: str = "",
) -> dict:
    """Fetch the connected X account's handle and name for this patron (free).

    Uses the patron's vaulted X OAuth token to call X's ``/users/me``. Returns
    ``{connected: true, username, name, profile_image_url}`` when connected, or
    the OAuth situation (``connected`` absent) when X isn't linked yet. Used to
    show the real @handle on the editor's tweet-card preview."""
    from excalibur_mcp.x_client import XAPIError

    client, situation = await _resolve_x_client(npub)
    if client is None:
        return situation or {"connected": False, "error_code": "oauth_unavailable"}
    try:
        me = await client.get_me()
    except XAPIError as exc:
        return _x_api_error_to_response(exc)
    return {"connected": True, **me}


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
        return _x_api_error_to_response(exc)

    return result


# ---------------------------------------------------------------------------
# MCP Tools — Stored-post CRUD (priced, npub-authorized)
#
# Posts persist inside eXcalibur's NeonVault; the editorial FE is a patron of
# its own operator. Core logic + validation + idempotency live in
# tools/posts.py; these wrappers are the priced, proof-gated surface. The
# @paid_tool decorator debits before the body and refunds on raise.
# ---------------------------------------------------------------------------


@tool
@runtime.paid_tool(capability_uuid("create_post"), catch_errors=True)
async def create_post(
    doc: dict,
    text_cache: str = "",
    publish_at: str | None = None,
    recurrence: dict | None = None,
    cease_at: str | None = None,
    status: str = "draft",
    client_req_id: str = "",
    tweet_url: str = "",
    npub: Annotated[str, Field(description="Required. Your Nostr public key (npub1...) for credit billing.")] = "", proof: str = "",
) -> dict:
    """Store a new post (draft or scheduled). Returns its ``post_id``.

    Args:
        doc: The editable Doc (blocks + flags + voice + bans + schedule).
        text_cache: Composed text (blocks joined) for scheduler + list excerpts.
        publish_at: ISO-8601 first/next publish time; required when status='scheduled'.
        recurrence: ``{"freq": "daily|weekly|monthly", "interval": n}`` or null.
        cease_at: ISO-8601 stop time for recurrence; null = open-ended.
        status: ``draft`` or ``scheduled``.
        client_req_id: Idempotency key — re-sending the same id returns the same
            post without a second charge.
        npub: Your DPYC patron Nostr public key for credit attribution.
    """
    from excalibur_mcp.tools import posts as posts_tools

    return await posts_tools.create(
        runtime, capability_uuid("create_post"),
        doc=doc, text_cache=text_cache, publish_at=publish_at,
        recurrence=recurrence, cease_at=cease_at, status=status,
        client_req_id=client_req_id, npub=npub, tweet_url=tweet_url,
    )


@tool
@runtime.paid_tool(capability_uuid("get_post"), catch_errors=True)
async def get_post(
    post_id: str,
    npub: Annotated[str, Field(description="Required. Your Nostr public key (npub1...) for credit billing.")] = "", proof: str = "",
) -> dict:
    """Read one stored post by id (owner-scoped)."""
    from excalibur_mcp.tools import posts as posts_tools

    return await posts_tools.get(runtime, capability_uuid("get_post"), post_id=post_id, npub=npub)


@tool
@runtime.paid_tool(capability_uuid("list_posts"), catch_errors=True)
async def list_posts(
    status: str = "",
    sort_col: str = "created",
    sort_dir: str = "desc",
    page: int = 0,
    page_size: int = 25,
    search: str = "",
    date_from: str = "",
    date_to: str = "",
    date_field: str = "created",
    npub: Annotated[str, Field(description="Required. Your Nostr public key (npub1...) for credit billing.")] = "", proof: str = "",
) -> dict:
    """List your stored posts, server-side sorted, filtered, and offset-paginated.

    Optional ``status`` filter. ``sort_col`` is one of
    ``created|updated|status|scheduled`` (default ``created``); ``sort_dir`` is
    ``asc|desc``. ``search`` is a case-insensitive regular expression matched
    against the post text. ``date_from``/``date_to`` (``YYYY-MM-DD``, end-inclusive)
    bound the ``date_field`` column, one of ``created|updated|scheduled|sent``
    (default ``created``). ``page`` is 0-indexed; ``page_size`` is 1..100. Returns
    ``{posts:[…], total, page, page_size}`` reflecting the filtered set."""
    from excalibur_mcp.tools import posts as posts_tools

    return await posts_tools.list_(
        runtime, capability_uuid("list_posts"),
        status=status, sort_col=sort_col, sort_dir=sort_dir,
        page=page, page_size=page_size, npub=npub,
        search=search, date_from=date_from, date_to=date_to, date_field=date_field,
    )


@tool
@runtime.paid_tool(capability_uuid("update_post"), catch_errors=True)
async def update_post(
    post_id: str,
    patch: dict,
    text_cache: str = "",
    client_req_id: str = "",
    npub: Annotated[str, Field(description="Required. Your Nostr public key (npub1...) for credit billing.")] = "", proof: str = "",
) -> dict:
    """Patch a stored post. ``patch`` may set ``doc, publish_at, recurrence,
    cease_at, status`` (omit a field to leave it unchanged). ``text_cache`` is
    written when supplied (alongside a doc change). ``client_req_id`` dedupes
    debounced autosave retries — a repeat is a no-op with no second charge."""
    from excalibur_mcp.tools import posts as posts_tools

    return await posts_tools.update(
        runtime, capability_uuid("update_post"),
        post_id=post_id, patch=patch, text_cache=text_cache,
        client_req_id=client_req_id, npub=npub,
    )


@tool
@runtime.paid_tool(capability_uuid("delete_post"), catch_errors=True)
async def delete_post(
    post_id: str,
    hard: bool = False,
    npub: Annotated[str, Field(description="Required. Your Nostr public key (npub1...) for credit billing.")] = "", proof: str = "",
) -> dict:
    """Delete a stored post. Default is a soft delete (``status='archived'``);
    pass ``hard=True`` to remove the row permanently."""
    from excalibur_mcp.tools import posts as posts_tools

    return await posts_tools.delete(
        runtime, capability_uuid("delete_post"),
        post_id=post_id, hard=hard, npub=npub,
    )


# ---------------------------------------------------------------------------
# Snippet library — npub-scoped, free, proof-gated
# ---------------------------------------------------------------------------


@tool
@runtime.paid_tool(capability_uuid("list_snippets"), catch_errors=True)
async def list_snippets(
    sort_col: str = "favorite",
    sort_dir: str = "desc",
    page: int = 0,
    page_size: int = 25,
    search: str = "",
    date_from: str = "",
    date_to: str = "",
    date_field: str = "created",
    npub: Annotated[str, Field(description="Required. Your Nostr public key (npub1...).")] = "",
    proof: str = "",
) -> dict:
    """List your saved post snippets, server-side sorted, filtered, and
    offset-paginated. ``sort_col`` is one of ``favorite|created|updated|name``
    (default ``favorite``); ``sort_dir`` is ``asc|desc``. ``search`` is a
    case-insensitive regular expression matched against the snippet name or body.
    ``date_from``/``date_to`` (``YYYY-MM-DD``, end-inclusive) bound the
    ``date_field`` column, one of ``created|updated`` (default ``created``).
    ``page`` is 0-indexed; ``page_size`` is 1..200. Free, owner-scoped. Returns
    ``{snippets:[…], total, page, page_size}`` reflecting the filtered set."""
    from excalibur_mcp.tools import snippets as snippets_tools

    return await snippets_tools.list_(
        npub, sort_col=sort_col, sort_dir=sort_dir, page=page, page_size=page_size,
        search=search, date_from=date_from, date_to=date_to, date_field=date_field,
    )


@tool
@runtime.paid_tool(capability_uuid("get_snippet"), catch_errors=True)
async def get_snippet(
    snippet_id: str,
    npub: Annotated[str, Field(description="Required. Your Nostr public key (npub1...).")] = "",
    proof: str = "",
) -> dict:
    """Read one of your saved snippets by id (full row incl. ``doc`` block
    document). Free and owner-scoped. Returns ``{"success": true, "snippet": …}``
    or ``snippet_not_found``."""
    from excalibur_mcp.tools import snippets as snippets_tools

    return await snippets_tools.get(npub, snippet_id=snippet_id)


@tool
@runtime.paid_tool(capability_uuid("save_snippet"), catch_errors=True)
async def save_snippet(
    name: str = "",
    text: str = "",
    snippet_id: str = "",
    favorite: bool | None = None,
    doc: dict | None = None,
    npub: Annotated[str, Field(description="Required. Your Nostr public key (npub1...).")] = "",
    proof: str = "",
) -> dict:
    """Save a reusable post snippet (opening/footer/CTA). Omit ``snippet_id`` to
    create a new one; pass it to update an existing snippet in place (name/text/
    favorite/doc). On update only the fields you pass change — omit ``favorite``
    (leave it null) to keep it as-is, so a doc-only patch (e.g. toggling a snippet
    dynamic) doesn't reset it. ``doc`` is the same block/flag document a post
    carries, so the editor is identical for both. Free and owner-scoped. Returns
    ``{"success": true, "snippet": …}``."""
    from excalibur_mcp.tools import snippets as snippets_tools

    return await snippets_tools.save(
        npub, snippet_id=snippet_id, name=name, text=text, favorite=favorite,
        doc=doc,
    )


@tool
@runtime.paid_tool(capability_uuid("delete_snippet"), catch_errors=True)
async def delete_snippet(
    snippet_id: str,
    npub: Annotated[str, Field(description="Required. Your Nostr public key (npub1...).")] = "",
    proof: str = "",
) -> dict:
    """Delete one of your saved snippets by id. Free and owner-scoped."""
    from excalibur_mcp.tools import snippets as snippets_tools

    return await snippets_tools.delete(npub, snippet_id=snippet_id)


# ---------------------------------------------------------------------------
# Writing Voice — npub-scoped singleton, priceable, proof-gated
# ---------------------------------------------------------------------------


@tool
@runtime.paid_tool(capability_uuid("get_voice"), catch_errors=True)
async def get_voice(
    npub: Annotated[str, Field(description="Required. Your Nostr public key (npub1...).")] = "",
    proof: str = "",
) -> dict:
    """Read your saved writing Voice — a profile blurb plus a list of "banned
    construction" chips (``{text, on}``) the editor passes to
    ``refine_post_region``. Owner-scoped; priced by the operator's pricing model
    (use ``check_price``). When you have not saved a Voice yet this returns an
    empty one (``{"voice": {"profile": "", "bans": []}}``) so the editor can seed
    its own defaults, not an error."""
    from excalibur_mcp.tools import voices as voices_tools

    return await voices_tools.get(npub)


@tool
@runtime.paid_tool(capability_uuid("save_voice"), catch_errors=True)
async def save_voice(
    profile: str = "",
    bans: list | None = None,
    npub: Annotated[str, Field(description="Required. Your Nostr public key (npub1...).")] = "",
    proof: str = "",
) -> dict:
    """Save your writing Voice (replaces the previous one — it is a per-npub
    singleton). ``profile`` is free text. ``bans`` is a list of ``{text, on}``
    objects: ``text`` is the construction to avoid, ``on`` whether it is an active
    constraint. Blank/duplicate entries are dropped server-side. Owner-scoped;
    priced by the operator's pricing model (use ``check_price``). Returns
    ``{"success": true, "voice": {...}}``."""
    from excalibur_mcp.tools import voices as voices_tools

    return await voices_tools.save(npub, profile=profile, bans=bans)


# ---------------------------------------------------------------------------
# FE-direct Claude refine (TaxSort tactic)
# ---------------------------------------------------------------------------


@tool
@runtime.paid_tool(capability_uuid("refine_post_region"), catch_errors=True)
async def refine_post_region(
    region: str,
    full_text: str = "",
    instruction: str = "",
    voice: str = "",
    bans: str = "",
    npub: Annotated[str, Field(description="Required. Your Nostr public key (npub1...) for credit billing.")] = "",
    proof: str = "",
) -> dict:
    """Refine a flagged region of a post with Claude — server-side.

    The operator's Anthropic key stays in the vault and never leaves the
    server. Send the flagged ``region``, the surrounding ``full_text``, an
    optional ``instruction`` (what to change), and the editor's ``voice``
    profile + ``bans`` (JSON array or comma list of banned constructions).
    Returns ``{"success": true, "suggestions": [...3 strings...]}``.

    Paid: the AI cost is metered as a tollbooth fare. The fare is refunded if
    no Anthropic key is configured or the upstream call returns nothing.

    Args:
        region: The flagged span to rewrite.
        full_text: The whole tweet, for context.
        instruction: What the editor wants changed (optional).
        voice: Voice-profile text fed to the model (optional).
        bans: Banned constructions — JSON array or comma-separated (optional).
        npub: Your DPYC patron npub for credit billing.
    """
    tool_id = capability_uuid("refine_post_region")
    if not region.strip():
        await runtime.rollback_debit(tool_id, npub)
        return {"success": False, "error_code": "tool_input_invalid", "error": "region is required."}

    try:
        creds = await runtime.load_credentials(["anthropic_api_key"])
        key = creds.get("anthropic_api_key")
    except Exception:
        key = None
    if not key:
        await runtime.rollback_debit(tool_id, npub)
        return {
            "success": False,
            "error_code": "operator_llm_unconfigured",
            "message": (
                "Refine is unavailable — the operator hasn't configured an "
                "Anthropic key yet. No fare was charged."
            ),
        }

    ban_list: list[str] = []
    if bans:
        try:
            parsed = json.loads(bans)
            if isinstance(parsed, list):
                ban_list = [str(b) for b in parsed if str(b).strip()]
        except (json.JSONDecodeError, TypeError):
            ban_list = [b.strip() for b in bans.split(",") if b.strip()]

    from excalibur_mcp.refine import refine_region
    try:
        suggestions = await refine_region(
            api_key=key, region=region, full_text=full_text or region,
            instruction=instruction, voice=voice, bans=ban_list,
        )
    except Exception as exc:
        await runtime.rollback_debit(tool_id, npub)
        logger.warning("refine_post_region upstream failed: %s: %s", type(exc).__name__, exc)
        return {
            "success": False,
            "error_code": "llm_upstream_error",
            "message": "The refine request failed upstream — your fare was refunded. Try again shortly.",
        }

    if not suggestions:
        await runtime.rollback_debit(tool_id, npub)
        return {
            "success": False,
            "error_code": "llm_no_output",
            "message": "No suggestions came back — your fare was refunded.",
        }

    return {"success": True, "suggestions": suggestions}


def _parse_str_list(raw: str) -> list[str]:
    """Parse a tool string arg into a clean list — JSON array first, else
    comma-separated. Used for bans and web_fetch allowed_domains."""
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return [str(x).strip() for x in parsed if str(x).strip()]
    except (json.JSONDecodeError, TypeError):
        pass
    return [x.strip() for x in raw.split(",") if x.strip()]


@tool
@runtime.paid_tool(capability_uuid("resolve_dynamic_block"), catch_errors=True)
async def resolve_dynamic_block(
    prompt: str,
    context: str = "",
    voice: str = "",
    bans: str = "",
    allowed_domains: str = "",
    max_fetches: int = 5,
    npub: Annotated[str, Field(description="Required. Your Nostr public key (npub1...) for credit billing.")] = "",
    proof: str = "",
) -> dict:
    """Resolve a dynamic post block with Claude — server-side.

    A dynamic block's ``prompt`` is run by Claude (with web search + web fetch for
    live data) and woven into the surrounding post ``context`` in the author's
    ``voice``. The author's instruction governs length — there is no character cap
    (X supports long-form posts). The operator's Anthropic key stays in the vault
    and never leaves the server. This powers the editor's Preview dry-run; the
    scheduler resolves dynamic blocks the same way at fire time.

    Returns ``{"success": true, "text": "..."}``.

    Paid: the AI cost is metered as a tollbooth fare, refunded if no Anthropic
    key is configured or the upstream call returns nothing.

    Args:
        prompt: The dynamic block's prompt to run.
        context: The surrounding composed post (may contain the ⟨HERE⟩ marker).
        voice: Voice-profile text fed to the model (optional).
        bans: Banned constructions — JSON array or comma-separated (optional).
        allowed_domains: Author allowlist for web_fetch — JSON array or
            comma-separated. Blank = fetch any URL the prompt references.
        max_fetches: Author budget for web lookups (search + fetch), 1..25.
        npub: Your DPYC patron npub for credit billing.
    """
    tool_id = capability_uuid("resolve_dynamic_block")
    if not prompt.strip():
        await runtime.rollback_debit(tool_id, npub)
        return {"success": False, "error_code": "tool_input_invalid", "error": "prompt is required."}

    try:
        creds = await runtime.load_credentials(["anthropic_api_key"])
        key = creds.get("anthropic_api_key")
    except Exception:
        key = None
    if not key:
        await runtime.rollback_debit(tool_id, npub)
        return {
            "success": False,
            "error_code": "operator_llm_unconfigured",
            "message": (
                "Dynamic blocks are unavailable — the operator hasn't configured "
                "an Anthropic key yet. No fare was charged."
            ),
        }

    ban_list = _parse_str_list(bans)
    domain_list = _parse_str_list(allowed_domains)

    from excalibur_mcp.resolve import clamp_fetches, resolve_block
    try:
        text = await resolve_block(
            api_key=key, prompt=prompt, context=context,
            voice=voice, bans=ban_list,
            allowed_domains=domain_list, max_fetches=clamp_fetches(max_fetches),
        )
    except Exception as exc:
        await runtime.rollback_debit(tool_id, npub)
        logger.warning("resolve_dynamic_block upstream failed: %s: %s", type(exc).__name__, exc)
        return {
            "success": False,
            "error_code": "llm_upstream_error",
            "message": "Resolving the dynamic block failed upstream — your fare was refunded. Try again shortly.",
        }

    if not text:
        await runtime.rollback_debit(tool_id, npub)
        return {
            "success": False,
            "error_code": "llm_no_output",
            "message": "No text came back — your fare was refunded.",
        }

    return {"success": True, "text": text}


# ---------------------------------------------------------------------------
# Scheduler entrypoint — operator-only (restricted). Triggered by the
# Cloudflare Worker cron, which holds the operator's long-lived proof_token.
# ---------------------------------------------------------------------------


@tool
@runtime.paid_tool(capability_uuid("process_scheduled_posts"), catch_errors=True)
async def process_scheduled_posts(
    npub: Annotated[str, Field(description="The OPERATOR's npub (npub1...); this tool is operator-only.")] = "",
    proof: str = "",
) -> dict:
    """Publish every due scheduled post (operator-only).

    Selects ``scheduled`` posts whose ``publish_at`` has arrived, posts each on
    behalf of its owner (billing the owner for ``post_tweet``), stamps
    ``last_sent_at``, and reschedules from ``recurrence`` or retires the post
    past ``cease_at``. Requires the operator's npub proof; the trigger itself is
    free. Returns ``{processed, posted, skipped, errors}``.
    """
    from excalibur_mcp.scheduler import process_due_posts

    return await process_due_posts(runtime)


@tool
@runtime.paid_tool(capability_uuid("get_scheduler_log"), catch_errors=True)
async def get_scheduler_log(
    npub: Annotated[str, Field(description="Your npub (npub1...).")] = "",
    proof: str = "",
    limit: Annotated[int, Field(description="How many recent runs to return (1..100).")] = 25,
) -> dict:
    """Read recent scheduler-tick outcomes.

    Each ``process_scheduled_posts`` run — fired by the Cloudflare cron Worker or
    a manual trigger — records its summary. This surfaces them so the FE debug
    log can show what the Worker is doing: the per-tick heartbeat (proof it ran)
    and per-post outcomes (posted / skip+error reasons like
    ``insufficient_balance`` or ``oauth_token_expired``).

    Owner-scoped: the operator sees every tick in full; any other proven patron
    sees the global heartbeat (``processed`` count + ``run_at``) plus only the
    per-post entries for THEIR OWN posts. Free; npub proof required. Returns
    ``{runs:[{run_at, summary}], scope}``.
    """
    from excalibur_mcp.db import scheduler_runs

    operator = runtime.operator_npub()
    runs = await scheduler_runs.list_runs(limit)
    scoped = scheduler_runs.scope_runs(runs, npub, operator)
    return {"runs": scoped, "scope": "operator" if npub == operator else "owner"}


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
