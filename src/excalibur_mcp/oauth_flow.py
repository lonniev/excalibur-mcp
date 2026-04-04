"""OAuth2 Authorization Code flow with PKCE for X (Twitter) API.

Thin X-specific wrapper around ``tollbooth.oauth2_collector``.
Binds X endpoint URLs, scopes, and PKCE parameters. Delegates
all generic OAuth2 mechanics to the collector module.
"""

from __future__ import annotations

import logging

from tollbooth.oauth2_collector import (
    build_authorize_url as _build_authorize_url,
)
from tollbooth.oauth2_collector import (
    exchange_code_for_token as _exchange_code_for_token,
)
from tollbooth.oauth2_collector import (
    generate_pkce_pair,
)
from tollbooth.oauth2_collector import (
    refresh_access_token as _refresh_access_token,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# X-specific constants
# ---------------------------------------------------------------------------

X_AUTHORIZE = "https://x.com/i/oauth2/authorize"
X_TOKEN = "https://api.x.com/2/oauth2/token"
X_SCOPES = "tweet.read tweet.write users.read offline.access"

# ---------------------------------------------------------------------------
# Flow helpers
# ---------------------------------------------------------------------------


def begin_oauth_flow(
    patron_npub: str,
    client_id: str,
    redirect_uri: str,
) -> tuple[str, str]:
    """Start the X OAuth2 + PKCE flow.

    Generates a PKCE pair, builds the authorization URL with the
    code_challenge, and returns (authorize_url, code_verifier).

    The caller must store the code_verifier until the code exchange
    (typically in-memory, keyed by patron_npub).

    Args:
        patron_npub: Patron's npub (used as OAuth state parameter).
        client_id: X OAuth2 client ID (from operator vault).
        redirect_uri: Registered redirect URI (the collector callback).

    Returns:
        (authorize_url, code_verifier) tuple.
    """
    verifier, challenge = generate_pkce_pair()

    url = _build_authorize_url(
        X_AUTHORIZE,
        client_id,
        redirect_uri,
        patron_npub,
        scope=X_SCOPES,
        extra_params={
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    return url, verifier


async def exchange_code_for_token(
    code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str,
    code_verifier: str,
) -> dict:
    """Exchange an X authorization code + PKCE verifier for tokens.

    Returns dict with access_token, refresh_token, expires_at, etc.
    """
    return await _exchange_code_for_token(
        code,
        client_id,
        client_secret,
        redirect_uri,
        X_TOKEN,
        code_verifier=code_verifier,
    )


async def refresh_access_token(
    client_id: str,
    client_secret: str,
    refresh_token: str,
) -> dict:
    """Refresh an expired X access token.

    Returns new token dict with access_token, expires_at, and
    optionally a rotated refresh_token.
    """
    return await _refresh_access_token(
        client_id,
        client_secret,
        refresh_token,
        X_TOKEN,
    )
