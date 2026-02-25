"""X (Twitter) API v2 client with OAuth 1.0a authentication.

Handles tweet posting via the v2 endpoint. Uses manual OAuth 1.0a
header signing (not authlib's AsyncOAuth1Client) because the X API v2
requires JSON bodies, and authlib mangles them during signature computation.

Credentials come from environment variables for Task 1; multi-tenant
vault planned for a future task.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import secrets
import time
import urllib.parse
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

X_API_BASE = "https://api.x.com/2"
X_UPLOAD_BASE = "https://upload.twitter.com/1.1"
ALLOWED_IMAGE_CONTENT_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp"}
MAX_IMAGE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB (X limit for images)
IMAGE_DOWNLOAD_TIMEOUT_SECONDS = 30


class XAPIError(Exception):
    """Raised when the X API returns an error response."""

    def __init__(self, status_code: int, detail: str, raw: dict | None = None):
        self.status_code = status_code
        self.detail = detail
        self.raw = raw or {}
        super().__init__(f"X API {status_code}: {detail}")


class MediaUploadError(XAPIError):
    """Raised when image download or media upload to X fails."""

    pass


@dataclass(frozen=True)
class XCredentials:
    """OAuth 1.0a credentials for X API access."""

    api_key: str
    api_secret: str
    access_token: str
    access_token_secret: str

    @classmethod
    def from_env(cls) -> XCredentials:
        """Load credentials from environment variables.

        Expected env vars:
            X_API_KEY, X_API_SECRET, X_ACCESS_TOKEN, X_ACCESS_TOKEN_SECRET
        """
        return cls(
            api_key=os.environ["X_API_KEY"],
            api_secret=os.environ["X_API_SECRET"],
            access_token=os.environ["X_ACCESS_TOKEN"],
            access_token_secret=os.environ["X_ACCESS_TOKEN_SECRET"],
        )


def _build_oauth1_header(
    method: str,
    url: str,
    consumer_key: str,
    consumer_secret: str,
    token: str,
    token_secret: str,
) -> str:
    """Build an OAuth 1.0a Authorization header (HMAC-SHA1, header-only).

    This produces a header-based OAuth signature that does NOT include
    the request body in the signature base string. Required for X API v2
    which uses JSON bodies (OAuth 1.0a body signing only works with
    application/x-www-form-urlencoded).
    """
    oauth_params = {
        "oauth_consumer_key": consumer_key,
        "oauth_nonce": secrets.token_hex(16),
        "oauth_signature_method": "HMAC-SHA1",
        "oauth_timestamp": str(int(time.time())),
        "oauth_token": token,
        "oauth_version": "1.0",
    }

    # Build signature base string (RFC 5849 §3.4.1)
    param_str = "&".join(
        f"{k}={urllib.parse.quote(v, safe='')}"
        for k, v in sorted(oauth_params.items())
    )
    base_str = (
        f"{method}&"
        f"{urllib.parse.quote(url, safe='')}&"
        f"{urllib.parse.quote(param_str, safe='')}"
    )

    # Sign with HMAC-SHA1
    signing_key = (
        f"{urllib.parse.quote(consumer_secret, safe='')}&"
        f"{urllib.parse.quote(token_secret, safe='')}"
    )
    signature = base64.b64encode(
        hmac.new(signing_key.encode(), base_str.encode(), hashlib.sha1).digest()
    ).decode()

    oauth_params["oauth_signature"] = signature

    # Format as Authorization header
    return "OAuth " + ", ".join(
        f'{k}="{urllib.parse.quote(v, safe="")}"'
        for k, v in sorted(oauth_params.items())
    )


class XClient:
    """Async X API v2 client with OAuth 1.0a header signing."""

    def __init__(self, credentials: XCredentials) -> None:
        self._creds = credentials

    def _auth_header(self, method: str, url: str) -> str:
        """Generate OAuth 1.0a Authorization header for a request."""
        return _build_oauth1_header(
            method=method,
            url=url,
            consumer_key=self._creds.api_key,
            consumer_secret=self._creds.api_secret,
            token=self._creds.access_token,
            token_secret=self._creds.access_token_secret,
        )

    async def download_image(self, image_url: str) -> tuple[bytes, str]:
        """Download an image from a URL.

        Args:
            image_url: The URL to download from.

        Returns:
            Tuple of (image_bytes, content_type).

        Raises:
            MediaUploadError: If download fails, content type is unsupported,
                or image exceeds size limit.
        """
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=IMAGE_DOWNLOAD_TIMEOUT_SECONDS,
        ) as client:
            try:
                response = await client.get(image_url)
            except httpx.HTTPError as exc:
                raise MediaUploadError(
                    0, f"Failed to download image from {image_url}: {exc}"
                )

        if response.status_code != 200:
            raise MediaUploadError(
                response.status_code,
                f"Image download returned {response.status_code}",
            )

        content_type = response.headers.get("content-type", "").split(";")[0].strip()
        if content_type not in ALLOWED_IMAGE_CONTENT_TYPES:
            raise MediaUploadError(
                0,
                f"Unsupported image type: {content_type}. "
                f"Allowed: {ALLOWED_IMAGE_CONTENT_TYPES}",
            )

        image_bytes = response.content
        if len(image_bytes) > MAX_IMAGE_SIZE_BYTES:
            raise MediaUploadError(
                0,
                f"Image too large: {len(image_bytes)} bytes "
                f"(max {MAX_IMAGE_SIZE_BYTES} bytes / 5 MB)",
            )

        return image_bytes, content_type

    async def upload_media(self, image_bytes: bytes, content_type: str) -> str:
        """Upload image bytes to X via v1.1 media/upload.

        Args:
            image_bytes: Raw image data.
            content_type: MIME type (e.g., "image/jpeg").

        Returns:
            media_id_string from the X response.

        Raises:
            MediaUploadError: If the upload fails.
        """
        url = f"{X_UPLOAD_BASE}/media/upload.json"
        auth_header = self._auth_header("POST", url)

        # Multipart upload — body excluded from OAuth signature (correct for multipart)
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                files={"media": ("image.jpg", image_bytes, content_type)},
                headers={"Authorization": auth_header},
            )

        if response.status_code not in (200, 202):
            try:
                body = response.json()
            except Exception:
                body = {"raw": response.text}
            raise MediaUploadError(
                response.status_code,
                f"Media upload failed: {response.status_code}",
                body,
            )

        data = response.json()
        media_id = data.get("media_id_string")
        if not media_id:
            raise MediaUploadError(0, "Media upload response missing media_id_string", data)

        return media_id

    async def post_tweet(
        self, text: str, *, media_ids: list[str] | None = None
    ) -> dict:
        """Post a tweet to X.

        Args:
            text: The tweet text (already Unicode-converted).
                Length enforced by X API based on account tier.
            media_ids: Optional list of media IDs to attach.

        Returns:
            dict with tweet_id, tweet_url, text_posted.

        Raises:
            XAPIError: If the X API returns an error.
        """
        url = f"{X_API_BASE}/tweets"
        auth_header = self._auth_header("POST", url)

        payload: dict = {"text": text}
        if media_ids:
            payload["media"] = {"media_ids": media_ids}

        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json=payload,
                headers={"Authorization": auth_header},
            )

        if response.status_code == 429:
            raise XAPIError(429, "Rate limited — try again later", response.json())

        if response.status_code in (401, 403):
            body = response.json()
            detail = body.get("detail", body.get("title", "Authentication failed"))
            raise XAPIError(response.status_code, detail, body)

        if response.status_code != 201:
            try:
                body = response.json()
            except Exception:
                body = {"raw": response.text}
            raise XAPIError(
                response.status_code,
                f"Unexpected response: {response.status_code}",
                body,
            )

        data = response.json()["data"]
        tweet_id = data["id"]

        return {
            "tweet_id": tweet_id,
            "tweet_url": f"https://x.com/i/status/{tweet_id}",
            "text_posted": text,
        }

    async def post_tweet_with_image(self, text: str, image_url: str) -> dict:
        """Download image, upload to X, and post tweet with media attached.

        Args:
            text: Tweet text (Unicode-converted).
            image_url: URL of image to attach.

        Returns:
            dict with tweet_id, tweet_url, text_posted, media_id.
        """
        image_bytes, content_type = await self.download_image(image_url)
        media_id = await self.upload_media(image_bytes, content_type)
        result = await self.post_tweet(text, media_ids=[media_id])
        result["media_id"] = media_id
        return result
