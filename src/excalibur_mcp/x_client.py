"""X (Twitter) API v2 client with OAuth 2.0 Bearer token authentication.

All requests use a Bearer token obtained via the OAuth 2.0 Authorization
Code Flow with PKCE. No OAuth 1.0a signing — all endpoints are v2.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)

X_API_BASE = "https://api.x.com/2"
ALLOWED_IMAGE_CONTENT_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp"}
MAX_IMAGE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
IMAGE_DOWNLOAD_TIMEOUT_SECONDS = 30

POSTIMG_UPLOAD_URL = "https://postimg.cc/json?q=a"
POSTIMG_UPLOAD_TIMEOUT_SECONDS = 30


class PostImgUploadError(Exception):
    """Raised when uploading to postimg.cc fails."""

    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)


async def upload_to_postimg(png_bytes: bytes, filename: str = "banner.png") -> str:
    """Upload PNG to postimg.cc, return direct image URL."""
    async with httpx.AsyncClient(timeout=POSTIMG_UPLOAD_TIMEOUT_SECONDS, follow_redirects=True) as client:
        try:
            response = await client.post(
                POSTIMG_UPLOAD_URL,
                data={
                    "token": "61aa06d6116f7331ad7b2ba9c7fb707ec9b182e8",
                    "upload_session": os.urandom(16).hex(),
                    "numfiles": "1",
                    "optsize": "0",
                    "upload_referer": "https://postimages.org/",
                },
                files={"file": (filename, png_bytes, "image/png")},
            )
        except httpx.HTTPError as exc:
            raise PostImgUploadError(f"PostImg upload failed: {exc}")

    if response.status_code != 200:
        raise PostImgUploadError(
            f"PostImg returned {response.status_code}: {response.text[:200]}"
        )

    try:
        data = response.json()
    except Exception:
        raise PostImgUploadError(f"PostImg returned non-JSON: {response.text[:200]}")

    url = data.get("url")
    if not url:
        raise PostImgUploadError(f"PostImg response missing 'url': {data}")

    return url


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
    """OAuth 2.0 Bearer token for X API access."""

    bearer_token: str


class XClient:
    """Async X API v2 client with OAuth 2.0 Bearer token auth."""

    def __init__(self, credentials: XCredentials) -> None:
        self._creds = credentials

    def _auth_header(self) -> str:
        return f"Bearer {self._creds.bearer_token}"

    async def download_image(self, image_url: str) -> tuple[bytes, str]:
        """Download an image from a URL."""
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
        """Upload image bytes to X via v2 media/upload.

        Returns media_id_string from the X response.
        """
        url = f"{X_API_BASE}/media/upload"

        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                files={"media": ("image.jpg", image_bytes, content_type)},
                headers={"Authorization": self._auth_header()},
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
        media_id = data.get("media_id_string") or data.get("id")
        if not media_id:
            raise MediaUploadError(0, "Media upload response missing media_id", data)

        return str(media_id)

    async def post_tweet(
        self, text: str, *, media_ids: list[str] | None = None
    ) -> dict:
        """Post a tweet to X."""
        url = f"{X_API_BASE}/tweets"

        payload: dict = {"text": text}
        if media_ids:
            payload["media"] = {"media_ids": media_ids}

        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json=payload,
                headers={"Authorization": self._auth_header()},
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
        """Download image, upload to X, and post tweet with media attached."""
        image_bytes, content_type = await self.download_image(image_url)
        media_id = await self.upload_media(image_bytes, content_type)
        result = await self.post_tweet(text, media_ids=[media_id])
        result["media_id"] = media_id
        return result
